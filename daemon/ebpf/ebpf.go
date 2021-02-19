package ebpf

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/vishvananda/netlink"

	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	"github.com/iovisor/gobpf/bcc"
	bpf "github.com/iovisor/gobpf/bcc"
)

//Our goal is to parse each new connection as quickly as possible
//that's why we don't use BPF_PERF_OUTPUT but maintain the maps inside ebpf.
//With BPF_PERF_OUTPUT processing time is ~50us whereas with the current method it is ~20us.

//a key/value map size must be indicated in advance when ebpf program starts. Normally as map grows full, we'd want
//to delete older entries from it. However, deleting one entry at a time is an expensive operation in ebpf, in
//contrast to deleting all entries of a map - which is cheap.
//That's why we employ 2 maps: odd and even map. The odd map holds the first 5000 unique entries and the even map
//holds the second 5000 unique entries for each 10000 entries.

//Workflow in ebpf:
//When the odd map reaches 4000 entries, the final 1000 entries are put both into the odd map and into the even map.
//When odd map reached 5000 entries, even map becomes the primary map.
//Even though even map is now primary, the next 1000 entries (i.e entries from 5001 to 6000)
//are put both into even map and into odd map.

//Workflow in userspace:
//When func monitorAndSwitchMaps() detects that odd map has >= 5000 entries, all future PID lookups will happen in even map.
//This detection doesn't happen exactly at 5000 mark but whenever monitorAndSwitchMaps() makes its next iteration.
//For this reason ebpf copies the first 1000 entries of even map into the odd map.
//monitorAndSwitchMaps() waits until odd map has 6000 entries and then deletes it.

//the same workflow applies for even map.

//Thus the capacity for each map must be 7000, viz. (in case of odd map)
//   1000 (duplicate entries: when even map is still the main map and we're about to switch to odd map)
// + 5000 (the actual unique entries)
// + 1000 (duplicate entries: after we just switched to even map)

import "C"

//based on https://github.com/iovisor/bcc/blob/master/examples/tracing/tcpv4connect.py
var source string = `
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <bcc/proto.h>

struct tcp_key_t {
	u16 sport;
	u32 daddr;
	u16 dport; 
}__attribute__((packed));

struct tcp_value_t{
	u32 pid;
	u32 saddr;
	u64 counter; //counters in value are for debug purposes only
}__attribute__((packed));;

struct tcpv6_key_t {
	u16 sport;
	unsigned __int128 daddr;
	u16 dport; 
}__attribute__((packed));

struct tcpv6_value_t{
	u32 pid;
	unsigned __int128 saddr;
	u64 counter; //counters in value are for debug purposes only
}__attribute__((packed));;

struct udp_key_t {
	u16 sport;
	u32 daddr;
	u16 dport; 
} __attribute__((packed));

struct udp_value_t{
	u32 pid;
	u32 saddr;
	u64 counter; //counters in value are for debug purposes only
}__attribute__((packed));

struct udpv6_key_t {
	u16 sport;
	unsigned __int128 daddr;
	u16 dport; 
}__attribute__((packed));

struct udpv6_value_t{
	u32 pid;
	unsigned __int128 saddr;
	u64 counter; //counters in value are for debug purposes only
}__attribute__((packed));

struct tcpv6sock_value_t {
	struct sock *sk;
	struct sockaddr *uaddr;
};


BPF_HASH(udpMapOdd, struct udp_key_t, struct udp_value_t, MAPSIZE+2000);
BPF_HASH(udpMapEven, struct udp_key_t, struct udp_value_t, MAPSIZE+2000);

BPF_HASH(udpv6MapOdd, struct udpv6_key_t, struct udpv6_value_t, MAPSIZE+2000);
BPF_HASH(udpv6MapEven, struct udpv6_key_t, struct udpv6_value_t, MAPSIZE+2000);

BPF_HASH(tcpMapOdd, struct tcp_key_t, struct tcp_value_t, MAPSIZE+2000);  
BPF_HASH(tcpMapEven, struct tcp_key_t, struct tcp_value_t, MAPSIZE+2000);

BPF_HASH(tcpv6MapOdd, struct tcpv6_key_t, struct tcpv6_value_t, MAPSIZE+2000);
BPF_HASH(tcpv6MapEven, struct tcpv6_key_t, struct tcpv6_value_t, MAPSIZE+2000);

//for TCP the IP-tuple will be known only upon return, so we stash the socket here to 
//look it up upon return 
BPF_HASH(tcpsock, u32, struct sock *, 100);
BPF_HASH(tcpv6sock, u32, struct tcpv6sock_value_t, 100);

//counts how many connections we've processed. Starts at 0.
BPF_ARRAY(tcpcounter, u64, 1);
BPF_ARRAY(tcpv6counter, u64, 1);
BPF_ARRAY(udpcounter, u64, 1);
BPF_ARRAY(udpv6counter, u64, 1);

BPF_ARRAY(tcpsendcounter, u64, 1);
BPF_HASH(tcpsend, struct tcp_key_t, struct tcp_value_t, 100000);

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk)
{
	u32 pid = bpf_get_current_pid_tgid();
	tcpsock.update(&pid, &sk);
	return 0;
};
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	struct sock **skpp = tcpsock.lookup(&pid);
	if (skpp == NULL) {
		tcpsendcounter.increment(0);
		return 0;}
	struct sock *skp = *skpp;
	
	struct tcp_key_t tcp_key = {};
	tcp_key.dport = skp->__sk_common.skc_dport;
	tcp_key.sport = inet_sk(skp)->inet_sport;
	tcp_key.daddr = skp->__sk_common.skc_daddr;

	struct tcp_value_t tcp_value = {};
	tcp_value.pid = pid;
	tcp_value.saddr = skp->__sk_common.skc_rcv_saddr;
	
	int zero_key = 0;
	u64 *val = tcpcounter.lookup(&zero_key);
	if (val == NULL){return 0;}
	tcp_value.counter = *val;

	//we need to decide into which map this connection goes
	u32 modulo = *val % (MAPSIZE*2);  
	if (modulo < MAPSIZE){ //from 0 to 4999 goes into odd map
		tcpMapOdd.update(&tcp_key, &tcp_value);
		if (modulo >= (MAPSIZE-1000) || modulo < 1000){
			//mirror the first and the last 1000 entries in another map
			struct tcp_key_t tcp_key2 = {};
			tcp_key2.dport = skp->__sk_common.skc_dport;
			tcp_key2.sport = inet_sk(skp)->inet_sport;
			tcp_key2.daddr = skp->__sk_common.skc_daddr;

			struct tcp_value_t tcp_value2 = {};
			tcp_value2.pid = pid;
			tcp_value2.saddr = skp->__sk_common.skc_rcv_saddr;
			tcp_value2.counter = *val;

			tcpMapEven.update(&tcp_key2, &tcp_value2);
		}
	}
	else {
		tcpMapEven.update(&tcp_key, &tcp_value);
		if (modulo >= (MAPSIZE*2-1000) || modulo < (MAPSIZE+1000) ){
			//mirror the the first and last 1000 entries in another map
			struct tcp_key_t tcp_key2 = {};
			tcp_key2.dport = skp->__sk_common.skc_dport;
			tcp_key2.sport = inet_sk(skp)->inet_sport;
			tcp_key2.daddr = skp->__sk_common.skc_daddr;

			struct tcp_value_t tcp_value2 = {};
			tcp_value2.pid = pid;
			tcp_value2.saddr = skp->__sk_common.skc_rcv_saddr;
			tcp_value2.counter = *val;

			tcpMapOdd.update(&tcp_key2, &tcp_value2);
		}
	}

	bpf_trace_printk("dumping packet : %d %d \\n", ntohs(tcp_key.sport), ntohs(tcp_key.dport));
	tcpcounter.increment(0);

	tcpsock.delete(&pid);
	return 0;
};


int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr)
{
	u32 pid = bpf_get_current_pid_tgid();
	struct tcpv6sock_value_t tcpv6sock_value = {};
	tcpv6sock_value.sk = sk;
	tcpv6sock_value.uaddr = uaddr;
	tcpv6sock.update(&pid, &tcpv6sock_value);
	return 0;
};
int kretprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();

	struct tcpv6sock_value_t *tcpv6sock_value = tcpv6sock.lookup(&pid);
	if (tcpv6sock_value == NULL) {return 0;}
	struct sock *sk = tcpv6sock_value->sk;
	struct sockaddr *uaddr = tcpv6sock_value->uaddr;
	struct sockaddr_in6 *usin = (struct sockaddr_in6 *) uaddr;
	
	struct tcpv6_key_t tcpv6_key = {};
	tcpv6_key.dport = sk->__sk_common.skc_dport;
	tcpv6_key.sport = inet_sk(sk)->inet_sport;
	bpf_probe_read(&tcpv6_key.daddr, sizeof(tcpv6_key.daddr),
		sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

	struct tcpv6_value_t tcpv6_value = {};
	tcpv6_value.pid = pid;
	bpf_probe_read(&tcpv6_value.saddr, sizeof(tcpv6_value.saddr), 
	sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

	int zero_key = 0;
	u64 *val = tcpv6counter.lookup(&zero_key);
	if (val == NULL){return 0;}
	tcpv6_value.counter = *val;

	u32 modulo = *val % (MAPSIZE*2);  
	if (modulo < MAPSIZE){
		tcpv6MapOdd.update(&tcpv6_key, &tcpv6_value);
		if (modulo >= (MAPSIZE-1000) || modulo < 1000){
			tcpv6MapEven.update(&tcpv6_key, &tcpv6_value);
		}
	}
	else {
		tcpv6MapEven.update(&tcpv6_key, &tcpv6_value);
		if (modulo >= (MAPSIZE*2-1000) || modulo < (MAPSIZE+1000)){
			//mirror the last 1000 entries in another map
			tcpv6MapOdd.update(&tcpv6_key, &tcpv6_value);
		}
	}
	
	tcpv6counter.increment(0);
	tcpv6sock.delete(&pid);
	return 0;
};


int kprobe__udp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{
	u32 pid = bpf_get_current_pid_tgid();
	struct flowi4 *fl4 = &(inet_sk(sk)->cork.fl.u.ip4);
	struct sockaddr_in * usin = (struct sockaddr_in *)msg->msg_name;

	struct udp_key_t udp_key = {};
	udp_key.dport = sk->__sk_common.skc_dport;
	if (udp_key.dport == 0){
		udp_key.dport = usin->sin_port;
		udp_key.daddr = usin->sin_addr.s_addr;
	}
	else {
		udp_key.daddr = sk->__sk_common.skc_daddr;
	}

	udp_key.sport = sk->__sk_common.skc_num;
	u32 saddr = sk->__sk_common.skc_rcv_saddr;
	if (saddr == 0) {
		saddr = inet_sk(sk)->inet_saddr;
		if (saddr == 0) {
			saddr = inet_sk(sk)->cork.fl.u.ip4.saddr;
			if (saddr == 0){
				if (sk->sk_state != TCP_CLOSE) {
					//if a UDP socket is listening on all interfaces 0.0.0.0,
					//its state must be 7 , (called TCP_CLOSE, although nothing to do with TCP)
					return 0;
				}
			}
		}
	}

	int zero_key = 0;
	u64 *counterVal = udpcounter.lookup(&zero_key);
	if (counterVal == NULL){return 0;}
	u32 modulo = *counterVal % (MAPSIZE*2);  
	bool oddMap = (modulo < MAPSIZE) ? true : false;

	struct udp_value_t *lookedupValue = oddMap ? udpMapOdd.lookup(&udp_key) : udpMapEven.lookup(&udp_key);
	if ( lookedupValue == NULL || lookedupValue->pid != pid) {
		struct udp_value_t udp_value = {};
		udp_value.pid = pid;
		udp_value.saddr = saddr;
		udp_value.counter = *counterVal;

		if (oddMap){
			udpMapOdd.update(&udp_key, &udp_value);
			if (modulo >= (MAPSIZE-1000) || modulo < 1000){
				//mirror the last 1000 entries in another map
				udpMapEven.update(&udp_key, &udp_value);
			}
		}
		else {
			udpMapEven.update(&udp_key, &udp_value);
			if (modulo >= (MAPSIZE*2-1000) || modulo < (MAPSIZE+1000)){
				//mirror the last 1000 entries in another map
				udpMapOdd.update(&udp_key, &udp_value);
			}
		}
		udpcounter.increment(0);
	}
	//else nothing to do
	return 0;

};

int kprobe__udpv6_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg, size_t len)
{	
	u32 pid = bpf_get_current_pid_tgid();
	struct sockaddr_in6 * usin = (struct sockaddr_in6 *)msg->msg_name;

	struct udpv6_key_t udpv6_key = {};

	udpv6_key.sport = sk->__sk_common.skc_num;

	udpv6_key.dport = sk->__sk_common.skc_dport;
	if (udpv6_key.dport == 0){
		struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *)msg->msg_name;
		udpv6_key.dport = sin6->sin6_port;
		bpf_probe_read(&udpv6_key.daddr, sizeof(udpv6_key.daddr),
			sin6->sin6_addr.in6_u.u6_addr32);
	}
	else {
		bpf_probe_read(&udpv6_key.daddr, sizeof(udpv6_key.daddr),
			sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	unsigned __int128 saddr;
	bpf_probe_read(&saddr, sizeof(saddr), 
		sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	if (saddr == 0){
		if (sk->sk_state != TCP_CLOSE) {
			//if a UDP socket is listening on all interfaces 0.0.0.0,
			//it's state must be 7 , (called TCP_CLOSE, although nothing to do with TCP)
			return 0;
		}
	}

	int zero_key = 0;
	u64 *counterVal = udpv6counter.lookup(&zero_key);
	if (counterVal == NULL){return 0;}
	u32 modulo = *counterVal % (MAPSIZE*2);  
	bool oddMap = (*counterVal % (MAPSIZE*2) <= MAPSIZE) ? true : false;

	struct udpv6_value_t *lookedupValue = oddMap ? udpv6MapOdd.lookup(&udpv6_key) : udpv6MapEven.lookup(&udpv6_key);
	if ( lookedupValue == NULL || lookedupValue->pid != pid) {
		struct udpv6_value_t udpv6_value = {};
		udpv6_value.pid = pid;
		udpv6_value.saddr = saddr;
		udpv6_value.counter = *counterVal;

		if (oddMap){
			udpv6MapOdd.update(&udpv6_key, &udpv6_value);
			if (modulo >= (MAPSIZE-1000) || modulo < 1000){
				//mirror the last 1000 entries in another map
				udpv6MapEven.update(&udpv6_key, &udpv6_value);
			}
		}
		else {
			udpv6MapEven.update(&udpv6_key, &udpv6_value);
			if (modulo >= (MAPSIZE*2-1000) || modulo < (MAPSIZE+1000)){
				//mirror the last 1000 entries in another map
				udpv6MapOdd.update(&udpv6_key, &udpv6_value);
			}
		}
		udpv6counter.increment(0);
	}
	//else nothing to do
	return 0;
	
};

int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk, struct msghdr *msg){
	u32 pid = bpf_get_current_pid_tgid();
	struct sockaddr_in * usin = (struct sockaddr_in *)msg->msg_name;

	struct tcp_key_t tcp_key = {};
	u16 dport = sk->__sk_common.skc_dport;
	u32 daddr;
	if (dport == 0){	
		tcp_key.dport = usin->sin_port;
		tcp_key.daddr = usin->sin_addr.s_addr;
	} else {
		tcp_key.dport = dport;
		tcp_key.daddr = sk->__sk_common.skc_daddr;
	}
	
	u16 sport = inet_sk(sk)->inet_sport;
	if (sport == 0) {
		sport = sk->__sk_common.skc_num;
	}
	tcp_key.sport = sport; 

	struct tcp_value_t tcp_value = {};
	tcp_value.pid = pid;
	tcp_value.saddr = sk->__sk_common.skc_rcv_saddr;

	int zero_key = 0;
	u64 *counterVal = tcpsendcounter.lookup(&zero_key);
	if (counterVal == NULL){return 0;}
	tcp_value.counter = *counterVal; 
	
	tcpsend.update(&tcp_key, &tcp_value);
	tcpsendcounter.increment(0);
	return 0;
}

`

//contains pointers to all ebpf maps (also called tables) for a given protocol (tcp/udp/v6)
type ebpfMapsForProto struct {
	sync.Mutex
	counter, mapEven, mapOdd *bcc.Table
	mapOddFd, mapEvenFd      uint64 //ebpf map file descriptor
	isOddInUse               bool
	waitingToPurgeOdd        bool
	waitingToPurgeEven       bool
}

func (e *ebpfMapsForProto) getIsOddInUse() bool {
	e.Lock()
	defer e.Unlock()
	return e.isOddInUse
}

//mimics union bpf_attr's anonymous struct used by BPF_MAP_*_ELEM commands
//from <linux_headers>/include/uapi/linux/bpf.h
type bpf_lookup_elem_t struct {
	map_fd uint64 //even though in bpf.h its type is __u32, we must make it 8 bytes long
	//because "key" is of type __aligned_u64, i.e. "key" must be aligned on an 8-byte boundary
	key   uintptr
	value uintptr
}

type lookup_value_t struct {
	pid     uint32
	saddr   uint32
	counter uint64
}

type lookup_valuev6_t struct {
	pid     uint32
	saddr1  uint64
	saddr2  uint64
	counter uint64
}

var (
	m                       *bpf.Module
	mapSize                 = 500000
	ebpfMaps                map[string]*ebpfMapsForProto
	alreadyEstablishedTCP   = make(map[*daemonNetlink.Socket]int)
	alreadyEstablishedTCPv6 = make(map[*daemonNetlink.Socket]int)
	stop                    = false
	tcpMapFd                int
	udpMapFd                int
	bpf_lookup_elem         bpf_lookup_elem_t
	bpf_lookup_elemv6       bpf_lookup_elem_t
	lookupKey               = make([]byte, 8)
	lookupKeyv6             = make([]byte, 20)
	lookupValue             lookup_value_t
	lookupValuev6           lookup_valuev6_t
	localAddresses          []net.IP
	localAddressesLock      sync.RWMutex
)

//Start installs ebpf kprobes
func Start() error {
	source = strings.ReplaceAll(source, "MAPSIZE", strconv.Itoa(mapSize))

	m = bpf.NewModule(source, []string{})
	tcpcounter := bpf.NewTable(m.TableId("tcpcounter"), m)
	tcpv6counter := bpf.NewTable(m.TableId("tcpv6counter"), m)
	udpcounter := bpf.NewTable(m.TableId("udpcounter"), m)
	udpv6counter := bpf.NewTable(m.TableId("udpv6counter"), m)
	tcpsendcounter := bpf.NewTable(m.TableId("tcpsendcounter"), m)

	for _, table := range []*bcc.Table{tcpcounter, tcpv6counter, udpcounter, udpv6counter, tcpsendcounter} {
		zeroKey := make([]byte, 4)
		zeroValue := make([]byte, 8)
		if err := table.Set(zeroKey, zeroValue); err != nil {
			fmt.Println("error in counterTable.Set", err)
			return err
		}
	}

	tcpMapOdd := bpf.NewTable(m.TableId("tcpMapOdd"), m)
	tcpMapEven := bpf.NewTable(m.TableId("tcpMapEven"), m)
	udpMapOdd := bpf.NewTable(m.TableId("udpMapOdd"), m)
	udpMapEven := bpf.NewTable(m.TableId("udpMapEven"), m)
	tcpv6MapOdd := bpf.NewTable(m.TableId("tcpv6MapOdd"), m)
	tcpv6MapEven := bpf.NewTable(m.TableId("tcpv6MapEven"), m)
	udpv6MapOdd := bpf.NewTable(m.TableId("udpv6MapOdd"), m)
	udpv6MapEven := bpf.NewTable(m.TableId("udpv6MapEven"), m)

	tcpMapOddFd := (uint64)(tcpMapOdd.Config()["fd"].(int))
	tcpMapEvenFd := (uint64)(tcpMapEven.Config()["fd"].(int))
	udpMapOddFd := (uint64)(udpMapOdd.Config()["fd"].(int))
	udpMapEvenFd := (uint64)(udpMapEven.Config()["fd"].(int))
	tcpv6MapOddFd := (uint64)(tcpv6MapOdd.Config()["fd"].(int))
	tcpv6MapEvenFd := (uint64)(tcpv6MapEven.Config()["fd"].(int))
	udpv6MapOddFd := (uint64)(udpv6MapOdd.Config()["fd"].(int))
	udpv6MapEvenFd := (uint64)(udpv6MapEven.Config()["fd"].(int))

	bpf_lookup_elem.key = uintptr(unsafe.Pointer(&lookupKey[0]))
	bpf_lookup_elem.value = uintptr(unsafe.Pointer(&lookupValue))
	bpf_lookup_elemv6.key = uintptr(unsafe.Pointer(&lookupKeyv6[0]))
	bpf_lookup_elemv6.value = uintptr(unsafe.Pointer(&lookupValuev6))

	ebpfMaps = map[string]*ebpfMapsForProto{
		"tcp": {mapEven: tcpMapEven, mapOdd: tcpMapOdd, counter: tcpcounter,
			mapOddFd: tcpMapOddFd, mapEvenFd: tcpMapEvenFd,
			isOddInUse: true, waitingToPurgeOdd: false, waitingToPurgeEven: true},
		"tcp6": {mapEven: tcpv6MapEven, mapOdd: tcpv6MapOdd, counter: tcpv6counter,
			mapOddFd: tcpv6MapOddFd, mapEvenFd: tcpv6MapEvenFd,
			isOddInUse: true, waitingToPurgeOdd: false, waitingToPurgeEven: true},
		"udp": {mapEven: udpMapEven, mapOdd: udpMapOdd, counter: udpcounter,
			mapOddFd: udpMapOddFd, mapEvenFd: udpMapEvenFd,
			isOddInUse: true, waitingToPurgeOdd: false, waitingToPurgeEven: true},
		"udp6": {mapEven: udpv6MapEven, mapOdd: udpv6MapOdd, counter: udpv6counter,
			mapOddFd: udpv6MapOddFd, mapEvenFd: udpv6MapEvenFd,
			isOddInUse: true, waitingToPurgeOdd: false, waitingToPurgeEven: true},
	}

	for _, name := range []string{"tcp_v4_connect", "tcp_v6_connect", "udp_sendmsg", "udpv6_sendmsg", "tcp_sendmsg"} {
		probe, err := m.LoadKprobe(fmt.Sprintf("kprobe__%s", name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load kprobe__%s: %s\n", name, err)
			return err
		}
		// passing -1 for maxActive signifies to use the default
		// according to the kernel kprobes documentation
		err = m.AttachKprobe(name, probe, -1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to attach kprobe__%s: %s\n", name, err)
			return err
		}
		if name == "udp_sendmsg" || name == "udpv6_sendmsg" || name == "tcp_sendmsg" {
			continue
		}
		//attach kretprobes for tcp_v4_connect and tcp_v6_connect
		probe, err = m.LoadKprobe(fmt.Sprintf("kretprobe__%s", name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load kretprobe__%s: %s\n", name, err)
			return err
		}
		err = m.AttachKretprobe(name, probe, -1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to attach kretprobe__%s: %s\n", name, err)
			return err
		}
	}

	socketListTCP, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET), uint8(syscall.IPPROTO_TCP))
	if err != nil {
		fmt.Println("error in SocketsDump")
	}
	for _, sock := range socketListTCP {
		fmt.Println(*sock)
		inode := int((*sock).INode)
		pid := procmon.GetPIDFromINode(inode, fmt.Sprint(inode,
			(*sock).ID.Source, (*sock).ID.SourcePort, (*sock).ID.Destination, (*sock).ID.DestinationPort))
		fmt.Println(pid)
		alreadyEstablishedTCP[sock] = pid
	}

	socketListTCPv6, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET6), uint8(syscall.IPPROTO_TCP))
	if err != nil {
		fmt.Println("error in SocketsDump")
	}
	for _, sock := range socketListTCPv6 {
		fmt.Println(*sock)
		inode := int((*sock).INode)
		pid := procmon.GetPIDFromINode(inode, fmt.Sprint(inode,
			(*sock).ID.Source, (*sock).ID.SourcePort, (*sock).ID.Destination, (*sock).ID.DestinationPort))

		fmt.Println(pid)
		alreadyEstablishedTCPv6[sock] = pid
	}

	go monitorAndSwitchMaps()
	go monitorLocalAddresses()

	return nil
}

func Stop() {
	stop = true
}

//we need to manually remove old connections from a bpf map
//since a full bpf map doesnt allow any insertions
//all our bpf maps are of size 10000
func monitorAndSwitchMaps() {
	zeroKey := make([]byte, 4)
	for {
		time.Sleep(time.Second * 1)
		if stop {
			return
		}
		for _, ebpfMap := range ebpfMaps {
			v, err := ebpfMap.counter.Get(zeroKey)
			if err != nil {
				fmt.Println("error in hashmap.counter.Get(zeroKey)", err)
				continue
			}
			counterValue := binary.LittleEndian.Uint64(v)
			//fmt.Println("counterValue", counterValue)
			modulo := counterValue % uint64(mapSize*2)

			if !ebpfMap.isOddInUse && modulo < uint64(mapSize) {
				ebpfMap.Lock()
				ebpfMap.isOddInUse = true
				ebpfMap.waitingToPurgeEven = true
				ebpfMap.Unlock()
			}
			if ebpfMap.waitingToPurgeEven && modulo >= 1000 {
				err = ebpfMap.mapEven.DeleteAll()
				if err != nil {
					fmt.Println("error in hashmap.id.Delete", err)
				}
				ebpfMap.Lock()
				ebpfMap.waitingToPurgeEven = false
				ebpfMap.Unlock()
			}
			if ebpfMap.isOddInUse && modulo >= uint64(mapSize) {
				ebpfMap.Lock()
				ebpfMap.isOddInUse = false
				ebpfMap.waitingToPurgeOdd = true
				ebpfMap.Unlock()
			}
			if ebpfMap.waitingToPurgeOdd && modulo >= uint64(mapSize+1000) {
				err = ebpfMap.mapOdd.DeleteAll()
				if err != nil {
					fmt.Println("error in hashmap.id.Delete", err)
				}
				ebpfMap.Lock()
				ebpfMap.waitingToPurgeOdd = false
				ebpfMap.Unlock()
			}
		}
	}
}

func GetPid(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) int {

	var pid int
	var key *[]byte
	var bpf_lookup *bpf_lookup_elem_t

	if proto == "tcp" || proto == "udp" {
		key = &lookupKey
		bpf_lookup = &bpf_lookup_elem
		copy((*key)[2:6], dstIP)
		binary.BigEndian.PutUint16((*key)[6:8], uint16(dstPort))
	}
	if proto == "tcp6" || proto == "udp6" {
		key = &lookupKeyv6
		bpf_lookup = &bpf_lookup_elemv6
		copy((*key)[2:18], dstIP)
		binary.BigEndian.PutUint16((*key)[18:20], uint16(dstPort))
	}
	if proto == "tcp" || proto == "tcp6" {
		binary.BigEndian.PutUint16((*key)[0:2], uint16(srcPort))
	}
	if proto == "udp" || proto == "udp6" {
		binary.LittleEndian.PutUint16((*key)[0:2], uint16(srcPort))
	}

	ebpfMap := ebpfMaps[proto]
	if (*ebpfMap).getIsOddInUse() {
		bpf_lookup.map_fd = (*ebpfMap).mapOddFd
	} else {
		bpf_lookup.map_fd = (*ebpfMap).mapEvenFd
	}

	BPF_MAP_LOOKUP_ELEM := 1 //cmd number
	syscall_BPF := 321       //syscall number
	sizeOfStruct := 24       //sizeof bpf_lookup_elem_t struct

	var r1 uintptr
	var err error
	var i int
	for i = 0; i < 500; i++ {

		r1, _, err = syscall.Syscall(uintptr(syscall_BPF), uintptr(BPF_MAP_LOOKUP_ELEM),
			uintptr(unsafe.Pointer(bpf_lookup)), uintptr(sizeOfStruct))
		if r1 != 0 && proto == "udp" && srcIP.String() == "127.0.0.1" && dstIP.String() == "127.0.0.1" {
			//very rarely I see this connection. It has dstIP == 0.0.0.0 in ebpf map
			//I could not reproduce it
			copy((*key)[2:6], make([]byte, 4))
			r1, _, err = syscall.Syscall(uintptr(syscall_BPF), uintptr(BPF_MAP_LOOKUP_ELEM),
				uintptr(unsafe.Pointer(bpf_lookup)), uintptr(sizeOfStruct))
		}
		if r1 == 0 {
			break
		}
	}

	if r1 != 0 {
		fmt.Println("looked up key", hex.EncodeToString(*key))
		fmt.Println("the was an error", err)
		return -1
	}
	if i > 0 {
		fmt.Println("found in ebpf map only on i-th time:", i)
		return -1
	}

	if proto == "tcp" || proto == "udp" {
		pid = int(lookupValue.pid)
	} else {
		pid = int(lookupValuev6.pid)
	}
	//TODO assert that srcIP in lookupValue(v6) equals to our srcIP
	return pid
}

//FindInAlreadyEstablishedTCP searches those TCP connections which were already established at the time
//when opensnitch started
func FindInAlreadyEstablishedTCP(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) (int, error) {
	if proto == "tcp" {
		for sock, v := range alreadyEstablishedTCP {
			if (*sock).ID.SourcePort == uint16(srcPort) && (*sock).ID.Source.Equal(srcIP) &&
				(*sock).ID.Destination.Equal(dstIP) && (*sock).ID.DestinationPort == uint16(dstPort) {
				return v, nil
			}
		}
	}
	if proto == "tcp6" {
		for sock, v := range alreadyEstablishedTCPv6 {
			if (*sock).ID.SourcePort == uint16(srcPort) && (*sock).ID.Source.Equal(srcIP) &&
				(*sock).ID.Destination.Equal(dstIP) && (*sock).ID.DestinationPort == uint16(dstPort) {
				return v, nil
			}
		}
	}
	return 0, fmt.Errorf("Inode not found")
}

func FindAddressInLocalAddresses(addr net.IP) bool {
	localAddressesLock.Lock()
	defer localAddressesLock.Unlock()
	for _, a := range localAddresses {
		if addr.String() == a.String() {
			return true
		}
	}
	return false
}

//maintains a list of this machine's local addresses
func monitorLocalAddresses() {
	for {
		addr, err := netlink.AddrList(nil, netlink.FAMILY_ALL)
		if err != nil {
			fmt.Println("error in netlink.AddrList", err)
			continue
		}
		localAddressesLock.Lock()
		localAddresses = nil
		for _, a := range addr {
			localAddresses = append(localAddresses, a.IP)
		}
		localAddressesLock.Unlock()
		time.Sleep(time.Second * 1)
	}
}

//PrintEverything prints all the stats
func PrintEverything(suffix string) {
	bash, _ := exec.LookPath("bash")
	cmd := exec.Command(bash, "-c", "bpftool map dump name tcpMapOdd > mapoddHi"+suffix)
	if err := cmd.Run(); err != nil {
		fmt.Println("Error running go test -c", err)
	}

	bash, _ = exec.LookPath("bash")
	cmd = exec.Command(bash, "-c", "bpftool map dump name tcpMapEven > mapEvenHi"+suffix)
	if err := cmd.Run(); err != nil {
		fmt.Println("Error running go test -c", err)
	}

	for sock1, v := range alreadyEstablishedTCP {
		fmt.Println(*sock1, v)
	}
	fmt.Println("---------------------")
	for sock1, v := range alreadyEstablishedTCPv6 {
		fmt.Println(*sock1, v)
	}
	fmt.Println("---------------------")
	sockets, _ := daemonNetlink.SocketsDump(syscall.AF_INET, syscall.IPPROTO_TCP)
	for idx := range sockets {
		fmt.Println("socket tcp: ", sockets[idx])
	}
	fmt.Println("---------------------")
	sockets, _ = daemonNetlink.SocketsDump(syscall.AF_INET6, syscall.IPPROTO_TCP)
	for idx := range sockets {
		fmt.Println("socket tcp6: ", sockets[idx])
	}
	fmt.Println("---------------------")
	sockets, _ = daemonNetlink.SocketsDump(syscall.AF_INET, syscall.IPPROTO_UDP)
	for idx := range sockets {
		fmt.Println("socket udp: ", sockets[idx])
	}
	fmt.Println("---------------------")
	sockets, _ = daemonNetlink.SocketsDump(syscall.AF_INET6, syscall.IPPROTO_UDP)
	for idx := range sockets {
		fmt.Println("socket udp6: ", sockets[idx])
	}

}
