#define KBUILD_MODNAME "dummy"

#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <net/sock.h>
#include <net/inet_sock.h>

#define MAPSIZE 50000
#define MAPCACHESIZE 10000

//-------------------------------map definitions 
// which github.com/iovisor/gobpf/elf expects
#define BUF_SIZE_MAP_NS 256

typedef struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
	unsigned int pinning;
	char namespace[BUF_SIZE_MAP_NS];
} bpf_map_def;

enum bpf_pin_type {
	PIN_NONE = 0,
	PIN_OBJECT_NS,
	PIN_GLOBAL_NS,
	PIN_CUSTOM_NS,
};
//-----------------------------------

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

// Add +1,+2, etc. to max size helps to easier distinguish maps in bpftool's output
struct bpf_map_def SEC("maps/tcpMapOdd") tcpMapOdd = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcp_key_t),
	.value_size = sizeof(struct tcp_value_t),
	.max_entries = MAPSIZE+MAPCACHESIZE*2+1,
};

struct bpf_map_def SEC("maps/tcpMapEven") tcpMapEven = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcp_key_t),
	.value_size = sizeof(struct tcp_value_t),
	.max_entries = MAPSIZE+MAPCACHESIZE*2+2,
};

struct bpf_map_def SEC("maps/tcpv6MapOdd") tcpv6MapOdd = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcpv6_key_t),
	.value_size = sizeof(struct tcpv6_value_t),
	.max_entries = MAPSIZE+MAPCACHESIZE*2+3,
};

struct bpf_map_def SEC("maps/tcpv6MapEven") tcpv6MapEven = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcpv6_key_t),
	.value_size = sizeof(struct tcpv6_value_t),
	.max_entries = MAPSIZE+MAPCACHESIZE*2+4,
};

struct bpf_map_def SEC("maps/udpMapOdd") udpMapOdd = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct udp_key_t),
	.value_size = sizeof(struct udp_value_t),
	.max_entries = MAPSIZE+MAPCACHESIZE*2+5,
};

struct bpf_map_def SEC("maps/udpMapEven") udpMapEven = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct udp_key_t),
	.value_size = sizeof(struct udp_value_t),
	.max_entries = MAPSIZE+MAPCACHESIZE*2+6,
};

struct bpf_map_def SEC("maps/udpv6MapOdd") udpv6MapOdd = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct udpv6_key_t),
	.value_size = sizeof(struct udpv6_value_t),
	.max_entries = MAPSIZE+MAPCACHESIZE*2+7,
};

struct bpf_map_def SEC("maps/udpv6MapEven") udpv6MapEven = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct udpv6_key_t),
	.value_size = sizeof(struct udpv6_value_t),
	.max_entries = MAPSIZE+MAPCACHESIZE*2+8,
};



// //for TCP the IP-tuple will be known only upon return, so we stash the socket here to 
// //look it up upon return 
struct bpf_map_def SEC("maps/tcpsock") tcpsock = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct sock *),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps/tcpv6sock") tcpv6sock = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(struct tcpv6sock_value_t),
	.max_entries = 100,
};

// //counts how many connections we've processed. Starts at 0.
struct bpf_map_def SEC("maps/tcpcounter") tcpcounter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};
struct bpf_map_def SEC("maps/tcpv6counter") tcpv6counter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};
struct bpf_map_def SEC("maps/udpcounter") udpcounter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};
struct bpf_map_def SEC("maps/udpv6counter") udpv6counter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};


SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	u32 pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcpsock, &pid, &sk, BPF_ANY);
	return 0;
};
SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();
	struct sock **skp = bpf_map_lookup_elem(&tcpsock, &pid);
	if (skp == NULL) {
		return 0;}
	struct sock *sk = *skp;
	
	struct tcp_key_t tcp_key = {};
	bpf_probe_read(&tcp_key.dport, sizeof(tcp_key.dport), &sk->__sk_common.skc_dport);
	struct inet_sock *inet_sk = (struct inet_sock *)sk;
    bpf_probe_read(&tcp_key.sport, sizeof(tcp_key.sport), &inet_sk->inet_sport);
	bpf_probe_read(&tcp_key.daddr, sizeof(tcp_key.daddr), &sk->__sk_common.skc_daddr);
	struct tcp_value_t tcp_value = {};
	tcp_value.pid = pid;
	bpf_probe_read(&tcp_value.saddr, sizeof(tcp_value.saddr), &sk->__sk_common.skc_daddr);
	
	int zero_key = 0;
	u64 *val = bpf_map_lookup_elem(&tcpcounter, &zero_key);
	if (val == NULL){return 0;}
	tcp_value.counter = *val;

	//we need to decide into which map this connection goes
	u32 modulo = *val % (MAPSIZE*2);  
	if (modulo < MAPSIZE){ //from 0 to 4999 goes into odd map
	    bpf_map_update_elem(&tcpMapOdd, &tcp_key, &tcp_value, BPF_ANY);
		if (modulo >= (MAPSIZE-MAPCACHESIZE) || modulo < MAPCACHESIZE){
			//mirror the first and the last MAPCACHESIZE entries in another map
			struct tcp_key_t tcp_key2 = {};
			tcp_key2.dport = tcp_key.dport;
			tcp_key2.sport = tcp_key.sport;
			tcp_key2.daddr = tcp_key.daddr;

			struct tcp_value_t tcp_value2 = {};
			tcp_value2.pid = pid;
			tcp_value2.saddr = tcp_value.saddr;
			tcp_value2.counter = *val;

			bpf_map_update_elem(&tcpMapEven, &tcp_key2, &tcp_value2, BPF_ANY);
		}
	}
	else {
		bpf_map_update_elem(&tcpMapEven, &tcp_key, &tcp_value, BPF_ANY);
		if (modulo >= (MAPSIZE*2-MAPCACHESIZE) || modulo < (MAPSIZE+MAPCACHESIZE) ){
			//mirror the the first and last MAPCACHESIZE entries in another map
			struct tcp_key_t tcp_key2 = {};
			tcp_key2.dport = tcp_key.dport;
			tcp_key2.sport = tcp_key.sport;
			tcp_key2.daddr = tcp_key.daddr;

			struct tcp_value_t tcp_value2 = {};
			tcp_value2.pid = pid;
			tcp_value2.saddr = tcp_value.saddr;
			tcp_value2.counter = *val;

			bpf_map_update_elem(&tcpMapOdd, &tcp_key2, &tcp_value2, BPF_ANY);
		}
	}
	u64 newval = *val + 1;
	bpf_map_update_elem(&tcpcounter, &zero_key, &newval, BPF_ANY);
	bpf_map_delete_elem(&tcpsock, &pid);
	return 0;
};


SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct sockaddr *uaddr = (struct sockaddr *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();
	struct tcpv6sock_value_t tcpv6sock_value = {};
	tcpv6sock_value.sk = sk;
	tcpv6sock_value.uaddr = uaddr;
	bpf_map_update_elem(&tcpv6sock, &pid, &tcpv6sock_value, BPF_ANY);
	return 0;
};
SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	u32 pid = bpf_get_current_pid_tgid();

	struct tcpv6sock_value_t *tcpv6sock_value = bpf_map_lookup_elem(&tcpv6sock, &pid);
	if (tcpv6sock_value == NULL) {return 0;}

	struct sock *sk = tcpv6sock_value->sk;
	struct sockaddr *uaddr = tcpv6sock_value->uaddr;
	struct sockaddr_in6 *usin = (struct sockaddr_in6 *) uaddr;
	
	struct tcpv6_key_t tcpv6_key = {};
	bpf_probe_read(&tcpv6_key.dport, sizeof(tcpv6_key.dport), &sk->__sk_common.skc_dport);
	struct inet_sock *inet_sk = (struct inet_sock *)sk;
	bpf_probe_read(&tcpv6_key.sport, sizeof(tcpv6_key.sport), &inet_sk->inet_sport);
	bpf_probe_read(&tcpv6_key.daddr, sizeof(tcpv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);

	struct tcpv6_value_t tcpv6_value = {};
	tcpv6_value.pid = pid;
	bpf_probe_read(&tcpv6_value.saddr, sizeof(tcpv6_value.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

	int zero_key = 0;
	u64 *val = bpf_map_lookup_elem(&tcpv6counter, &zero_key);
	if (val == NULL){return 0;}
	tcpv6_value.counter = *val;

	u32 modulo = *val % (MAPSIZE*2);  
	if (modulo < MAPSIZE){
		bpf_map_update_elem(&tcpv6MapOdd, &tcpv6_key, &tcpv6_value, BPF_ANY);
		if (modulo >= (MAPSIZE-MAPCACHESIZE) || modulo < MAPCACHESIZE){
			bpf_map_update_elem(&tcpv6MapEven, &tcpv6_key, &tcpv6_value, BPF_ANY);
		}
	}
	else {
		bpf_map_update_elem(&tcpv6MapEven, &tcpv6_key, &tcpv6_value, BPF_ANY);
		if (modulo >= (MAPSIZE*2-MAPCACHESIZE) || modulo < (MAPSIZE+MAPCACHESIZE)){
			//mirror the last MAPCACHESIZE entries in another map
			bpf_map_update_elem(&tcpv6MapOdd, &tcpv6_key, &tcpv6_value, BPF_ANY);
		}
	}
	u64 newval = *val + 1;
	bpf_map_update_elem(&tcpv6counter, &zero_key, &newval, BPF_ANY);
	bpf_map_delete_elem(&tcpv6sock, &pid);
	return 0;
};


SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();
	struct inet_sock *inet_sk = (struct inet_sock *)sk;
	struct flowi4 fl4;
	bpf_probe_read(&fl4, sizeof(fl4), &inet_sk->cork.fl.u.ip4);

	void *msg_name;
	bpf_probe_read(&msg_name, sizeof(msg_name), &msg->msg_name);
	struct sockaddr_in * usin = (struct sockaddr_in *)msg_name;

	struct udp_key_t udp_key = {};
	bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &sk->__sk_common.skc_dport);
	if (udp_key.dport == 0){
		bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &usin->sin_port);
		bpf_probe_read(&udp_key.daddr, sizeof(udp_key.daddr), &usin->sin_addr.s_addr);
	}
	else {
		bpf_probe_read(&udp_key.daddr, sizeof(udp_key.daddr), &sk->__sk_common.skc_daddr);
	}
	bpf_probe_read(&udp_key.sport, sizeof(udp_key.sport), &sk->__sk_common.skc_num);
	u32 saddr;
	bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
	if (saddr == 0) {
		bpf_probe_read(&saddr, sizeof(saddr), &inet_sk->inet_saddr);
		if (saddr == 0) {
			bpf_probe_read(&saddr, sizeof(saddr), &inet_sk->cork.fl.u.ip4.saddr);
			if (saddr == 0){
				unsigned char state;
				bpf_probe_read(&state, sizeof(state), &sk->sk_state);
				if (state != TCP_CLOSE) {
					//if a UDP socket is listening on all interfaces 0.0.0.0,
					//its state must be 7 , (called TCP_CLOSE, although nothing to do with TCP)
					return 0;
				}
			}
		}
	}

	int zero_key = 0;
	u64 *counterVal = bpf_map_lookup_elem(&udpcounter, &zero_key);
	if (counterVal == NULL){return 0;}
	u32 modulo = *counterVal % (MAPSIZE*2);  
	bool oddMap = (modulo < MAPSIZE) ? true : false;

	struct udp_value_t *lookedupValue;
	if (oddMap){
		lookedupValue = bpf_map_lookup_elem(&udpMapOdd, &udp_key);
	}
	else {
		lookedupValue = bpf_map_lookup_elem(&udpMapEven, &udp_key);
	}
	if ( lookedupValue == NULL || lookedupValue->pid != pid) {
		struct udp_value_t udp_value = {};
		udp_value.pid = pid;
		udp_value.saddr = saddr;
		udp_value.counter = *counterVal;

		if (oddMap){
			bpf_map_update_elem(&udpMapOdd, &udp_key, &udp_value, BPF_ANY);
			if (modulo >= (MAPSIZE-MAPCACHESIZE) || modulo < MAPCACHESIZE){
				//mirror the last 1000 entries in another map
				bpf_map_update_elem(&udpMapEven, &udp_key, &udp_value, BPF_ANY);
			}
		}
		else {
			bpf_map_update_elem(&udpMapEven, &udp_key, &udp_value, BPF_ANY);
			if (modulo >= (MAPSIZE*2-MAPCACHESIZE) || modulo < (MAPSIZE+MAPCACHESIZE)){
				//mirror the last 1000 entries in another map
				bpf_map_update_elem(&udpMapOdd, &udp_key, &udp_value, BPF_ANY);
			}
		}
		u64 newval = *counterVal + 1;
		bpf_map_update_elem(&udpcounter, &zero_key, &newval, BPF_ANY);
	}
	//else nothing to do
	return 0;

};


SEC("kprobe/udpv6_sendmsg")
int kprobe__udpv6_sendmsg(struct pt_regs *ctx)
{	
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

	u32 pid = bpf_get_current_pid_tgid();
	void *msg_name;
	bpf_probe_read(&msg_name, sizeof(msg_name), &msg->msg_name);

	struct udpv6_key_t udpv6_key = {};
	bpf_probe_read(&udpv6_key.sport, sizeof(udpv6_key.sport), &sk->__sk_common.skc_num);
	bpf_probe_read(&udpv6_key.dport, sizeof(udpv6_key.dport), &sk->__sk_common.skc_dport);

	if (udpv6_key.dport == 0){
		struct sockaddr_in6 * sin6 = (struct sockaddr_in6 *)msg_name;
		bpf_probe_read(&udpv6_key.dport, sizeof(udpv6_key.dport), &sin6->sin6_port);
		bpf_probe_read(&udpv6_key.daddr, sizeof(udpv6_key.daddr), &sin6->sin6_addr.in6_u.u6_addr32);
	}
	else {
		bpf_probe_read(&udpv6_key.daddr, sizeof(udpv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	unsigned __int128 saddr;
	bpf_probe_read(&saddr, sizeof(saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	if (saddr == 0){
		unsigned char state;
		bpf_probe_read(&state, sizeof(state), &sk->sk_state);
		if (state != TCP_CLOSE) {
			//if a UDP socket is listening on all interfaces 0.0.0.0,
			//it's state must be 7 , (called TCP_CLOSE, although nothing to do with TCP)
			return 0;
		}
	}

	int zero_key = 0;
	u64 *counterVal = bpf_map_lookup_elem(&udpv6counter, &zero_key);
	if (counterVal == NULL){return 0;}
	u32 modulo = *counterVal % (MAPSIZE*2);  
	bool oddMap = (*counterVal % (MAPSIZE*2) <= MAPSIZE) ? true : false;

	struct udpv6_value_t *lookedupValue;
	if (oddMap){
		lookedupValue = bpf_map_lookup_elem(&udpv6MapOdd, &udpv6_key);
	}
	else {
		lookedupValue = bpf_map_lookup_elem(&udpv6MapEven, &udpv6_key);
	}
	if ( lookedupValue == NULL || lookedupValue->pid != pid) {
		struct udpv6_value_t udpv6_value = {};
		udpv6_value.pid = pid;
		udpv6_value.saddr = saddr;
		udpv6_value.counter = *counterVal;

		if (oddMap){
			bpf_map_update_elem(&udpv6MapOdd, &udpv6_key, &udpv6_value, BPF_ANY);
			if (modulo >= (MAPSIZE-MAPCACHESIZE) || modulo < MAPCACHESIZE){
				//mirror the last 1000 entries in another map
				bpf_map_update_elem(&udpv6MapEven, &udpv6_key, &udpv6_value, BPF_ANY);
			}
		}
		else {
			bpf_map_update_elem(&udpv6MapEven, &udpv6_key, &udpv6_value, BPF_ANY);
			if (modulo >= (MAPSIZE*2-MAPCACHESIZE) || modulo < (MAPSIZE+MAPCACHESIZE)){
				//mirror the last 1000 entries in another map
				bpf_map_update_elem(&udpv6MapOdd, &udpv6_key, &udpv6_value, BPF_ANY);
			}
		}
		u64 newval = *counterVal + 1;
		bpf_map_update_elem(&udpv6counter, &zero_key, &newval, BPF_ANY);	
	}
	//else nothing to do
	return 0;
	
};

char _license[] SEC("license") = "GPL";
// this number will be interpreted by the elf loader
// to set the current running kernel version
u32 _version SEC("version") = 0xFFFFFFFE;
