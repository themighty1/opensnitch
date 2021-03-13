#define KBUILD_MODNAME "dummy"

#include <linux/ptrace.h>
#include <linux/version.h>
#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h> 
#include <net/sock.h>
#include <net/inet_sock.h>

#define MAPSIZE 12000

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
	u32 saddr;
}__attribute__((packed));

struct tcp_value_t{
	u64 pid; //32-bit verifier complains when this is set to u32
	u64 counter; //counters in value are for debug purposes only
}__attribute__((packed));

// not using unsigned __int128 because it is not supported on 32-bit platforms
struct ipV6 {
	u64 part1;
	u64 part2;
}__attribute__((packed));

struct tcpv6_key_t {
	u16 sport;
	struct ipV6 daddr;
	//unsigned __int128 daddr;
	u16 dport;
	struct ipV6 saddr;
	//unsigned __int128 saddr;
}__attribute__((packed));

struct tcpv6_value_t{
	u64 pid;
	u64 counter; //counters in value are for debug purposes only
}__attribute__((packed));;

struct udp_key_t {
	u16 sport;
	u32 daddr;
	u16 dport;
	u32 saddr; 
} __attribute__((packed));

struct udp_value_t{
	u64 pid;
	u32 saddr1;
	u32 saddr2;
	u32 saddr3;
	u32 saddr4;
	u64 counter; //counters in value are for debug purposes only
}__attribute__((packed));

struct udpv6_key_t {
	u16 sport;
	struct ipV6 daddr;
	//unsigned __int128 daddr;
	u16 dport;
	struct ipV6 saddr; 
	//unsigned __int128 saddr;
}__attribute__((packed));

struct udpv6_value_t{
	u64 pid;
	u64 counter; //counters in value are for debug purposes only
}__attribute__((packed));


// Add +1,+2, etc. to map size helps to easier distinguish maps in bpftool's output
struct bpf_map_def SEC("maps/tcpMap") tcpMap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcp_key_t),
	.value_size = sizeof(struct tcp_value_t),
	.max_entries = MAPSIZE+1,
};
struct bpf_map_def SEC("maps/tcpv6Map") tcpv6Map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct tcpv6_key_t),
	.value_size = sizeof(struct tcpv6_value_t),
	.max_entries = MAPSIZE+2,
};
struct bpf_map_def SEC("maps/udpMap") udpMap = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct udp_key_t),
	.value_size = sizeof(struct udp_value_t),
	.max_entries = MAPSIZE+3,
};
struct bpf_map_def SEC("maps/udpv6Map") udpv6Map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct udpv6_key_t),
	.value_size = sizeof(struct udpv6_value_t),
	.max_entries = MAPSIZE+4,
};

// //for TCP the IP-tuple will be known only upon return, so we stash the socket here to 
// //look it up upon return 
struct bpf_map_def SEC("maps/tcpsock") tcpsock = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),// using u64 instead of sizeof(struct sock *) 
							  // to avoid pointer quirks on 32-bit platforms
	.max_entries = 100,
};
struct bpf_map_def SEC("maps/tcpv6sock") tcpv6sock = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u64),
	.value_size = sizeof(u64),
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
struct bpf_map_def SEC("maps/debugcounter") debugcounter = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(u64),
	.max_entries = 1,
};


//maps/bytes used for debug purposes only
struct bpf_map_def SEC("maps/bytes") bytes = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u8),
	.value_size = sizeof(u8),
	.max_entries = 222,
};

//150 too much for 4.14 100 is 0k
struct rawBytes_t {
    u8 bytes[100];
};

// initializing variables with __builtin_memset() is required
// for compatibility with bpf on kernel 4.4


SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	u32 zero_key = 0;
	u64 *val = bpf_map_lookup_elem(&debugcounter, &zero_key);
	if (val == NULL){return 0;}
	u64 newval = *val + 1;
	bpf_map_update_elem(&debugcounter, &zero_key, &newval, BPF_ANY);

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	u64 skp = sk;
	u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcpsock, &pid_tgid, &skp, BPF_ANY);
	return 0;
};


SEC("kretprobe/tcp_v4_connect")
int kretprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *skp = bpf_map_lookup_elem(&tcpsock, &pid_tgid);
	if (skp == NULL) {return 0;}

	struct sock *sk;
	__builtin_memset(&sk, 0, sizeof(sk));
	sk = *skp;

	struct tcp_key_t tcp_key;
    __builtin_memset(&tcp_key, 0, sizeof(tcp_key));
	bpf_probe_read(&tcp_key.dport, sizeof(tcp_key.dport), &sk->__sk_common.skc_dport);

    struct rawBytes_t rb;
    __builtin_memset(&rb, 0, sizeof(rb));
    bpf_probe_read(&rb, sizeof(rb), *(&sk));
	// accessing sport via hard-coded offset worked on all kernels
	// however accesing it via inet(sk)->sport gave wrong results on kernel 4.19
    const u8 offset0 = 0x0e;
    const u8 offset1 = 0x0f;
    // u8 port[2] = {0,0}; don't init like this, it will be optimized away by clang
    u8 port_bytes[2];
    port_bytes[1] = rb.bytes[offset0];
    port_bytes[0] = rb.bytes[offset1];
    u16 *sport = (u16 *)&port_bytes;
    tcp_key.sport = *sport;
       
	bpf_probe_read(&tcp_key.daddr, sizeof(tcp_key.daddr), &sk->__sk_common.skc_daddr);
	bpf_probe_read(&tcp_key.saddr, sizeof(tcp_key.saddr), &sk->__sk_common.skc_rcv_saddr);
	
	u32 zero_key = 0;
	u64 *val = bpf_map_lookup_elem(&tcpcounter, &zero_key);
	if (val == NULL){return 0;}

	struct tcp_value_t tcp_value;
    __builtin_memset(&tcp_value, 0, sizeof(tcp_value));
	tcp_value.pid = pid_tgid >> 32;
	tcp_value.counter = *val;
	bpf_map_update_elem(&tcpMap, &tcp_key, &tcp_value, BPF_ANY);

	u64 newval = *val + 1;
	bpf_map_update_elem(&tcpcounter, &zero_key, &newval, BPF_ANY);
	bpf_map_delete_elem(&tcpsock, &pid_tgid);
	return 0;
};


SEC("kprobe/tcp_v6_connect")
int kprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	u64 skp = sk;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&tcpv6sock, &pid_tgid, &skp, BPF_ANY);
	return 0;
};
SEC("kretprobe/tcp_v6_connect")
int kretprobe__tcp_v6_connect(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *skp = bpf_map_lookup_elem(&tcpv6sock, &pid_tgid);
	if (skp == NULL) {return 0;}
	struct sock *sk;
	__builtin_memset(&sk, 0, sizeof(sk));
	sk = *skp;
	
	struct tcpv6_key_t tcpv6_key;
    __builtin_memset(&tcpv6_key, 0, sizeof(tcpv6_key));
	bpf_probe_read(&tcpv6_key.dport, sizeof(tcpv6_key.dport), &sk->__sk_common.skc_dport);

	struct rawBytes_t rb;
    __builtin_memset(&rb, 0, sizeof(rb));
    bpf_probe_read(&rb, sizeof(rb), *(&sk));
	// accessing sport via hard-coded offset worked on all kernels
	// however accesing it via inet(sk)->sport gave wrong results on kernel 4.19
    const u8 offset0 = 0x0e;
    const u8 offset1 = 0x0f;
    // u8 port[2] = {0,0}; don't init like this, it will be optimized away by clang
    u8 port_bytes[2];
    port_bytes[1] = rb.bytes[offset0];
    port_bytes[0] = rb.bytes[offset1];
    u16 *sport = (u16 *)&port_bytes;
    tcpv6_key.sport = *sport;

	bpf_probe_read(&tcpv6_key.daddr, sizeof(tcpv6_key.daddr), &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	bpf_probe_read(&tcpv6_key.saddr, sizeof(tcpv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);

	u32 zero_key = 0;
	u64 *val = bpf_map_lookup_elem(&tcpv6counter, &zero_key);
	if (val == NULL){return 0;}

	struct tcpv6_value_t tcpv6_value;
    __builtin_memset(&tcpv6_value, 0, sizeof(tcpv6_value));
	tcpv6_value.pid = pid_tgid >> 32;
	tcpv6_value.counter = *val;
	bpf_map_update_elem(&tcpv6Map, &tcpv6_key, &tcpv6_value, BPF_ANY);
	u64 newval = *val + 1;
	bpf_map_update_elem(&tcpv6counter, &zero_key, &newval, BPF_ANY);
	bpf_map_delete_elem(&tcpv6sock, &pid_tgid);
	return 0;
};


SEC("kprobe/udp_sendmsg")
int kprobe__udp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);

	struct inet_sock *inet_sk = (struct inet_sock *)sk;
	struct flowi4 fl4;
    __builtin_memset(&fl4, 0, sizeof(fl4));
	bpf_probe_read(&fl4, sizeof(fl4), &inet_sk->cork.fl.u.ip4);

	u64 msg_name; //pointer
    __builtin_memset(&msg_name, 0, sizeof(msg_name));
	bpf_probe_read(&msg_name, sizeof(msg_name), &msg->msg_name);
	struct sockaddr_in * usin = (struct sockaddr_in *)msg_name;

	struct udp_key_t udp_key;
    __builtin_memset(&udp_key, 0, sizeof(udp_key));
	bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &sk->__sk_common.skc_dport);
	if (udp_key.dport == 0){
		int one = 1;
		bpf_map_update_elem(&bytes, &one, &one, BPF_ANY);
		bpf_probe_read(&udp_key.dport, sizeof(udp_key.dport), &usin->sin_port);
		bpf_probe_read(&udp_key.daddr, sizeof(udp_key.daddr), &usin->sin_addr.s_addr);
	}
	else {
		int two = 2;
		bpf_map_update_elem(&bytes, &two, &two, BPF_ANY);
		bpf_probe_read(&udp_key.daddr, sizeof(udp_key.daddr), &sk->__sk_common.skc_daddr);
	}
	bpf_probe_read(&udp_key.sport, sizeof(udp_key.sport), &sk->__sk_common.skc_num);
	bpf_probe_read(&udp_key.saddr, sizeof(udp_key.saddr), &sk->__sk_common.skc_rcv_saddr);
	
	u32 zero_key = 0;
    __builtin_memset(&zero_key, 0, sizeof(zero_key));
	u64 *counterVal = bpf_map_lookup_elem(&udpcounter, &zero_key);
	if (counterVal == NULL){return 0;}
	struct udp_value_t *lookedupValue = bpf_map_lookup_elem(&udpMap, &udp_key);
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	if ( lookedupValue == NULL || lookedupValue->pid != pid) {
		struct udp_value_t udp_value;
        __builtin_memset(&udp_value, 0, sizeof(udp_value));
		udp_value.pid = pid;
		udp_value.counter = *counterVal;
		bpf_map_update_elem(&udpMap, &udp_key, &udp_value, BPF_ANY);
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
	u64 msg_name; //a pointer
    __builtin_memset(&msg_name, 0, sizeof(msg_name));
	bpf_probe_read(&msg_name, sizeof(msg_name), &msg->msg_name);

	struct udpv6_key_t udpv6_key;
    __builtin_memset(&udpv6_key, 0, sizeof(udpv6_key));
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
	bpf_probe_read(&udpv6_key.saddr, sizeof(udpv6_key.saddr), &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
	
	u32 zero_key = 0;
	u64 *counterVal = bpf_map_lookup_elem(&udpv6counter, &zero_key);
	if (counterVal == NULL){return 0;}
	struct udpv6_value_t *lookedupValue = bpf_map_lookup_elem(&udpv6Map, &udpv6_key);
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	if ( lookedupValue == NULL || lookedupValue->pid != pid) {

		struct udpv6_value_t udpv6_value;
        __builtin_memset(&udpv6_value, 0, sizeof(udpv6_value));
		udpv6_value.pid = pid;
		udpv6_value.counter = *counterVal;
		bpf_map_update_elem(&udpv6Map, &udpv6_key, &udpv6_value, BPF_ANY);
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



// code below only for debugging:

// we use this testprobe in order to determine the offset of inet_sk->inet_sport
// ive only seen it as 0x0e an all ubuntu kernels
// but on other systems we may need this code to dynamically determine the offset


// uncomment this section
// SEC("kprobe/tcp_v4_connect")
// int testprobe_tcp_v4_connect(struct pt_regs *ctx)
// {
//     struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
// 	u32 pid = bpf_get_current_pid_tgid();
//     bpf_map_update_elem(&tcpsock, &pid, &sk, BPF_ANY);
// 	return 0;
// };
// SEC("kretprobe/tcp_v4_connect")
// int testretprobe_tcp_v4_connect(struct pt_regs *ctx)
// {
//    	u32 pid = bpf_get_current_pid_tgid();
// 	struct sock **skp = bpf_map_lookup_elem(&tcpsock, &pid);
// 	if (skp == NULL) {
// 		return 0;}
// 	struct sock *sk = *skp;

// 	struct tcp_key_t tcp_key;
//     __builtin_memset(&tcp_key, 0, sizeof(tcp_key));

// 	bpf_probe_read(&tcp_key.dport, sizeof(tcp_key.dport), &sk->__sk_common.skc_dport);
// 	struct inet_sock *inet_sk = (struct inet_sock *)sk;

//     struct mStruct mcast_pointer;
//     __builtin_memset(&mcast_pointer, 0, sizeof(mcast_pointer));
//     bpf_probe_read(&mcast_pointer, sizeof(mcast_pointer), *(&sk));
//     bpf_map_update_elem(&mcasts, &tcp_key.sport, &mcast_pointer, BPF_ANY);

//     const offset0 = 0x0000000e;
//     const offset1 = 0x0000000f;
//     const offsetMark = 0x0B0E0E0F;
//     //use it so that it doesnt get optimized away
//     u16 ffval = 0xFFFF;
//     bpf_map_update_elem(&bytes, &offset0, &ffval, BPF_ANY);
//     bpf_map_update_elem(&bytes, &offset1, &ffval, BPF_ANY);
//     bpf_map_update_elem(&bytes, &offsetMark, &ffval, BPF_ANY);

//     u16 i;
//     u8 prevValue = 0;
//     u16 foundport;
//     __builtin_memset(&foundport, 0, sizeof(foundport));
//     bpf_probe_read(&foundport, sizeof(foundport), &inet_sk->inet_sport);
//     bpf_map_update_elem(&mcasts, &foundport, &mcast_pointer, BPF_ANY);


//     #pragma clang loop unroll(full)
//     for (i = 0; i < arraySize; i++) {
//         u8 value = mcast_pointer.myArray[i];

//         u8 port[2];
//         port[0] = value;
//         port[1] = prevValue;
//         u16 *port16 = &port;

//         if (*port16 == foundport) {
//             u32 key = 0xFFFFFFFF;
//             u16 foundvalue = i;
//             bpf_map_update_elem(&bytes, &key, &foundvalue, BPF_ANY);
//             break;
//         }
//         prevValue = value;
//     }

//     // u8 port[2] = {0,0}; don't init like this, it will be optimized away by clang
//     u8 port[2];
//     port[1] = mcast_pointer.myArray[offset0];
//     port[0] = mcast_pointer.myArray[offset1];
//     u16 *port16 = &port;
//     tcp_key.sport = *port16;
       

// 	bpf_probe_read(&tcp_key.daddr, sizeof(tcp_key.daddr), &sk->__sk_common.skc_daddr);
// 	struct tcp_value_t tcp_value;
//     __builtin_memset(&tcp_value, 0, sizeof(tcp_value));
// 	tcp_value.pid = pid;
// 	bpf_probe_read(&tcp_value.saddr, sizeof(tcp_value.saddr), &sk->__sk_common.skc_daddr);
	
// 	int zero_key = 0;
// 	u64 *val = bpf_map_lookup_elem(&tcpcounter, &zero_key);
// 	if (val == NULL){return 0;}
// 	tcp_value.counter = *val;
// 	bpf_map_update_elem(&tcpMap, &tcp_key, &tcp_value, BPF_ANY);
// 	u64 newval = *val + 1;
// 	bpf_map_update_elem(&tcpcounter, &zero_key, &newval, BPF_ANY);
// 	bpf_map_delete_elem(&tcpsock, &pid);
// 	return 0;
// }