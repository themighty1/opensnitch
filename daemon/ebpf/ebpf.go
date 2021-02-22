package ebpf

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/vishvananda/netlink"

	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	elf "github.com/iovisor/gobpf/elf"
)

//Our goal is to parse each new connection as quickly as possible
//that's why we don't use BPF_PERF_OUTPUT but maintain the maps inside ebpf.
//With BPF_PERF_OUTPUT processing time is ~50us whereas with the current method it is ~20us.

//a key/value map size must be indicated in advance when ebpf program starts. Normally as map grows full, we'd want
//to delete older entries from it. However, deleting one entry at a time is an expensive operation in ebpf, in
//contrast to deleting all entries of a map - which is cheap.
//That's why we employ 2 maps: odd and even map. The odd map holds the first 5000 unique entries and the even map
//holds the second 5000 unique entries for each 10000 entries.

//Workflow in ebpf. (check ebpf_prog/opensnitch.c)
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

//contains pointers to all ebpf maps (also called tables) for a given protocol (tcp/udp/v6)
type ebpfMapsForProto struct {
	sync.Mutex
	counterMap          *elf.Map
	mapEven             *elf.Map
	mapOdd              *elf.Map
	mapOddFd, mapEvenFd uint64 //ebpf map file descriptor
	isOddInUse          bool
	waitingToPurgeOdd   bool
	waitingToPurgeEven  bool
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
	m       *elf.Module
	mapSize = 50000
	// mapCacheSize is the size of the cache we build to make a smooth
	// switch from odd<->even maps
	mapCacheSize            = 10000
	ebpfMaps                map[string]*ebpfMapsForProto
	alreadyEstablishedTCP   = make(map[*daemonNetlink.Socket]int)
	alreadyEstablishedTCPv6 = make(map[*daemonNetlink.Socket]int)
	stop                    = false
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
	m = elf.NewModule("opensnitch.o")
	if err := m.Load(nil); err != nil {
		panic(err)
	}

	for _, name := range []string{
		"kprobe/tcp_v4_connect",
		"kretprobe/tcp_v4_connect",
		"kprobe/tcp_v6_connect",
		"kretprobe/tcp_v6_connect",
		"kprobe/udp_sendmsg",
		"kprobe/udpv6_sendmsg"} {
		err := m.EnableKprobe(name, 0)
		if err != nil {
			fmt.Println(name)
			m.Close()
			panic(err)
		}
	}

	// init counters to 0
	zeroKey := make([]byte, 4)
	zeroValue := make([]byte, 8)
	for _, name := range []string{"tcpcounter", "tcpv6counter", "udpcounter", "udpv6counter"} {
		err := m.UpdateElement(m.Map(name), unsafe.Pointer(&zeroKey[0]), unsafe.Pointer(&zeroValue[0]), 0)
		if err != nil {
			panic(err)
		}
	}

	// prepare struct for bpf() syscall
	bpf_lookup_elem.key = uintptr(unsafe.Pointer(&lookupKey[0]))
	bpf_lookup_elem.value = uintptr(unsafe.Pointer(&lookupValue))
	bpf_lookup_elemv6.key = uintptr(unsafe.Pointer(&lookupKeyv6[0]))
	bpf_lookup_elemv6.value = uintptr(unsafe.Pointer(&lookupValuev6))

	ebpfMaps = map[string]*ebpfMapsForProto{
		"tcp": {isOddInUse: true, waitingToPurgeOdd: false, waitingToPurgeEven: true,
			counterMap: m.Map("tcpcounter"),
			mapOdd:     m.Map("tcpMapOdd"),
			mapEven:    m.Map("tcpMapEven"),
			mapOddFd:   uint64(m.Map("tcpMapOdd").Fd()),
			mapEvenFd:  uint64(m.Map("tcpMapEven").Fd())},
		"tcp6": {isOddInUse: true, waitingToPurgeOdd: false, waitingToPurgeEven: true,
			counterMap: m.Map("tcpv6counter"),
			mapOdd:     m.Map("tcpv6MapOdd"),
			mapEven:    m.Map("tcpv6MapEven"),
			mapOddFd:   uint64(m.Map("tcpv6MapOdd").Fd()),
			mapEvenFd:  uint64(m.Map("tcpv6MapEven").Fd())},
		"udp": {isOddInUse: true, waitingToPurgeOdd: false, waitingToPurgeEven: true,
			counterMap: m.Map("udpcounter"),
			mapOdd:     m.Map("udpMapOdd"),
			mapEven:    m.Map("udpMapEven"),
			mapOddFd:   uint64(m.Map("udpMapOdd").Fd()),
			mapEvenFd:  uint64(m.Map("udpMapEven").Fd())},
		"udp6": {isOddInUse: true, waitingToPurgeOdd: false, waitingToPurgeEven: true,
			counterMap: m.Map("udpv6counter"),
			mapOdd:     m.Map("udpv6MapOdd"),
			mapEven:    m.Map("udpv6MapEven"),
			mapOddFd:   uint64(m.Map("udpv6MapOdd").Fd()),
			mapEvenFd:  uint64(m.Map("udpv6MapEven").Fd())},
	}

	// save already established connections
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
	go monitorAlreadyEstablished()
	return nil
}

func Stop() {
	stop = true
	m.Close()
}

// delete all elements in a map
func deleteAllElements(bpfmap *elf.Map, isIPv6 bool) {
	var lookupKey []byte
	var nextKey []byte
	var value []byte
	if !isIPv6 {
		lookupKey = make([]byte, 8)
		nextKey = make([]byte, 8)
		value = make([]byte, 16)
	} else {
		lookupKey = make([]byte, 20)
		nextKey = make([]byte, 20)
		value = make([]byte, 28)
	}
	firstrun := true
	fmt.Println("start deleting map")
	for {
		ok, err := m.LookupNextElement(bpfmap, unsafe.Pointer(&lookupKey[0]),
			unsafe.Pointer(&nextKey[0]), unsafe.Pointer(&value[0]))
		if err != nil {
			fmt.Println("LookupNextElement error", err)
			os.Exit(1)
		}
		if firstrun {
			// on first run lookupKey is a dummy, nothing to delete
			firstrun = false
			copy(lookupKey, nextKey)
			continue
		}
		if err := m.DeleteElement(bpfmap, unsafe.Pointer(&lookupKey[0])); err != nil {
			fmt.Println("DeleteElement error", err)
			os.Exit(1)
		}
		if !ok { //reached end of map
			break
		}
		copy(lookupKey, nextKey)
	}
	fmt.Println("finished deleting map")
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
		for name, ebpfMap := range ebpfMaps {
			value := make([]byte, 8)
			if err := m.LookupElement(ebpfMap.counterMap,
				unsafe.Pointer(&zeroKey[0]), unsafe.Pointer(&value[0])); err != nil {
				fmt.Println("elfmod.LookupElement(elftcpcounter, ", err)
			}
			counterValue := binary.LittleEndian.Uint64(value)
			modulo := counterValue % uint64(mapSize*2)

			if !ebpfMap.isOddInUse && modulo < uint64(mapSize) {
				ebpfMap.Lock()
				ebpfMap.isOddInUse = true
				ebpfMap.waitingToPurgeEven = true
				ebpfMap.Unlock()
			}
			if ebpfMap.waitingToPurgeEven && modulo >= uint64(mapCacheSize) {
				deleteAllElements(ebpfMap.mapEven, name == "tcp6" || name == "udp6")
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
			if ebpfMap.waitingToPurgeOdd && modulo >= uint64(mapSize+mapCacheSize) {
				deleteAllElements(ebpfMap.mapOdd, name == "tcp6" || name == "udp6")
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
		bpf_lookup.map_fd = ebpfMap.mapOddFd
	} else {
		bpf_lookup.map_fd = ebpfMap.mapEvenFd
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
		if stop {
			return
		}
	}
}

func monitorAlreadyEstablished() {
	for {
		time.Sleep(time.Second * 1)
		if stop {
			return
		}
		socketListTCP, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET), uint8(syscall.IPPROTO_TCP))
		if err != nil {
			fmt.Println("error in SocketsDump")
			continue
		}
		for aesock := range alreadyEstablishedTCP {
			found := false
			for _, sock := range socketListTCP {
				if (*aesock).INode == (*sock).INode &&
					//inodes are unique enough, so the matches below will never have to be checked
					(*aesock).ID.SourcePort == (*sock).ID.SourcePort &&
					(*aesock).ID.Source.Equal((*sock).ID.Source) &&
					(*aesock).ID.Destination.Equal((*sock).ID.Destination) &&
					(*aesock).ID.DestinationPort == (*sock).ID.DestinationPort &&
					(*aesock).UID == (*sock).UID {
					found = true
					break
				}
			}
			if !found {
				delete(alreadyEstablishedTCP, aesock)
			}
		}

		socketListTCPv6, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET6), uint8(syscall.IPPROTO_TCP))
		if err != nil {
			fmt.Println("error in SocketsDump")
			continue
		}
		for aesock := range alreadyEstablishedTCPv6 {
			found := false
			for _, sock := range socketListTCPv6 {
				if (*aesock).INode == (*sock).INode &&
					//inodes are unique enough, so the matches below will never have to be checked
					(*aesock).ID.SourcePort == (*sock).ID.SourcePort &&
					(*aesock).ID.Source.Equal((*sock).ID.Source) &&
					(*aesock).ID.Destination.Equal((*sock).ID.Destination) &&
					(*aesock).ID.DestinationPort == (*sock).ID.DestinationPort &&
					(*aesock).UID == (*sock).UID {
					found = true
					break
				}
			}
			if !found {
				delete(alreadyEstablishedTCPv6, aesock)
			}
		}
	}
}

//PrintEverything prints all the stats
func PrintEverything(suffix string) {
	bash, _ := exec.LookPath("bash")
	fmt.Println("tcpoddfd is", ebpfMaps["tcp"].mapOddFd)
	cmd := exec.Command(bash, "-c", "bpftool map dump name tcpMapOdd > mapoddHi"+suffix)
	if err := cmd.Run(); err != nil {
		fmt.Println("bpftool map dump name tcpMapOdd ", err)
	}

	bash, _ = exec.LookPath("bash")
	cmd = exec.Command(bash, "-c", "bpftool map dump name tcpMapEven > mapEvenHi"+suffix)
	if err := cmd.Run(); err != nil {
		fmt.Println("bpftool map dump name tcpMapEven", err)
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
