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

//contains pointers to ebpf maps (also called tables) for a given protocol (tcp/udp/v6)
type ebpfMapsForProto struct {
	counterMap    *elf.Map
	bpfmap        *elf.Map
	bpfmapFd      uint64 // ebpf map file descriptor
	lastPurgedMax uint64 // max counter value up to and including which the map was purged on the last purge
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
	m                       *elf.Module
	mapSize                 = 25000
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
		"tcp": {lastPurgedMax: 0,
			counterMap: m.Map("tcpcounter"),
			bpfmap:     m.Map("tcpMap"),
			bpfmapFd:   uint64(m.Map("tcpMap").Fd())},
		"tcp6": {lastPurgedMax: 0,
			counterMap: m.Map("tcpv6counter"),
			bpfmap:     m.Map("tcpv6Map"),
			bpfmapFd:   uint64(m.Map("tcpv6Map").Fd())},
		"udp": {lastPurgedMax: 0,
			counterMap: m.Map("udpcounter"),
			bpfmap:     m.Map("udpMap"),
			bpfmapFd:   uint64(m.Map("udpMap").Fd())},
		"udp6": {lastPurgedMax: 0,
			counterMap: m.Map("udpv6counter"),
			bpfmap:     m.Map("udpv6Map"),
			bpfmapFd:   uint64(m.Map("udpv6Map").Fd())},
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

	go monitorMaps()
	go monitorLocalAddresses()
	go monitorAlreadyEstablished()
	return nil
}

func Stop() {
	stop = true
	m.Close()
}

// delete all elements whose counter value is <=  maxToDelete
func deleteElements(bpfmap *elf.Map, isIPv6 bool, maxToDelete uint64) {
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
	fmt.Println("start deleting map", maxToDelete)
	i := 0
	for {
		i++
		if i > 25000 {
			// TODO find out what causes the endless loop
			// maybe because bpf prog modified map while le were iterating
			fmt.Println("breaking because endless loop was detected")
			break
		}
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
		// last 8 bytes of value is counter value
		counterValue := binary.LittleEndian.Uint64(value[8:16])
		fmt.Println("got counter", counterValue)
		if counterValue > maxToDelete {
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
func monitorMaps() {
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
			fmt.Println("counterValuem, ebpfMap.lastPurgedMax", counterValue, ebpfMap.lastPurgedMax)
			if counterValue-ebpfMap.lastPurgedMax > 20000 {
				ebpfMap.lastPurgedMax = counterValue - 10000
				deleteElements(ebpfMap.bpfmap, name == "tcp6" || name == "udp6", ebpfMap.lastPurgedMax)
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

	bpf_lookup.map_fd = ebpfMaps[proto].bpfmapFd
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

// maintains a list of this machine's local addresses
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
	fmt.Println("tcpoddfd is", ebpfMaps["tcp"].bpfmapFd)
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
