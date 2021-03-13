package ebpf

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/vishvananda/netlink"

	daemonNetlink "github.com/evilsocket/opensnitch/daemon/netlink"
	elf "github.com/iovisor/gobpf/elf"
)

//contains pointers to ebpf maps for a given protocol (tcp/udp/v6)
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

var (
	m        *elf.Module
	mapSize  = 12000
	ebpfMaps map[string]*ebpfMapsForProto
	//connections which were established at the time when opensnitch started
	alreadyEstablishedTCP   = make(map[*daemonNetlink.Socket]int)
	alreadyEstablishedTCPv6 = make(map[*daemonNetlink.Socket]int)
	//stop will be set to true when all goroutines should stop
	stop              = false
	bpf_lookup_elem   bpf_lookup_elem_t
	bpf_lookup_elemv6 bpf_lookup_elem_t
	// keys/values for looking up bpf maps
	bpfLookupKey     = make([]byte, 12)
	bpfLookupKeyv6   = make([]byte, 36)
	bpfLookupValue   = make([]byte, 12)
	bpfLookupValuev6 = make([]byte, 12)
	// list of local addresses of this machine
	localAddresses     []net.IP
	localAddressesLock sync.RWMutex
)

// returns a random string
func randString() string {
	rand.Seed(time.Now().UnixNano())
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

//Start installs ebpf kprobes
func Start() error {
	m = elf.NewModule("opensnitch.o")
	if err := m.Load(nil); err != nil {
		log.Error("m.Load", err)
		return err
	}

	// if previous opensnitch was shut down uncleanly, the kprobe will not be enabled
	// we have to close and load the module again
	if err := m.EnableKprobes(0); err != nil {
		m.Close()
		if err := m.Load(nil); err != nil {
			log.Error("m.Load", err)
			return err
		}
		if err := m.EnableKprobes(0); err != nil {
			fmt.Println("m.EnableKprobes", err)
			return err
		}
	}

	// init all counters to 0
	zeroKey := make([]byte, 4)
	zeroValue := make([]byte, 8)
	for _, name := range []string{"tcpcounter", "tcpv6counter", "udpcounter", "udpv6counter", "debugcounter"} {
		err := m.UpdateElement(m.Map(name), unsafe.Pointer(&zeroKey[0]), unsafe.Pointer(&zeroValue[0]), 0)
		if err != nil {
			return err
		}
	}

	// prepare struct for bpf() syscall
	bpf_lookup_elem.key = uintptr(unsafe.Pointer(&bpfLookupKey[0]))
	bpf_lookup_elem.value = uintptr(unsafe.Pointer(&bpfLookupValue[0]))
	bpf_lookup_elemv6.key = uintptr(unsafe.Pointer(&bpfLookupKeyv6[0]))
	bpf_lookup_elemv6.value = uintptr(unsafe.Pointer(&bpfLookupValuev6[0]))

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
		return err
	}
	for _, sock := range socketListTCP {
		inode := int((*sock).INode)
		pid := procmon.GetPIDFromINode(inode, fmt.Sprint(inode,
			(*sock).ID.Source, (*sock).ID.SourcePort, (*sock).ID.Destination, (*sock).ID.DestinationPort))
		alreadyEstablishedTCP[sock] = pid
	}

	socketListTCPv6, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET6), uint8(syscall.IPPROTO_TCP))
	if err != nil {
		return err
	}
	for _, sock := range socketListTCPv6 {
		inode := int((*sock).INode)
		pid := procmon.GetPIDFromINode(inode, fmt.Sprint(inode,
			(*sock).ID.Source, (*sock).ID.SourcePort, (*sock).ID.Destination, (*sock).ID.DestinationPort))
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

// delete all map's elements whose counter value is <= maxToDelete
func deleteOld(bpfmap *elf.Map, isIPv6 bool, maxToDelete uint64) {
	var lookupKey []byte
	var nextKey []byte
	var value []byte
	if !isIPv6 {
		lookupKey = make([]byte, 12)
		nextKey = make([]byte, 12)
		value = make([]byte, 12)
	} else {
		lookupKey = make([]byte, 36)
		nextKey = make([]byte, 36)
		value = make([]byte, 12)
	}
	firstrun := true
	log.Debug("start deleting old", maxToDelete)
	i := 0
	for {
		i++
		if i > 12000 {
			// TODO find out what causes the endless loop
			// maybe because bpf prog modified the map while we were iterating
			log.Error("breaking because endless loop was detected in deleteOld")
			break
		}
		ok, err := m.LookupNextElement(bpfmap, unsafe.Pointer(&lookupKey[0]),
			unsafe.Pointer(&nextKey[0]), unsafe.Pointer(&value[0]))
		if err != nil {
			log.Error("LookupNextElement error", err)
			return
		}
		if firstrun {
			// on first run lookupKey is a dummy, nothing to delete
			firstrun = false
			copy(lookupKey, nextKey)
			continue
		}
		// last 8 bytes of value is counter value
		counterValue := binary.LittleEndian.Uint64(value[4:12])
		if counterValue > maxToDelete {
			copy(lookupKey, nextKey)
			continue
		}
		if err := m.DeleteElement(bpfmap, unsafe.Pointer(&lookupKey[0])); err != nil {
			log.Error("DeleteElement error", err)
			return
		}
		if !ok { //reached end of map
			break
		}
		copy(lookupKey, nextKey)
	}
	log.Debug("finished deleting old")
}

// we need to manually remove old connections from a bpf map
// since a full bpf map doesnt allow any insertions
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
				log.Error("m.LookupElement", err)
			}
			counterValue := binary.LittleEndian.Uint64(value)
			//fmt.Println("counterValue, ebpfMap.lastPurgedMax", counterValue, ebpfMap.lastPurgedMax)
			if counterValue-ebpfMap.lastPurgedMax > 10000 {
				ebpfMap.lastPurgedMax = counterValue - 5000
				deleteOld(ebpfMap.bpfmap, name == "tcp6" || name == "udp6", ebpfMap.lastPurgedMax)
			}
		}
	}
}

//GetPid looks up a connection in bpf map and returns PID if found
// the lookup keys and values are defined in opensnitch.c , e.g.
//
// struct tcp_key_t {
// 	u16 sport;
// 	u32 daddr;
// 	u16 dport;
//  u32 saddr;
// }__attribute__((packed));

// struct tcp_value_t{
// 	u32 pid;
// 	u64 counter; //counters in value are for debug purposes only
// }__attribute__((packed));;

func GetPid(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) int {
	var key *[]byte
	var bpf_lookup *bpf_lookup_elem_t
	var isIP4 bool = (proto == "tcp") || (proto == "udp") || (proto == "udplite")

	if isIP4 {
		key = &bpfLookupKey
		bpf_lookup = &bpf_lookup_elem
		copy((*key)[2:6], dstIP)
		binary.BigEndian.PutUint16((*key)[6:8], uint16(dstPort))
		copy((*key)[8:12], srcIP)
	} else { // IPv6
		key = &bpfLookupKeyv6
		bpf_lookup = &bpf_lookup_elemv6
		copy((*key)[2:18], dstIP)
		binary.BigEndian.PutUint16((*key)[18:20], uint16(dstPort))
		copy((*key)[20:36], srcIP)
	}
	if proto == "tcp" || proto == "tcp6" {
		binary.BigEndian.PutUint16((*key)[0:2], uint16(srcPort))
	} else { // non-TCP
		binary.LittleEndian.PutUint16((*key)[0:2], uint16(srcPort))
	}
	bpf_lookup.map_fd = ebpfMaps[proto].bpfmapFd
	r := makeBpfSyscall(bpf_lookup)
	if r != 0 {
		//maybe srcIP is 0.0.0.0 Happens especially with UDP sendto()
		//TODO: can this happen with TCP?
		if isIP4 {
			zeroes := make([]byte, 4)
			copy((*key)[8:12], zeroes)
		} else {
			zeroes := make([]byte, 16)
			copy((*key)[20:36], zeroes)
		}
		r = makeBpfSyscall(bpf_lookup)
	}
	if r != 0 && proto == "udp" && srcIP.String() == "127.0.0.1" && dstIP.String() == "127.0.0.1" {
		fmt.Println("need investigation srcIP.String() == 127.0.0.1 ")
		fmt.Println()
		for {
			time.Sleep(time.Second)
		}
		os.Exit(1)
		//very rarely I see this connection. It has dstIP == 0.0.0.0 in ebpf map
		//I could not reproduce it
		copy((*key)[2:6], make([]byte, 4))
		r = makeBpfSyscall(bpf_lookup)
	}
	if r != 0 {
		// key not found in bpf map
		fmt.Println("key not found", *key)
		return -1
	}
	pid := int(binary.LittleEndian.Uint32(bpfLookupValue[0:4]))
	return pid
}

//make bpf() syscall with bpf_lookup prepared by the caller
func makeBpfSyscall(bpf_lookup *bpf_lookup_elem_t) uintptr {
	BPF_MAP_LOOKUP_ELEM := 1 //cmd number
	syscall_BPF := 321       //syscall number
	sizeOfStruct := 24       //sizeof bpf_lookup_elem_t struct

	r1, _, _ := syscall.Syscall(uintptr(syscall_BPF), uintptr(BPF_MAP_LOOKUP_ELEM),
		uintptr(unsafe.Pointer(bpf_lookup)), uintptr(sizeOfStruct))
	return r1
}

// FindInAlreadyEstablishedTCP searches those TCP connections which were already established at the time
// when opensnitch started
func FindInAlreadyEstablishedTCP(proto string, srcPort uint, srcIP net.IP, dstIP net.IP, dstPort uint) (int, error) {
	var alreadyEstablished map[*daemonNetlink.Socket]int
	if proto == "tcp" {
		alreadyEstablished = alreadyEstablishedTCP
	} else if proto == "tcp6" {
		alreadyEstablished = alreadyEstablishedTCPv6
	}
	for sock, v := range alreadyEstablished {
		if (*sock).ID.SourcePort == uint16(srcPort) && (*sock).ID.Source.Equal(srcIP) &&
			(*sock).ID.Destination.Equal(dstIP) && (*sock).ID.DestinationPort == uint16(dstPort) {
			return v, nil
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
			log.Error("error in netlink.AddrList", err)
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

// monitorAlreadyEstablished makes sure that when the connection is closed it will be removed from
// alreadyEstablished. If we don't do this and keep the alreadyEstablished entry forever,
// a malicious process may obtain the same PID and local port after the genuine process quits
// and will be able to send packets to the same destination.
func monitorAlreadyEstablished() {
	for {
		time.Sleep(time.Second * 1)
		if stop {
			return
		}
		socketListTCP, err := daemonNetlink.SocketsDump(uint8(syscall.AF_INET), uint8(syscall.IPPROTO_TCP))
		if err != nil {
			log.Error("error in SocketsDump")
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

//PrintEverything prints all the stats. used only for debugging
func PrintEverything(suffix string) {
	bash, _ := exec.LookPath("bash")
	fmt.Println("tcpoddfd is", ebpfMaps["tcp"].bpfmapFd)
	cmd := exec.Command(bash, "-c", "bpftool map dump name tcpMap > tcpmap"+suffix)
	if err := cmd.Run(); err != nil {
		fmt.Println("bpftool map dump name tcpMap ", err)
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
