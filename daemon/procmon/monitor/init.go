package monitor

import (
	"github.com/evilsocket/opensnitch/daemon/ebpf"
	"github.com/evilsocket/opensnitch/daemon/log"
	"github.com/evilsocket/opensnitch/daemon/procmon"
	"github.com/evilsocket/opensnitch/daemon/procmon/audit"
)

// monitor method supported types
const (
	MethodProc = "proc"
)

// Init starts parsing connections using the method specified.
func Init() {
	if procmon.MethodIsEbpf() {
		err := ebpf.Start()
		if err == nil {
			log.Info("Process monitor method ebpf")
			return
		}
		log.Warning("error starting ebpf monitor method: %v", err)

	} else if procmon.MethodIsFtrace() {
		err := procmon.Start()
		if err == nil {
			log.Info("Process monitor method ftrace")
			return
		}
		log.Warning("error starting ftrace monitor method: %v", err)

	} else if procmon.MethodIsAudit() {
		auditConn, err := audit.Start()
		if err == nil {
			log.Info("Process monitor method audit")
			go audit.Reader(auditConn, (chan<- audit.Event)(audit.EventChan))
			return
		}
		log.Warning("error starting audit monitor method: %v", err)
	}

	// if any of the above methods have failed, fallback to proc
	log.Info("Process monitor method /proc")
	procmon.SetMonitorMethod(MethodProc)
	go procmon.MonitorActivePids()
}

// End stops the way of parsing new connections.
func End() {
	if procmon.MethodIsAudit() {
		audit.Stop()
	} else if procmon.MethodIsEbpf() {
		ebpf.Stop()
	} else if procmon.MethodIsFtrace() {
		go func() {
			if err := procmon.Stop(); err != nil {
				log.Warning("procmon.End() stop ftrace error: %v", err)
			}
		}()
	}
}
