package icmp

import (
	"github.com/go-ping/ping"
	"runtime"
	"time"
)

func Check(ip string) bool {
	pinger, err := ping.NewPinger(ip)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		pinger.SetPrivileged(true)
	}
	pinger.Count = 1
	pinger.Timeout = 100 * time.Millisecond
	err = pinger.Run()
	if err != nil {
		return false
	}
	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 {
		return true
	}
	return false
}
