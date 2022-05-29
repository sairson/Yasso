package plugin

import (
	"Yasso/core/logger"
	"fmt"
	"net"
	"sync"
	"time"
)

type Scanner struct {
	ports       []int
	ip          string
	scanChannel chan int
	thread      int
	scan        func(ip string, port int) bool
}

func NewRunner(ports []int, ip string, thread int, scan func(ip string, port int) bool) *Scanner {
	return &Scanner{
		ports:       ports,
		ip:          ip,
		scanChannel: make(chan int, 1000),
		thread:      thread,
		scan:        scan,
	}
}

func (s *Scanner) RunEnumeration() []int {
	var wg sync.WaitGroup
	var re []int
	for i := 0; i < s.thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range s.scanChannel {
				if s.scan(s.ip, p) {
					logger.Info(fmt.Sprintf("%v:%v is open", s.ip, p))
					re = append(re, p)
				}
			}
		}()
	}
	for _, p := range s.ports {
		s.scanChannel <- p
	}
	close(s.scanChannel)
	wg.Wait()
	return re
}

func tcpConn(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, port), 100*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

//TODO: 暂定，目前还没有syn扫描方式
func synConn(ip string, port int) bool {
	return true
}
