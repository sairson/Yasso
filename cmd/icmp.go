package cmd

import (
	"bytes"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"github.com/spf13/cobra"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	OS    = runtime.GOOS // 系统架构
	Alive []string       // 存活的ip列表
)
var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Use ping to scanner alive host (not support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		var ips []string
		if Hosts == "" {
			_ = cmd.Help()
			return
		}
		if Hosts != "" {
			ips, _ = ResolveIPS(Hosts) // resolve ip to []string ips
		} else {
			Println("Yasso scanner need a hosts")
			return
		}
		Println(fmt.Sprintf("[Yasso] will ping %d host", len(ips)))
		_ = execute(ips, RunICMP)
	},
}

func init() {
	pingCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "Set `hosts`(The format is similar to Nmap)")
	pingCmd.Flags().BoolVarP(&RunICMP, "icmp", "i", false, "Icmp packets are sent to check whether the host is alive(need root)")
	rootCmd.AddCommand(pingCmd)
}

func execute(ips []string, r bool) []string {
	var wg sync.WaitGroup
	// 修改ants池的并发方式
	p, _ := ants.NewPoolWithFunc(len(ips), func(ip interface{}) {
		var ipt string
		if r == true {
			// 127.0.0.1:8080格式
			if strings.Contains(ip.(string), ":") {
				ipt = strings.Split(ip.(string), ":")[0]
			} else {
				ipt = ip.(string)
			}
			if icmp(ipt) {
				Println(fmt.Sprintf("[+] Find %v (icmp)", ip))
				Alive = append(Alive, ip.(string))
			}
		} else {
			if strings.Contains(ip.(string), ":") {
				ipt = strings.Split(ip.(string), ":")[0]
			} else {
				ipt = ip.(string)
			}
			if ping(ipt) {
				Println(fmt.Sprintf("[+] Find %v (ping)", ip))
				Alive = append(Alive, ip.(string))
			}
		}
		wg.Done()
	})
	for _, ip := range ips {
		wg.Add(1)
		_ = p.Invoke(ip)
	}
	wg.Wait()
	return Alive
}

func ping(ip string) bool {
	var cmd *exec.Cmd
	switch OS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false")
	case "linux":
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" >/dev/null && echo true || echo false")
	case "darwin":
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1 "+ip+" >/dev/null && echo true || echo false")
	default:
		cmd = exec.Command("/bin/bash", "-c", "ping -c 1"+ip+" >/dev/null && echo true || echo false")
	}
	info := bytes.Buffer{}
	cmd.Stdout = &info
	err := cmd.Start()
	if err != nil {
		return false
	}
	if err = cmd.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(info.String(), "true") {
			return true
		} else {
			return false
		}
	}
}

func icmp(host string) bool {
	conn, err := net.DialTimeout("ip4:icmp", host, 1*time.Second)
	if err != nil {
		return false
	}
	defer func() {
		_ = conn.Close()
	}()
	if err := conn.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return false
	}
	msg := packet(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}
	var receive = make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}
	return true
}

func packet(host string) []byte {
	var msg = make([]byte, 40)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = host[0], host[1]
	msg[6], msg[7] = byte(1>>8), byte(1&255)
	msg[2] = byte(checksum(msg[0:40]) >> 8)
	msg[3] = byte(checksum(msg[0:40]) & 255)
	return msg
}

func checksum(msg []byte) uint16 {
	var sum = 0
	var length = len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	return uint16(^sum)
}
