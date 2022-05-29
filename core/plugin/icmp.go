package plugin

import (
	"bytes"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func ping(ip string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
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
