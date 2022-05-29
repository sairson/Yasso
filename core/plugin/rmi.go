package plugin

import (
	"Yasso/config"
	"Yasso/core/logger"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// RMIConn 识别rmi服务方式
func RMIConn(info config.ServiceConn, user, pass string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", info.Hostname, info.Port), info.Timeout)
	if err != nil {
		return false
	}
	msg := "\x4a\x52\x4d\x49\x00\x02\x4b"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return false
	}
	reply := make([]byte, 256)
	_, _ = conn.Read(reply)
	if conn != nil {
		_ = conn.Close()
	}
	var buffer [256]byte
	if bytes.Equal(reply[:], buffer[:]) {
		return false
	} else if hex.EncodeToString(reply[0:1]) != "4e" {
		return false
	}
	// 这里解析出字符串
	banner := byteToString(reply)
	logger.Success(fmt.Sprintf("%v [%v]", fmt.Sprintf("%v:%v", info.Hostname, info.Port), banner))
	return true
}

func byteToString(p []byte) string {
	var w []string
	var res string
	for i := 0; i < len(p); i++ {
		if p[i] > 32 && p[i] < 127 {
			w = append(w, string(p[i]))
			continue
		}
		asciiTo16 := fmt.Sprintf("\\x%s", hex.EncodeToString(p[i:i+1]))
		w = append(w, asciiTo16)
	}
	res = strings.Join(w, "")
	if strings.Contains(res, "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00") {
		s := strings.Split(res, "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00")
		return s[0]
	}
	return res
}
