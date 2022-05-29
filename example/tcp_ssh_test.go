package example

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TcpProtocol(host string, port int, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", host, port), time.Duration(timeout))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	reply := make([]byte, 256)
	_, err = conn.Read(reply)

	var buffer [256]byte
	if err == nil && bytes.Equal(reply[:], buffer[:]) == false {
		if conn != nil {
			_ = conn.Close()
		}
		return reply, nil
	}
	conn, err = net.DialTimeout("tcp", fmt.Sprintf("%v:%v", host, port), time.Duration(timeout))
	if err != nil {
		return nil, err
	}
	msg := "GET /test HTTP/1.1\r\n\r\n"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	reply = make([]byte, 256)
	_, _ = conn.Read(reply)
	if conn != nil {
		_ = conn.Close()
	}
	return reply, nil
}
func ByteToStringParse1(p []byte) string {
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
func Test1(test *testing.T) {
	buff, err := TcpProtocol("192.168.248.203", 22, 1*time.Second)
	if err != nil {
		fmt.Println(err)
	}
	ok, _ := regexp.Match(`^SSH.\d`, buff)
	str := ByteToStringParse1(buff)
	fmt.Println(ok, str)
	if ok {
		fmt.Println(strings.Split(str, "\\x0d\\x0a")[0])
	}
}
