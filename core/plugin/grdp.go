package plugin

import (
	"Yasso/config"
	"Yasso/core/logger"
	"Yasso/pkg/grdp"
	"Yasso/pkg/grdp/glog"
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
)

func RdpConn(info config.ServiceConn, user, pass string) (bool, error) {
	var err error
	var host = fmt.Sprintf("%v:%v", info.Hostname, info.Port)
	g := grdp.NewClient(host, glog.NONE)
	//SSL协议登录测试
	err = g.LoginForSSL(info.Domain, user, pass)
	if err == nil {
		return true, nil
	}
	if err.Error() != "PROTOCOL_RDP" {
		return false, err
	}
	//RDP协议登录测试
	err = g.LoginForRDP(info.Domain, user, pass)
	if err == nil {
		return true, nil
	} else {
		return false, nil
	}
}

func VersionRdp(info config.ServiceConn, user, pass string) (bool, string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", info.Hostname, info.Port), info.Timeout)
	if err != nil {
		return false, ""
	}
	msg := "\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00\x43\x6f\x6f\x6b\x69\x65\x3a\x20\x6d\x73\x74\x73\x68\x61\x73\x68\x3d\x75\x73\x65\x72\x30\x0d\x0a\x01\x00\x08\x00\x00\x00\x00\x00"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return false, ""
	}
	reply := make([]byte, 256)
	_, _ = conn.Read(reply)
	if conn != nil {
		_ = conn.Close()
	}

	var buffer [256]byte
	if bytes.Equal(reply[:], buffer[:]) {
		return false, ""
	} else if hex.EncodeToString(reply[0:8]) != "030000130ed00000" {
		return false, ""
	}

	os := map[string]string{}
	os["030000130ed000001234000209080000000000"] = "Windows 7/Windows Server 2008 R2"
	os["030000130ed000001234000200080000000000"] = "Windows 7/Windows Server 2008"
	os["030000130ed000001234000201080000000000"] = "Windows Server 2008 R2"
	os["030000130ed000001234000207080000000000"] = "Windows 8/Windows server 2012"
	os["030000130ed00000123400020f080000000000"] = "Windows 8.1/Windows Server 2012 R2"
	os["030000130ed000001234000300080001000000"] = "Windows 10/Windows Server 2016"
	os["030000130ed000001234000300080005000000"] = "Windows 10/Windows 11/Windows Server 2019"
	var banner string
	for k, v := range os {
		if k == hex.EncodeToString(reply[0:19]) {
			banner = v
			logger.Info(fmt.Sprintf("%v [%v]", fmt.Sprintf("%v:%v", info.Hostname, info.Port), banner))
			return true, fmt.Sprintf("%v [%v]", fmt.Sprintf("%v:%v", info.Hostname, info.Port), banner)
		}
	}
	banner = hex.EncodeToString(reply[0:19])
	_ = reply
	logger.Info(fmt.Sprintf("%v [%v]", fmt.Sprintf("%v:%v", info.Hostname, info.Port), banner))
	return true, fmt.Sprintf("%v [%v]", fmt.Sprintf("%v:%v", info.Hostname, info.Port), banner)
}
