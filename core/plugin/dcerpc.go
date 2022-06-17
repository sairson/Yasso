package plugin

import (
	"Yasso/core/logger"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const v1 = "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x08\x83\xaf\xe1\x1f\x5d\xc9\x11\x91\xa4\x08\x00\x2b\x14\xa0\xfa\x03\x00\x00\x00\x33\x05\x71\x71\xba\xbe\x37\x49\x83\x19\xb5\xdb\xef\x9c\xcc\x36\x01\x00\x00\x00"

const dce = "\x05\x00\x0b\x03\x10\x00\x00\x00\x78\x00\x28\x00\x03\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x01\x00\xa0\x01\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60\x02\x00\x00\x00\x0a\x02\x00\x00\x00\x00\x00\x00\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x01\xb1\x1d\x00\x00\x00\x0f"

var length = 0

func DceRpcOSVersion(ip string, port int, timeout time.Duration) (bool, string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, port), timeout)
	if err != nil {
		return false, ""
	}
	_, err = conn.Write([]byte(dce))
	if err != nil {
		return false, ""
	}
	var buffer = make([]byte, 4096)
	_, err = conn.Read(buffer)
	if err != nil {
		return false, ""
	}
	digit := osDigits(ip) // 获取位数
	osVersionBytes := buffer[int(0xa0)-54+10 : int(0xa0)-54+18]
	majorVersion := osVersionBytes[0:1] // 主要版本
	MinorVersion := osVersionBytes[1:2] // 次要版本
	BuildNumber := osVersionBytes[2:4]  // 构建号
	osVersion := fmt.Sprintf("Windows Verison %d.%d Build %v %v", majorVersion[0], MinorVersion[0], binary.LittleEndian.Uint16(BuildNumber), digit)

	//infoLengthBytes := buffer[int(0xa0)-54+2 : int(0xa0)-54+4]
	//infoLength := int(binary.LittleEndian.Uint16(infoLengthBytes))
	//infoBytes := buffer[n-infoLength : n-4]
	//netBoisDomainName := attribute(infoBytes)
	//dnsDomainName := attribute(infoBytes)
	//dnsComputerName := attribute(infoBytes)
	//dnsTreeName := attribute(infoBytes)
	logger.Success(fmt.Sprintf("%v:%v %v", ip, port, osVersion))
	//logger.Info(fmt.Sprintf("NetBios (%v) DomainName (%v) ComputerName (%v)", netBoisDomainName, dnsDomainName, dnsComputerName))
	return true, osVersion
}

func osDigits(ip string) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", ip, 135), time.Second*5)
	if err != nil {
		return ""
	}
	conn.Write([]byte(v1))
	var buffer = make([]byte, 1024)
	conn.Read(buffer)
	var digits = "x86"
	if bytes.Contains(buffer, []byte("\x33\x05\x71\x71\xBA\xBE\x37\x49\x83\x19\xB5\xDB\xEF\x9C\xCC\x36")) {
		digits = "x64"
	}
	return digits
}

func attribute(info []byte) string {
	nameLength := int(binary.LittleEndian.Uint16(info[length+2 : length+4]))
	name := bytes.Replace(info[length+4:length+4+nameLength], []byte("\x00"), []byte(""), -1)
	length = length + 4 + nameLength
	return string(name)
}
