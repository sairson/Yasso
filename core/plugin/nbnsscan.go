package plugin

import (
	"Yasso/core/logger"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func NbnsScanConn(host string, port int, timeout time.Duration) (bool, string) {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%v:%v", host, port), timeout)
	if err != nil {
		return false, ""
	}
	msg := []byte{
		0x0, 0x00, 0x0, 0x10, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x20, 0x43, 0x4b, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x0, 0x0,
		0x21, 0x0, 0x1,
	}
	_, err = conn.Write(msg)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return false, ""
	}
	reply := make([]byte, 256)
	err = conn.SetDeadline(time.Now().Add(time.Duration(timeout)))
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return false, ""
	}
	_, _ = conn.Read(reply)
	if conn != nil {
		_ = conn.Close()
	}

	var buffer [256]byte
	if bytes.Equal(reply[:], buffer[:]) {
		return false, ""
	}
	/*
		Re: https://en.wikipedia.org/wiki/NetBIOS#NetBIOS_Suffixes
		For unique names:
			00: Workstation Service (workstation name)
			03: Windows Messenger service
			06: Remote Access Service
			20: File Service (also called Host Record)
			21: Remote Access Service client
			1B: Domain Master Browser – Primary Domain Controller for a domain
			1D: Master Browser
		For group names:
			00: Workstation Service (workgroup/domain name)
			1C: Domain Controllers for a domain (group record with up to 25 IP addresses)
			1E: Browser Service Elections
	*/
	var n int
	NumberFoNames, _ := strconv.Atoi(convert([]byte{reply[56:57][0]}[:]))
	var flagGroup string
	var flagUnique string
	var flagDC string

	for i := 0; i < NumberFoNames; i++ {
		data := reply[n+57+18*i : n+57+18*i+18]
		if string(data[16:17]) == "\x84" || string(data[16:17]) == "\xC4" {
			if string(data[15:16]) == "\x1C" {
				flagDC = "Domain Controllers"
			}
			if string(data[15:16]) == "\x00" {
				flagGroup = nbnsByteToStringParse(data[0:16])
			}
			if string(data[14:16]) == "\x02\x01" {
				flagGroup = nbnsByteToStringParse(data[0:16])
			}
		} else if string(data[16:17]) == "\x04" || string(data[16:17]) == "\x44" || string(data[16:17]) == "\x64" {
			if string(data[15:16]) == "\x1C" {
				flagDC = "Domain Controllers"
			}
			if string(data[15:16]) == "\x00" {
				flagUnique = nbnsByteToStringParse(data[0:16])
			}
			if string(data[15:16]) == "\x20" {
				flagUnique = nbnsByteToStringParse(data[0:16])
			}

		}
	}
	if flagGroup == "" && flagUnique == "" {
		return false, ""
	}

	result := make(map[string]interface{})
	result["banner.string"] = flagGroup + "\\" + flagUnique
	result["identify.string"] = fmt.Sprintf("[%s]", logger.LightRed(flagDC))
	if len(flagDC) != 0 {
		result["identify.bool"] = true
	} else {
		result["identify.bool"] = false
	}
	if result["identify.bool"] == true {
		logger.Success(fmt.Sprintf("[%s] %v %v", fmt.Sprintf("%v:%v", host, port), result["banner.string"], result["identify.string"]))
	} else {
		logger.Success(fmt.Sprintf("[%s] %v", fmt.Sprintf("%v:%v", host, port), result["banner.string"]))
	}

	return true, fmt.Sprintf("%v", result["banner.string"])
}

func convert(b []byte) string {
	s := make([]string, len(b))
	for i := range b {
		s[i] = strconv.Itoa(int(b[i]))
	}
	return strings.Join(s, "")
}

func nbnsByteToStringParse(p []byte) string {
	var w []string
	var res string
	for i := 0; i < len(p); i++ {
		if p[i] > 32 && p[i] < 127 {
			w = append(w, string(p[i]))
			continue
		}
	}
	res = strings.Join(w, "")
	return res
}
