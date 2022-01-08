package cmd

import (
	"Yasso/config"
	"bytes"
	"fmt"
)

func ZookeeperConn(info config.HostIn) (bool, error) {
	payload := []byte("envidddfdsfsafafaerwrwerqwe")
	conn, err := GetConn(fmt.Sprintf("%s:%v", info.Host, info.Port), info.TimeOut)
	if err != nil {
		return false, err
	}
	_, err = conn.Write(payload)
	if err == nil {
		reply := make([]byte, 1024)
		n, err := conn.Read(reply)
		if err == nil {
			if bytes.Contains(reply[:n], []byte("Environment")) {
				Println(fmt.Sprintf("[+] zookeeper %s unauthorized", fmt.Sprintf("%v:%v", info.Host, info.Port)))
				return true, nil
			}
		}
	}
	return false, err
}
