package cmd

import (
	"Yasso/config"
	"bytes"
	"fmt"
	"time"
)

// 未授权

func MemcacheConn(info config.HostIn) (bool, error) {
	client, err := GetConn(fmt.Sprintf("%s:%v", info.Host, info.Port), info.TimeOut)
	if err != nil {
		return false, err
	}
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err == nil {
		err = client.SetDeadline(time.Now().Add(time.Duration(info.TimeOut)))
		if err == nil {
			_, err = client.Write([]byte("stats\n")) //Set the key randomly to prevent the key on the server from being overwritten
			if err == nil {
				reply := make([]byte, 1024)
				n, err := client.Read(reply)
				if err == nil {
					if bytes.Contains(reply[:n], []byte("STAT")) {
						Println(fmt.Sprintf("[+] Memcached %s unauthorized", fmt.Sprintf("%s:%v", info.Host, info.Port)))
						return true, nil
					}
				}
			}
		}
	}
	return false, err
}
