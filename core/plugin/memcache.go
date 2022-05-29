package plugin

import (
	"Yasso/config"
	"Yasso/core/logger"
	"bytes"
	"fmt"
	"net"
	"time"
)

func MemcacheConn(info config.ServiceConn, user, pass string) (bool, error) {
	client, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%v", info.Hostname, info.Port), info.Timeout)
	if err != nil {
		return false, err
	}
	defer func() {
		if client != nil {
			client.Close()
		}
	}()
	if err == nil {
		err = client.SetDeadline(time.Now().Add(time.Duration(info.Timeout)))
		if err == nil {
			_, err = client.Write([]byte("stats\n")) //Set the key randomly to prevent the key on the server from being overwritten
			if err == nil {
				reply := make([]byte, 1024)
				n, err := client.Read(reply)
				if err == nil {
					if bytes.Contains(reply[:n], []byte("STAT")) {
						logger.Success(fmt.Sprintf("Memcached %s unauthorized", fmt.Sprintf("%s:%v", info.Hostname, info.Port)))
						return true, nil
					}
				}
			}
		}
	}
	return false, err
}
