package plugin

import (
	"Yasso/config"
	"Yasso/core/logger"
	"bytes"
	"fmt"
	"net"
)

func ZookeeperConn(info config.ServiceConn, user, pass string) (bool, error) {
	payload := []byte("envidddfdsfsafafaerwrwerqwe")
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%v", info.Hostname, info.Port), info.Timeout)
	if err != nil {
		return false, err
	}
	_, err = conn.Write(payload)
	if err == nil {
		reply := make([]byte, 1024)
		n, err := conn.Read(reply)
		if err == nil {
			if bytes.Contains(reply[:n], []byte("Environment")) {
				logger.Success(fmt.Sprintf("zookeeper %s unauthorized", fmt.Sprintf("%v:%v", info.Hostname, info.Port)))
				return true, nil
			}
		}
	}
	return false, err
}
