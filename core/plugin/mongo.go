package plugin

import (
	"Yasso/config"
	"Yasso/core/logger"
	"fmt"
	"gopkg.in/mgo.v2"
	"net"
	"strings"
	"time"
)

func MongoAuth(info config.ServiceConn, user, pass string) (*mgo.Session, bool, error) {

	conf := &mgo.DialInfo{
		Dial: func(addr net.Addr) (net.Conn, error) {
			return net.DialTimeout("tcp", addr.String(), info.Timeout)
		},
		Addrs:     []string{fmt.Sprintf("%s:%d", info.Hostname, info.Port)},
		Timeout:   info.Timeout,
		Database:  "test",
		Source:    "admin",
		Username:  user,
		Password:  pass,
		PoolLimit: 4096,
		Direct:    false,
	}
	db, err := mgo.DialWithInfo(conf)
	if err == nil {
		err = db.Ping()
		if err != nil {
			return nil, false, err
		}
		return db, true, nil
	}
	return nil, false, err
}

func MongoUnAuth(info config.ServiceConn, user, pass string) (bool, error) {
	var flag = false
	data1 := []byte{58, 0, 0, 0, 167, 65, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 255, 255, 255, 255, 19, 0, 0, 0, 16, 105, 115, 109, 97, 115, 116, 101, 114, 0, 1, 0, 0, 0, 0}
	data2 := []byte{72, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 1, 0, 0, 0, 33, 0, 0, 0, 2, 103, 101, 116, 76, 111, 103, 0, 16, 0, 0, 0, 115, 116, 97, 114, 116, 117, 112, 87, 97, 114, 110, 105, 110, 103, 115, 0, 0}
	connString := fmt.Sprintf("%s:%v", info.Hostname, info.Port)
	conn, err := net.DialTimeout("tcp", connString, info.Timeout)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return false, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.Timeout)))
	if err != nil {
		return false, err
	}
	_, err = conn.Write(data1)
	if err != nil {
		return false, err
	}
	reply := make([]byte, 1024)
	count, err := conn.Read(reply)
	if err != nil {
		return false, err
	}
	text := string(reply[0:count])
	if strings.Contains(text, "ismaster") {
		_, err = conn.Write(data2)
		if err != nil {
			return false, err
		}
		count, err := conn.Read(reply)
		if err != nil {
			return false, err
		}
		text := string(reply[0:count])
		if strings.Contains(text, "totalLinesWritten") {
			flag = true
			logger.Success(fmt.Sprintf("Mongodb %v unauthorized", info.Hostname))
		}
	}
	return flag, nil
}
