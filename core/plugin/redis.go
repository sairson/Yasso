package plugin

import (
	"Yasso/config"
	"Yasso/core/logger"
	"fmt"
	"net"
	"strings"
	"time"
)

func RedisAuthConn(info config.ServiceConn, user, pass string) (net.Conn, bool, error) {
	var flag = false
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%v", info.Hostname, info.Port), info.Timeout)
	if err != nil {
		return conn, false, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.Timeout)))
	if err != nil {
		return conn, false, err
	}
	// 认证
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass)))
	if err != nil {
		return conn, false, err
	}
	reply, err := RedisReply(conn)
	if err != nil {
		return conn, false, err
	}
	if strings.Contains(reply, "+OK") {
		flag = true
		dbfilename := redisInfo(conn, reply)
		logger.Info(fmt.Sprintf("Redis %s:%v Login Success dbfilename:[%v]", info.Hostname, info.Port, dbfilename))
	}
	return conn, flag, nil
}

func RedisUnAuthConn(info config.ServiceConn, user, pass string) (net.Conn, bool, error) {
	_, _ = user, pass
	var flag = false
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%v", info.Hostname, info.Port), info.Timeout)
	if err != nil {
		return conn, false, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.Timeout)))
	if err != nil {
		return conn, false, err
	}
	_, err = conn.Write([]byte("info\r\n"))
	if err != nil {
		return conn, false, err
	}
	reply, err := RedisReply(conn)
	if err != nil {
		return conn, false, err
	}
	if strings.Contains(reply, "redis_version") {
		flag = true
		dbfilename := redisInfo(conn, reply)
		logger.Success(fmt.Sprintf("Redis %s:%v unauthorized dbfilename:[%v] ", info.Hostname, info.Port, dbfilename))
	}
	return conn, flag, nil
}

func RedisReply(conn net.Conn) (string, error) {
	var (
		r   string
		err error
	)
	buf := make([]byte, 5*1024)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		r += string(buf[0:count])
		if count < 5*1024 {
			break
		}
	}
	return r, err
}

func redisInfo(conn net.Conn, reply string) string {
	var (
		dbfilename string
	)
	// 读取filename
	_, err := conn.Write([]byte(fmt.Sprintf("CONFIG GET dbfilename\r\n")))
	if err != nil {
		return ""
	}
	text, err := RedisReply(conn)
	if err != nil {
		return ""
	}
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}
	return dbfilename
}
