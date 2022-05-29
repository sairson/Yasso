package plugin

import (
	"Yasso/config"
	"Yasso/core/logger"
	"bytes"
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"net"
	"strconv"
	"time"
)

func MssqlConn(info config.ServiceConn, user, pass string) (*sql.DB, bool, error) {
	var flag = false
	db, err := sql.Open("mssql", fmt.Sprintf("sqlserver://%v:%v@%v:%v/?connection&timeout=%v&encrypt=disable", user, pass, info.Hostname, info.Port, info.Timeout))
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout))
		db.SetConnMaxIdleTime(time.Duration(info.Timeout))
		db.SetMaxIdleConns(0)
		err = db.Ping()
		if err == nil {
			flag = true
			return db, flag, nil
		}
	}
	return db, flag, err
}

func VersionMssql(info config.ServiceConn) (bool, string) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%v", info.Hostname, info.Port), info.Timeout)
	if err != nil {
		return false, ""
	}

	msg := "\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x02\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x00\x00\x31\x32"
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
	} else if hex.EncodeToString(reply[0:4]) != "04010025" {
		return false, ""
	}
	v, status := getVersion(reply)
	if status {
		logger.Info(fmt.Sprintf("%s:%v [version:%v][mssql]", info.Hostname, info.Port, v))
		return true, fmt.Sprintf("%s:%v [version:%v]", info.Hostname, info.Port, v)
	}
	return false, ""
}

func getVersion(reply []byte) (string, bool) {
	m, err := strconv.ParseUint(hex.EncodeToString(reply[29:30]), 16, 32)
	if err != nil {
		return "", false
	}
	s, err := strconv.ParseUint(hex.EncodeToString(reply[30:31]), 16, 32)
	if err != nil {
		return "", false
	}
	r, err := strconv.ParseUint(hex.EncodeToString(reply[31:33]), 16, 32)
	if err != nil {
		return "", false
	}
	v := fmt.Sprintf("%d.%d.%d", m, s, r)
	return v, true
}
