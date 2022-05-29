package plugin

import (
	"Yasso/config"
	"Yasso/core/logger"
	"Yasso/core/utils"
	"bytes"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

func SshConnByUser(info config.ServiceConn, user, pass string) (*ssh.Client, bool, error) {
	sshConfig := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(pass)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: info.Timeout}
	con, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", info.Hostname, info.Port), info.Timeout)
	if err != nil {
		return nil, false, err
	}
	c, ch, re, err := ssh.NewClientConn(con, fmt.Sprintf("%v:%v", info.Hostname, info.Port), sshConfig)
	if err != nil {
		return nil, false, err
	}
	return ssh.NewClient(c, ch, re), true, err
}

func SshConnByKey(info config.ServiceConn, user string) (*ssh.Client, bool, error) {
	var (
		err      error
		HomePath string
		key      []byte
	)
	switch {
	case info.PublicKey == "":
		HomePath, err = os.UserHomeDir()
		if err != nil {
			return nil, false, err
		}
		key, err = ioutil.ReadFile(path.Join(HomePath, ".ssh", "id_rsa"))
		if err != nil {
			return nil, false, err
		}
	case info.PublicKey != "":
		key, err = ioutil.ReadFile(info.PublicKey)
		if err != nil {
			return nil, false, err
		}
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, false, err
	}
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		Timeout:         info.Timeout,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	con, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", info.Hostname, info.Port), info.Timeout)
	if err != nil {
		return nil, false, err
	}

	c, ch, re, err := ssh.NewClientConn(con, fmt.Sprintf("%v:%v", info.Hostname, info.Port), sshConfig)
	if err != nil {
		return nil, false, err
	}
	return ssh.NewClient(c, ch, re), true, err
}

func VersionSSH(info config.ServiceConn) string {
	buff, err := sshConn(info)
	if err != nil {
		logger.Fatal(fmt.Sprintf("%s ssh conn has an error", info.Hostname))
		return ""
	}
	ok, _ := regexp.Match(`^SSH.\d`, buff)
	str := utils.ByteToStringParse(buff)
	if ok {
		logger.Info(fmt.Sprintf("%s:%v [%v]", info.Hostname, info.Port, strings.Split(str, "\\x0d\\x0a")[0]))
		return fmt.Sprintf("%s:%v [%v]", info.Hostname, info.Port, strings.Split(str, "\\x0d\\x0a")[0])
	}
	return ""
}

// sshConn 连接到tcp
func sshConn(info config.ServiceConn) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", info.Hostname, info.Port), time.Duration(info.Timeout))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	reply := make([]byte, 256)
	_, err = conn.Read(reply)

	var buffer [256]byte
	if err == nil && bytes.Equal(reply[:], buffer[:]) == false {
		if conn != nil {
			_ = conn.Close()
		}
		return reply, nil
	}
	conn, err = net.DialTimeout("tcp", fmt.Sprintf("%v:%v", info.Hostname, info.Port), time.Duration(info.Timeout))
	if err != nil {
		return nil, err
	}
	msg := "GET /test HTTP/1.1\r\n\r\n"
	_, err = conn.Write([]byte(msg))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(time.Duration(2) * time.Second))
	reply = make([]byte, 256)
	_, _ = conn.Read(reply)
	if conn != nil {
		_ = conn.Close()
	}
	return reply, nil
}
