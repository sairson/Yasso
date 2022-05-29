package plugin

import (
	"Yasso/config"
	"errors"
	"github.com/stacktitan/smb/smb"
	"time"
)

func SmbConn(info config.ServiceConn, user, pass string) (bool, error) {
	signal := make(chan struct{})
	var (
		flag bool
		err  error
	)
	go func() {
		flag, err = dialSmbTimeOut(info, user, pass, signal)
	}()
	select {
	case <-signal:
		return flag, err
	case <-time.After(1 * time.Second):
		return false, errors.New("smb conn time out")
	}
}

func dialSmbTimeOut(info config.ServiceConn, user, pass string, signal chan struct{}) (bool, error) {
	var flag = false
	options := smb.Options{
		Host:        info.Hostname,
		Port:        445,
		User:        user,
		Password:    pass,
		Domain:      info.Domain,
		Workstation: "",
	}
	session, err := smb.NewSession(options, false)
	if err == nil {
		session.Close()
		if session.IsAuthenticated {
			flag = true
		}
	}
	signal <- struct{}{}
	return flag, err
}
