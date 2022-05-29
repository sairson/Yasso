package plugin

import (
	"Yasso/config"
	"Yasso/core/logger"
	"fmt"
	"github.com/jlaffaye/ftp"
	"net"
	"time"
)

func FtpConn(info config.ServiceConn, user, pass string) (bool, error) {
	var flag = false
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%v:%v", info.Hostname, info.Port), time.Duration(info.Timeout))

	conn, err := ftp.Dial(fmt.Sprintf("%v:%v", info.Hostname, info.Port), ftp.DialWithNetConn(c))
	if err == nil {
		err = conn.Login(user, pass)
		if err == nil {
			if pass == "" {
				logger.Success(fmt.Sprintf("ftp %v unauthorized", fmt.Sprintf("%v:%v", info.Hostname, info.Port)))
			}
			flag = true
		}
	}
	return flag, err
}
