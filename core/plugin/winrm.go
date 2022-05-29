package plugin

import (
	"Yasso/config"
	"fmt"
	"github.com/masterzen/winrm"
	"net"
	"os"
)

func WinRMAuth(info config.ServiceConn, user, pass string) (*winrm.Client, bool, error) {
	var err error
	params := winrm.DefaultParameters
	// 设置代理认证
	params.Dial = func(network, addr string) (net.Conn, error) {
		return net.DialTimeout("tcp", fmt.Sprintf("%s:%v", info.Hostname, info.Port), info.Timeout)
	}
	// 设置输入
	endpoint := winrm.NewEndpoint("other-host", 5985, false, false, nil, nil, nil, 0)
	client, err := winrm.NewClientWithParameters(endpoint, user, pass, params)
	stdout := os.Stdout
	res, err := client.Run("echo ISOK > nul", stdout, os.Stderr)
	if err != nil {
		return nil, false, err
	}
	if res == 0 && err == nil {
		return client, true, nil
	}
	return nil, false, err
}
