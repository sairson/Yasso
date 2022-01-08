package cmd

import (
	"Yasso/config"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/stacktitan/smb/smb"
	"time"
)

/*
模块完成时间2021年12月28日，主要用于smb爆破，扫描445端口,似乎不能走socks5代理
*/

var SmbCmd = &cobra.Command{
	Use:   "smb",
	Short: "Smb burst module (not support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" {
			_ = cmd.Help()
		} else {
			BruteSmbByUser()
		}
	},
}

func BruteSmbByUser() {
	if BrutePort == 0 {
		BrutePort = 445
	}
	var ips []string
	var err error
	if Hosts != "" {
		ips, err = ResolveIPS(Hosts)
		if err != nil {
			Println(fmt.Sprintf("resolve hosts address failed %v", err))
			return
		}
		if BruteFlag == true {
			users, pass := ReadTextToDic("smb", UserDic, PassDic)
			Println(Clearln + "[*] Brute Module [smb]")
			Println(fmt.Sprintf(Clearln+"[*] Have [user:%v] [pass:%v] [request:%v]", len(users), len(pass), len(users)*len(pass)*len(ips)))
			SwitchBurp("smb", users, pass, ips, BrutePort, Runtime, TimeDuration, "")
		} else {
			Println(Clearln + "[*] May be you want to brute? try to add --crack")
		}
	}
}

func SmbConn(info config.HostIn, user, pass string) (bool, error) {
	signal := make(chan struct{})
	var (
		flag bool
		err  error
	)
	go func() {
		flag, err = DialSmbTimeOut(info, user, pass, signal)
	}()
	select {
	case <-signal:
		return flag, err
	case <-time.After(1 * time.Second):
		return false, errors.New("smb conn time out")
	}
}

func DialSmbTimeOut(info config.HostIn, user, pass string, signal chan struct{}) (bool, error) {
	var flag = false
	options := smb.Options{
		Host:        info.Host,
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
