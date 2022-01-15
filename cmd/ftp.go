package cmd

import (
	"Yasso/config"
	"fmt"
	"github.com/jlaffaye/ftp"
	"github.com/spf13/cobra"
	"time"
)

var FtpCmd = &cobra.Command{
	Use:   "ftp",
	Short: "ftp burst module (support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" {
			_ = cmd.Help()
		} else {
			BruteFtpByUser()
		}
	},
}

func BruteFtpByUser() {
	if BrutePort == 0 {
		BrutePort = 21
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
			users, pass := ReadTextToDic("ftp", UserDic, PassDic)
			Println(Clearln + "[*] Brute Module [ftp]")
			Println(fmt.Sprintf(Clearln+"[*] Have [user:%v] [pass:%v] [request:%v]", len(users), len(pass), len(users)*len(pass)*len(ips)))
			SwitchBurp("ftp", users, pass, ips, BrutePort, Runtime, TimeDuration, "")
		} else {
			Println(Clearln + "[*] May be you want to brute? try to add --crack")
		}
	}
}

func FtpConn(info config.HostIn, user, pass string) (bool, error) {
	var flag = false
	c, err := GetConn(fmt.Sprintf("%v:%v", info.Host, info.Port), time.Duration(info.TimeOut))

	conn, err := ftp.Dial(fmt.Sprintf("%v:%v", info.Host, info.Port), ftp.DialWithNetConn(c))
	if err == nil {
		err = conn.Login(user, pass)
		if err == nil {
			if pass == "" {
				Println(fmt.Sprintf("ftp %v unauthorized", fmt.Sprintf("%v:%v", info.Host, info.Port)))
			}
			flag = true
		}
	}
	return flag, err
}
