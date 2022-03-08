package cmd

import (
	"Yasso/config"
	"fmt"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"os"
	"path"
)

/*
模块完成时间2021年12月28日，主要用于ssh爆破，连接，扫描22端口
*/

var SshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "SSH burst and SSH extend tools (support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" && ConnHost == "" {
			_ = cmd.Help()
		} else {
			BruteSshByUser()
		}
	},
}

func init() {
	SshCmd.Flags().StringVar(&ConnHost, "hostname", "", "Open an interactive SSH at that address(brute param need false)")
	SshCmd.Flags().StringVar(&LoginUser, "user", "", "Login ssh username")
	SshCmd.Flags().StringVar(&LoginPass, "pass", "", "Login ssh password")
	SshCmd.Flags().StringVar(&LoginPublicKey, "key", "", "ssh public key path")
}

func BruteSshByUser() {
	if BrutePort == 0 {
		BrutePort = 22
	}
	var ips []string
	var err error
	if Hosts != "" && ConnHost == "" {
		ips, err = ResolveIPS(Hosts)
		if err != nil {
			Println(fmt.Sprintf("resolve hosts address failed %v", err))
			return
		}
		if BruteFlag == true {
			users, pass := ReadTextToDic("ssh", UserDic, PassDic)
			//fmt.Println(users, pass)
			Println(Clearln + "[*] Brute Module [ssh]")
			Println(fmt.Sprintf(Clearln+"[*] Have [user:%v] [pass:%v] [request:%v]", len(users), len(pass), len(users)*len(pass)*len(ips)))
			SwitchBurp("ssh", users, pass, ips, BrutePort, Runtime, TimeDuration, "")
		} else {
			Println(Clearln + "[*] May be you want to brute? try to add --crack")
		}
	}
	if ConnHost != "" && Hosts == "" && (LoginUser != "" && (LoginPass != "" || LoginPublicKey != "")) && BruteFlag != true {
		if LoginUser != "" && LoginPass != "" {
			client, status, err := SshConnByUser(config.HostIn{Host: ConnHost, Port: BrutePort, TimeOut: TimeDuration}, LoginUser, LoginPass)
			if err != nil {
				Println(fmt.Sprintf(Clearln+"[-] Login ssh failed %v", err))
				return
			}
			if status == true {
				//认证成功
				SshLogin(client)
			} else {
				Println(Clearln + "[-] The username or password is incorrect")
				return
			}
		}
		if LoginPublicKey != "" && LoginUser != "" {
			client, status, err := sshConnByKey(config.HostIn{Host: ConnHost, Port: BrutePort, TimeOut: TimeDuration, PublicKey: LoginPublicKey}, LoginUser)
			if err != nil {
				Println(fmt.Sprintf(Clearln+"[-] Login ssh failed %v", err))
				return
			}
			if status == true {
				//认证成功
				SshLogin(client)
				return
			} else {
				Println(Clearln + "[-] The username or password is incorrect")
				return
			}
		}
	}
	if Hosts == "" && ConnHost != "" && BruteFlag == false && (LoginUser == "" || LoginPublicKey == "") {
		Println(Clearln + "[*] May be you want login ssh? try to add user and (user' key) or (user' pass)")
		return
	}
}

func SshConnByUser(info config.HostIn, user, pass string) (*ssh.Client, bool, error) {
	// 走socks5代理的ssh连接
	sshConfig := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(pass)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: info.TimeOut}
	con, err := GetConn(fmt.Sprintf("%v:%v", info.Host, info.Port), info.TimeOut)
	if err != nil {
		return nil, false, err
	}
	c, ch, re, err := ssh.NewClientConn(con, fmt.Sprintf("%v:%v", info.Host, info.Port), sshConfig)
	if err != nil {
		return nil, false, err
	}
	return ssh.NewClient(c, ch, re), true, err
}

func sshConnByKey(info config.HostIn, user string) (*ssh.Client, bool, error) {
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
		Timeout:         info.TimeOut,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	con, err := GetConn(fmt.Sprintf("%v:%v", info.Host, info.Port), info.TimeOut)
	if err != nil {
		return nil, false, err
	}

	c, ch, re, err := ssh.NewClientConn(con, fmt.Sprintf("%v:%v", info.Host, info.Port), sshConfig)
	if err != nil {
		return nil, false, err
	}
	return ssh.NewClient(c, ch, re), true, err
}

// ssh 完全交互式登陆

func SshLogin(client *ssh.Client) {
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		Println(fmt.Sprintf("new ssh session failed %v", err))
		return
	}
	defer session.Close()
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
		ssh.VSTATUS:       1,
	}
	fd := int(os.Stdin.Fd())
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		Println(fmt.Sprintf("terminal failed %v", err))
	}
	defer terminal.Restore(fd, oldState)
	w, h, err := terminal.GetSize(fd)
	if err = session.RequestPty("xterm-256color", h, w, modes); err != nil {
		Println(fmt.Sprintf("Session Request new xterm failed %v", err))
		return
	}
	if err = session.Shell(); err != nil {
		Println(fmt.Sprintf("Session start shell failed %v", err))
		return
	}
	if err = session.Wait(); err != nil {
		Println(fmt.Sprintf("Session wait failed %v", err))
		return
	}
}
