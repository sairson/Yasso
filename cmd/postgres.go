package cmd

import (
	"Yasso/config"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	"time"
)

var PostgreCmd = &cobra.Command{
	Use:   "postgres",
	Short: "PostgreSQL burst module (not support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" {
			_ = cmd.Help()
		} else {
			BrutePostgreByUser()
		}
	},
}

func BrutePostgreByUser() {
	if BrutePort == 0 {
		BrutePort = 5432
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
			users, pass := ReadTextToDic("postgres", UserDic, PassDic)
			Println(Clearln + "[*] Brute Module [postgres]")
			Println(fmt.Sprintf(Clearln+"[*] Have [user:%v] [pass:%v] [request:%v]", len(users), len(pass), len(users)*len(pass)*len(ips)))
			SwitchBurp("postgres", users, pass, ips, BrutePort, Runtime, TimeDuration, "")
		} else {
			Println(Clearln + "[*] May be you want to brute? try to add --crack")
		}
	}
}

func PostgreConn(info config.HostIn, user, pass string) (bool, error) {
	var flag = false
	db, err := sql.Open("postgres", fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", user, pass, info.Host, info.Port, "postgres", "disable"))
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.TimeOut))
		defer db.Close()
		err = db.Ping()
		if err == nil {
			flag = true
		}
	}
	return flag, err
}
