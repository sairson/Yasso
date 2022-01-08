package cmd

import (
	"Yasso/config"
	"context"
	"database/sql"
	"fmt"
	_ "github.com/denisenkom/go-mssqldb"
	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	"net"
	"time"
)

var MysqlCmd = &cobra.Command{
	Use:   "mysql",
	Short: "MYSQL burst module and extend tools (support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" && ConnHost == "" {
			_ = cmd.Help()
		} else {
			BruteMysqlByUser()
		}
	},
}

func BruteMysqlByUser() {
	if BrutePort == 0 {
		BrutePort = 3306
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
			users, pass := ReadTextToDic("mysql", UserDic, PassDic)
			Println(Clearln + "[*] Brute Module [mysql]")
			Println(fmt.Sprintf(Clearln+"[*] Have [user:%v] [pass:%v] [request:%v]", len(users), len(pass), len(users)*len(pass)*len(ips)))
			SwitchBurp("mysql", users, pass, ips, BrutePort, Runtime, TimeDuration, "")
		} else {
			Println(Clearln + "[*] May be you want to brute? try to add --crack")
		}
	}
	if Hosts == "" && ConnHost != "" {
		if SQLCommand == "" && SQLShellBool == false {
			Println("[*] try to add -C to exec sql command or -shell")
			return
		}
		if SQLCommand != "" && SQLShellBool == false {
			db, status, err := MySQLConn(config.HostIn{Host: ConnHost, Port: BrutePort, TimeOut: TimeDuration}, LoginUser, LoginPass)
			if err != nil {
				Println("mysql conn failed")
				return
			}
			if status == true {
				r, err := SQLExecute(db, SQLCommand)
				if err != nil {
					Println(fmt.Sprintf("sql execute failed %v", err))
					return
				}
				Println(r.String())
			}
		}
		if SQLCommand == "" && SQLShellBool == true {
			db, status, err := MySQLConn(config.HostIn{Host: ConnHost, Port: BrutePort, TimeOut: TimeDuration}, LoginUser, LoginPass)
			if err != nil {
				Println("mysql conn failed")
				return
			}
			if status == true {
				SQLshell(db, "mysql")
			}
		}
	}
}

func init() {
	MysqlCmd.Flags().StringVarP(&SQLCommand, "cmd", "c", "", "mysql sql command")
	MysqlCmd.Flags().StringVar(&ConnHost, "hostname", "", "Remote Connect a Mysql (brute param need false)")
	MysqlCmd.Flags().StringVar(&LoginUser, "user", "", "Login ssh username")
	MysqlCmd.Flags().StringVar(&LoginPass, "pass", "", "Login ssh password")
	MysqlCmd.Flags().BoolVar(&SQLShellBool, "shell", false, "create sql shell to exec sql command")
}

// mysql 连接

func MySQLConn(info config.HostIn, user, pass string) (*sql.DB, bool, error) {
	var flag = false
	address := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", user, pass, info.Host, info.Port, time.Duration(info.TimeOut))

	mysql.RegisterDialContext("tcp", func(ctx context.Context, network string) (net.Conn, error) {
		return GetConn(network, info.TimeOut)
	})

	db, err := sql.Open("mysql", address)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.TimeOut))
		db.SetConnMaxIdleTime(time.Duration(info.TimeOut))
		//defer db.Close()
		err = db.Ping()
		if err == nil {
			flag = true
		}
	}
	return db, flag, err
}
