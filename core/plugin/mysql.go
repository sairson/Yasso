package plugin

import (
	"Yasso/config"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"time"
)

func MySQLConn(info config.ServiceConn, user, pass string) (*sql.DB, bool, error) {
	var flag = false
	address := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", user, pass, info.Hostname, info.Port, info.Timeout)
	db, err := sql.Open("mysql", address)
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout))
		db.SetConnMaxIdleTime(time.Duration(info.Timeout))
		//defer db.Close()
		err = db.Ping()
		if err == nil {
			flag = true
		}
	}
	return db, flag, err
}
