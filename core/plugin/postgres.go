package plugin

import (
	"Yasso/config"
	"database/sql"
	"fmt"
	"time"
)

func PostgreConn(info config.ServiceConn, user, pass string) (bool, error) {
	var flag = false
	db, err := sql.Open("postgres", fmt.Sprintf("postgres://%v:%v@%v:%v/%v?sslmode=%v", user, pass, info.Hostname, info.Port, "postgres", "disable"))
	if err == nil {
		db.SetConnMaxLifetime(time.Duration(info.Timeout))
		defer db.Close()
		err = db.Ping()
		if err == nil {
			flag = true
		}
	}
	return flag, err
}
