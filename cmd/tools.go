package cmd

import (
	"bufio"
	"bytes"
	"database/sql"
	"fmt"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/net/proxy"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// socks5代理连接功能

func ConnBySOCKS5() (proxy.Dialer, error) {
	// 解析连接过来的socks5字符串
	if strings.ContainsAny(ProxyHost, "@") && strings.Count(ProxyHost, "@") == 1 {
		info := strings.Split(ProxyHost, "@")
		userpass := strings.Split(info[0], ":")
		auth := proxy.Auth{User: userpass[0], Password: userpass[1]}
		dialer, err := proxy.SOCKS5("tcp", info[1], &auth, proxy.Direct)
		return dialer, err
	} else {
		if strings.ContainsAny(ProxyHost, ":") && strings.Count(ProxyHost, ":") == 1 {
			dialer, err := proxy.SOCKS5("tcp", ProxyHost, nil, proxy.Direct)
			return dialer, err
		}
	}
	return nil, fmt.Errorf("proxy error")
}

// 返回一个连接

func GetConn(addr string, timeout time.Duration) (net.Conn, error) {
	if ProxyHost != "" {
		dialer, err := ConnBySOCKS5()
		if err != nil {
			return nil, err
		}
		conn, err := dialer.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		return conn, nil
	} else {
		return net.DialTimeout("tcp", addr, time.Duration(timeout))
	}
}

func SQLExecute(db *sql.DB, q string) (*Results, error) {
	if q == "" {
		return nil, nil
	}
	rows, err := db.Query(q)
	//rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var results [][]string
	for rows.Next() {
		rs := make([]sql.NullString, len(columns))
		rsp := make([]interface{}, len(columns))
		for i := range rs {
			rsp[i] = &rs[i]
		}
		if err = rows.Scan(rsp...); err != nil {
			break
		}

		_rs := make([]string, len(columns))
		for i := range rs {
			_rs[i] = rs[i].String
		}
		results = append(results, _rs)
	}
	if closeErr := rows.Close(); closeErr != nil {
		return nil, closeErr
	}
	if err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &Results{
		Columns: columns,
		Rows:    results,
	}, nil
}

type Results struct {
	Columns []string
	Rows    [][]string
}

func (r *Results) String() string {
	buf := bytes.NewBufferString("")
	table := tablewriter.NewWriter(buf)
	table.SetHeader(r.Columns)
	table.AppendBulk(r.Rows)
	table.Render()
	return buf.String()
}

func SQLshell(db *sql.DB, sqltype string) {
	reader := bufio.NewReader(os.Stdin)
	Println(fmt.Sprintf("Welcome to Yasso sql client "))
	for {
		fmt.Printf("Yasso-%s> ", sqltype)
		sqlstr, err := reader.ReadString('\n')
		if err != nil {
			log.Panic("failed to ReadString ", err)
		}
		sqlstr = strings.Trim(sqlstr, "\r\n")
		sqls := []byte(sqlstr)
		if len(sqls) > 6 {
			if string(sqls[:6]) == "select" || string(sqls[:4]) == "show" || string(sqls[:4]) == "desc" {
				//result set sql
				r, err := SQLExecute(db, sqlstr)
				if err != nil {
					Println(fmt.Sprintf("%v", err))
				}
				Println(fmt.Sprintf("%v", r))
			} else {
				//no result set sql
				r, err := SQLExecute(db, sqlstr)
				if err != nil {
					Println(fmt.Sprintf("%v", err))
				}
				Println(fmt.Sprintf("%v", r))
			}
		}
		if sqlstr == "exit" {
			Println("exit sql shell")
			break
		}
	}
}
