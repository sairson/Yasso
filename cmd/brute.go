package cmd

import (
	"Yasso/config"
	"bufio"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"github.com/projectdiscovery/cdncheck"
	"github.com/spf13/cobra"
	"log"
	"math"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

// 爆破模块

var BruteCmd = &cobra.Command{
	Use:   "crack",
	Short: "crack module and extend tool",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.DisableFlagsInUseLine = true
		_ = cmd.Help()
	},
}

func init() {
	// 添加全局变量
	BruteCmd.PersistentFlags().StringVarP(&Hosts, "hosts", "H", "", "to crack hosts address or ips.txt path (crack Must)")
	BruteCmd.PersistentFlags().IntVar(&BrutePort, "port", 0, "to crack hosts port (if not set use default)")
	BruteCmd.PersistentFlags().IntVar(&Runtime, "runtime", 100, "set crack thread number")
	BruteCmd.PersistentFlags().BoolVarP(&BruteFlag, "crack", "", false, "make sure to use crack")
	BruteCmd.PersistentFlags().DurationVar(&TimeDuration, "timeout", 1*time.Second, "crack module timeout(.eg) 1s (ns,ms,s,m,h)")
	BruteCmd.PersistentFlags().StringVar(&PassDic, "pd", "", "pass dic path (.eg) pass.txt")
	BruteCmd.PersistentFlags().StringVar(&UserDic, "ud", "", "user dic path (.eg) user.txt")
	BruteCmd.PersistentFlags().StringVar(&ProxyHost, "proxy", "", "set socks5 proxy address")
	BruteCmd.AddCommand(SshCmd)
	BruteCmd.AddCommand(WinRMCmd)
	BruteCmd.AddCommand(SmbCmd)
	BruteCmd.AddCommand(Log4jCmd)
	BruteCmd.AddCommand(RedisCmd)
	BruteCmd.AddCommand(RdpCmd)
	BruteCmd.AddCommand(MysqlCmd)
	BruteCmd.AddCommand(MssqlCmd)
	BruteCmd.AddCommand(FtpCmd)
	BruteCmd.AddCommand(PostgreCmd)
	BruteCmd.AddCommand(MongoCmd)
	rootCmd.AddCommand(BruteCmd)
}

var BurpModule = map[string]interface{}{
	"ssh":       SshConnByUser,
	"mysql":     MySQLConn,
	"mssql":     MssqlConn,
	"redis":     RedisAuthConn,
	"unredis":   RedisUnAuthConn, // redis 未授权
	"postgres":  PostgreConn,
	"smb":       SmbConn,
	"ftp":       FtpConn,
	"rdp":       RdpConn,
	"winrm":     WinRMAuth,
	"mongodb":   MongoAuth,
	"unmongodb": MongoUnAuth, // mongodb 未授权
}

func BurpCall(EncryptMap map[string]interface{}, name string, params ...interface{}) []reflect.Value {
	f := reflect.ValueOf(EncryptMap[name]) // 获取map键位name的值
	if len(params) != f.Type().NumIn() {   // 如果参数的值不等于函数所需要的值
		log.Println(fmt.Sprintf("[ERROR] Burp Call Func key name %s is failed", name))
		os.Exit(1)
	}
	args := make([]reflect.Value, len(params))
	for k, param := range params {
		if param == "" || param == 0 {
			continue
		}
		//Println()(param)
		args[k] = reflect.ValueOf(param)
	}
	//Println()(args)
	//fmt.Println(args)
	return f.Call(args) // 调用函数并返回结果
}

func SwitchBurp(service string, users []string, pass []string, hosts []string, port int, thread int, timeout time.Duration, Domain string) {
	// 传入的参数均为3个
	// 调用方式
	var tunnel = make(chan string, 20)
	var wg sync.WaitGroup
	go func() {
		for _, ip := range hosts {
			tunnel <- ip
		}
	}()
	for i := 0; i < len(hosts); i++ {
		wg.Add(1)
		_ = ants.Submit(func() {
			ip := <-tunnel
			burpTask(ip, service, users, pass, port, thread, timeout, Domain, true, false, nil)
			wg.Done()
		})
	}
	wg.Wait()
	Println(fmt.Sprintf("[*] brute %s done", service))

	//Println()(service,users,pass,hosts,port,thread,BurpModule)
}

/***
* 从新计算爆破方式，之前的爆破是采用分割user进行的，但是发现，user数量会远少于password，所以按照password进行分割
 */

func burpTask(host, service string, users []string, pass []string, port int, thread int, timeout time.Duration, Domain string, run bool, jsonbool bool, out *JsonOut) {
	var t int
	var wg sync.WaitGroup
	if len(pass) <= thread {
		t = len(pass)
	} else {
		// 计算user数量
		t = thread // 协程数量
	}

	num := int(math.Ceil(float64(len(pass)) / float64(thread))) // 每个协程的user数量
	// 分割用户名
	all := map[int][]string{}
	for i := 1; i <= t; i++ {
		for j := 0; j < num; j++ {
			tmp := (i-1)*num + j
			if tmp < len(pass) {
				all[i] = append(all[i], pass[tmp])
			}
		}
	}
	if service == "redis" && run == true {
		BurpCall(BurpModule, "unredis", config.HostIn{Host: host, Port: BrutePort, TimeOut: TimeDuration}, "test", "test")
	}
	if service == "mongodb" && run == true {
		BurpCall(BurpModule, "unmongodb", config.HostIn{Host: host, Port: BrutePort, TimeOut: TimeDuration}, "test", "test")
	}
	//Println()(all,num,t)
	for i := 1; i <= t; i++ {
		wg.Add(1)
		tmp := all[i]
		_ = ants.Submit(func() {
			for _, p := range tmp {
				for _, u := range users {
					if strings.Contains(p, "{user}") {
						p = strings.ReplaceAll(p, "{user}", p)
					}
					if u == "" || p == "" {
						continue
					} else {
						result := BurpCall(BurpModule, service, config.HostIn{Host: host, Port: port, TimeOut: time.Duration(timeout), Domain: Domain}, u, p)
						burpStatus(result, service, host, Domain, u, p, jsonbool, out)
					}
				}
			}
			wg.Done()
		})
	}
	wg.Wait()
}

func burpStatus(result []reflect.Value, service, host, domain, user, pass string, jsonbool bool, out *JsonOut) {
	var lock sync.Mutex
	// 这里是判断类型并返回结果的函数
	if len(result) > 0 {
		for _, v := range result {
			switch v.Kind() {
			case reflect.Bool:
				if v.Bool() == true {
					if domain != "" {
						domain = domain + "\\"
					}
					if jsonbool == true {
						// 加锁
						lock.Lock()
						out.WeakPass = append(out.WeakPass, map[string]map[string]string{service: {user: pass}})
						lock.Unlock()
					}
					Println(fmt.Sprintf(`[+] %s brute %s success [%v%s:%s]`, host, service, domain, user, pass))
				}
			}
		}
	}
}

func Readiness(file *os.File) []string {
	var readiness []string /*定义一个空切片用于存储遍历后的数据*/
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			readiness = append(readiness, text)
		}
	}
	readiness = SplitUrlToIpList(readiness, 100)
	return readiness
}

func ReadTextToDic(service, user, pass string) ([]string, []string) {
	var (
		userdic = config.Userdict[service]
		passdic = config.Passwords
	)
	// 如果不包含.txt的话，按照用户名和密码来算。其中
	if user != "" && !strings.Contains(user, ".txt") {
		userdic = strings.Split(user, ",")
	}
	if pass != "" && !strings.Contains(pass, ".txt") {
		passdic = strings.Split(pass, ",")
	}

	if user != "" && strings.Contains(user, ".txt") {
		userive, err := os.Open(user)
		if err != nil {
			Println(fmt.Sprintf("[ERROR] Open %s is failed,please check your user dic path", UserDic))
			return []string{}, []string{}
		}
		userdic = Readiness(userive)
	}
	if pass != "" && strings.Contains(pass, ".txt") {
		passive, err := os.Open(pass)
		if err != nil {
			Println(fmt.Sprintf("[ERROR] Open %s is failed,please check your pass dic path", PassDic))
			return []string{}, []string{}
		}
		passdic = Readiness(passive)
	}
	return userdic, passdic
}

func SplitUrlToIpList(list []string, thread int) []string {
	cdnClient, err := cdncheck.NewWithCache()
	if err != nil {
		Println(fmt.Sprintf("[ERROR] new cdn cache has an error %v", err))
	}
	checkChan := make(chan string, 100)
	var wg sync.WaitGroup
	var re []string
	for i := 0; i < thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range checkChan {
				ip, err := net.LookupHost(host)
				if err != nil {
					continue
				}
				if ip != nil {
					for _, i := range ip {
						re = append(re, i)
						Println(fmt.Sprintf("[*] %v:%v", host, ip))
					}
				}
			}
		}()
	}
	// 判断前缀，将其添加到需要解析的列表当中
	for _, domain := range list {
		if strings.Contains(domain, "http://") {
			domain = strings.TrimPrefix(domain, "http://")
		}
		if strings.Contains(domain, "https://") {
			domain = strings.TrimPrefix(domain, "https://")
		}
		checkChan <- domain
	}
	close(checkChan)
	wg.Wait()
	re = remove(re) // 移除重复结果
	// 移除cdn结果
	var resp []string
	for _, ip := range re {
		success := cdnFilter(ip, cdnClient)
		if success != "" && !strings.Contains(ip, ":") {
			resp = append(resp, success)
		} else {
			Println(fmt.Sprintf("[*] %s has cdn", ip))
		}
	}
	return resp
}

// cdn 过滤器
func cdnFilter(ip string, client *cdncheck.Client) string {
	if found, _, err := client.Check(net.ParseIP(ip)); found && err == nil {
		return ""
	}
	return ip
}

// remove 移除重复结果
func remove(slc []string) []string {
	var result []string
	tempMap := map[string]byte{} // 存放不重复主键
	for _, e := range slc {
		l := len(tempMap)
		tempMap[e] = 0
		if len(tempMap) != l { // 加入map后，map长度变化，则元素不重复
			result = append(result, e)
		}
	}
	return result
}
