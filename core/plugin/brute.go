package plugin

import (
	"Yasso/config"
	"Yasso/config/banner"
	"Yasso/core/brute"
	"Yasso/core/logger"
	"Yasso/core/parse"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var BurpMap = map[string]interface{}{
	"ssh":      SshConnByUser,
	"mongodb":  MongoAuth,
	"mysql":    MySQLConn,
	"mssql":    MssqlConn,
	"rdp":      RdpConn,
	"redis":    RedisAuthConn,
	"ftp":      FtpConn,
	"smb":      SmbConn,
	"winrm":    WinRMAuth,
	"postgres": PostgreConn,
}

func BruteService(user, pass string, ipd string, module string, thread int, timeout time.Duration, isAlive bool) {
	banner.Banner()
	defer func() {
		logger.Info("brute service complete")
	}()
	// 先解析传过来的ips列表
	if ipd == "" {
		logger.Fatal("need ips to parse")
		return
	}
	ips, err := parse.HandleIps(ipd)
	if err != nil {
		return
	}
	var userDic, passDic []string
	if user != "" {
		userDic, err = parse.ReadFile(user)
	}
	if pass != "" {
		passDic, err = parse.ReadFile(pass)
	}
	if err != nil {
		logger.Fatal("dic file is not found")
		return
	}
	var wg sync.WaitGroup
	var ipChannel = make(chan string, 1000)
	var ipAlive []string
	if isAlive == true {
		for i := 0; i < thread; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range ipChannel {
					if ping(ip) == true {
						logger.Info(fmt.Sprintf("%v is alive (ping)", ip))
						ipAlive = append(ipAlive, ip)
					}
				}
			}()
		}
		for _, ip := range ips {
			// 带有端口的不进行扫描，直接加入
			if strings.Contains(ip, ":") {
				ipAlive = append(ipAlive, ip)
				continue
			} else {
				ipChannel <- ip
			}
		}
		close(ipChannel) // 防止死锁
		wg.Wait()
	} else {
		ipAlive = ips
	}

	logger.Info(fmt.Sprintf("start brute service %v", strings.Split(module, ",")))
	// 这里获取到了ip列表,格式各种各样 www.baidu.com:80 192.168.248.1 192.168.248.1:445
	for _, each := range strings.Split(module, ",") { // 遍历每一个服务
		// 这里获取到对应的服务和端口
		service := strings.Split(each, ":")
		if len(service) >= 3 || len(service) <= 0 {
			logger.Fatal("brute service format is error")
			break
		}
		switch service[0] {
		case "ssh":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 22
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "ssh", BurpMap["ssh"])
		case "mongo":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 27017
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "mongodb", BurpMap["mongodb"])
		case "mysql":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 3306
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "mysql", BurpMap["mysql"])
		case "rdp":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 3389
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "rdp", BurpMap["rdp"])
		case "redis":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 6379
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "redis", BurpMap["redis"])
		case "smb":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 445
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "smb", BurpMap["smb"])
		case "winrm":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 5985
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "winrm", BurpMap["winrm"])
		case "postgres":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 5432
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "postgres", BurpMap["postgres"])
		case "mssql":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 1433
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "mssql", BurpMap["mssql"])
		case "ftp":
			var p int
			if len(service) == 2 {
				// 带端口,采用用户自带端口
				p, err = strconv.Atoi(service[1])
			} else {
				// 不带端口,采用默认
				p = 21
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "ftp", BurpMap["ftp"])
		default:
			logger.Fatal(fmt.Sprintf("not found service %s", service[0]))
			return
		}
	}

}

// 执行爆破的函数
func run(ips []string, port int, user, pass []string, timeout time.Duration, thread int, service string, method interface{}) {
	var ipChannel = make(chan string, 1000) // 二次复用
	var mutex sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChannel {
				// 这里获取到每一个ip
				mutex.Lock()
				brute.NewBrute(user, pass, method, service, config.ServiceConn{
					Hostname: ip,
					Port:     port,
					Timeout:  time.Duration(timeout),
				}, thread, false, "").RunEnumeration()
				mutex.Unlock()
			}
		}()
	}
	for _, ip := range ips {
		// 带有端口的不进行扫描，直接直接跳过
		if strings.Count(ip, ":") == 1 {
			if strings.Split(ip, ":")[1] == strconv.Itoa(port) { // 带端口,且端口和需要爆破的端口号相同
				ipChannel <- strings.Split(ip, ":")[0]
			} else {
				continue
			}
		} else {
			ipChannel <- ip
		}
	}
	close(ipChannel) // 防止死锁
	wg.Wait()
}
