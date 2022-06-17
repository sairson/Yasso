package plugin

import (
	"Yasso/config"
	"Yasso/config/banner"
	"Yasso/core/brute"
	"Yasso/core/logger"
	"Yasso/core/parse"
	"Yasso/pkg/webscan"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type scannerAll struct {
	ip        string        // 需要解析的ip列表或者文件
	port      string        // 需要解析的端口列表
	noAlive   bool          // 是否探测存活
	noBrute   bool          // 是否进行爆破
	userPath  string        // 爆破所需的user字典路径
	passPath  string        // 爆破所需的pass字典路径
	thread    int           // 扫描所需线程数
	timeout   time.Duration // 爆破的超时数
	noService bool          // 是否进行服务的探测（包括web）
	noVulcan  bool          // 是否进行主机层漏洞扫描
}

func NewAllScanner(ip, port string, isAlive, isBrute bool, user, pass string, thread int, timeout time.Duration, noService bool, noVulcan bool) *scannerAll {
	return &scannerAll{
		ip:        ip,
		port:      port,
		noAlive:   isAlive,
		noBrute:   isBrute,
		userPath:  user,
		passPath:  pass,
		thread:    thread,
		timeout:   timeout,
		noService: noService,
		noVulcan:  noVulcan,
	}
}

// RunEnumeration 执行程序
func (s *scannerAll) RunEnumeration() {
	banner.Banner()
	defer func() {
		logger.Info("Yasso scan complete")
	}()
	if s.ip == "" {
		logger.Fatal("need ips to parse")
		return
	}
	// 1. 解析用户的ip列表
	ips, err := parse.HandleIps(s.ip)
	if err != nil {
		logger.Fatal("parse ips has an error", err.Error())
		return
	}
	// 2.解析用户的port列表
	var ports []int
	if s.port == "" {
		ports = config.DefaultScannerPort
	} else {
		ports, err = parse.HandlePorts(s.port)
		if err != nil {
			logger.Fatal("parse ports has an error", err.Error())
			return
		}
	}
	var user []string
	var pass []string
	// 3.解析用户的字典，没有字典的话，就采用默认的字典
	if s.userPath != "" {
		user, err = parse.ReadFile(s.userPath)
		if err != nil {
			logger.Fatal("parse user dict file has an error")
			return
		}
	}
	if s.passPath != "" {
		pass, err = parse.ReadFile(s.passPath)
		if err != nil {
			logger.Fatal("parse user dict file has an error")
			return
		}
		return
	} else {
		pass = config.PassDict
	}

	// 4. 解析完成后，通过isAlive判断存活，这里采用并发方式
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var ipChannel = make(chan string, 1000)
	var port7 []int = []int{139, 445, 135, 22, 23, 21, 3389}
	var ipAlive []string
	if s.noAlive == false {
		for i := 0; i < s.thread; i++ {
			wg.Add(1)
			go func(ctx context.Context) {
				defer wg.Done()
				for ip := range ipChannel {
					if ping(ip) == true {
						logger.Info(fmt.Sprintf("%v is alive (ping)", ip))
						logger.JSONSave(ip, logger.HostSave) // json存储
						ipAlive = append(ipAlive, ip)
					} else {
						// 这里尝试探测7个常用端口，如果有一个开放，则证明ip也是存活网段
						for _, p := range port7 {
							if tcpConn(ip, p) == true {
								logger.Info(fmt.Sprintf("%v is alive (tcp)", ip))
								logger.JSONSave(ip, logger.HostSave) // json存储
								ipAlive = append(ipAlive, ip)
								break
							}
						}
					}
				}
			}(context.Background())
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
	// 5.扫描完成后,做端口扫描,同样是高并发
	ipChannel = make(chan string, 1000) // 二次复用
	var portAlive = make(map[string][]int)
	for i := 0; i < s.thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChannel {
				// 做端口扫描
				mutex.Lock()
				p := NewRunner(ports, ip, s.thread, tcpConn).RunEnumeration()
				portAlive[ip] = append(portAlive[ip], p...)
				logger.JSONSave(ip, logger.PortSave, p) // 存储可用端口
				mutex.Unlock()
			}
		}()
	}
	for _, ip := range ipAlive {
		// 带有端口的不进行扫描，直接加入
		if strings.Count(ip, ":") == 1 {
			t := strings.Split(ip, ":")
			p, err := strconv.Atoi(t[1])
			if err != nil {
				continue
			}
			portAlive[t[0]] = append(portAlive[t[0]], p)
			continue
		} else {
			ipChannel <- ip
		}
	}
	close(ipChannel) // 防止死锁
	wg.Wait()
	// 6. 端口扫描结束，根据用户指示，判断是否进行爆破
	for k, v := range portAlive {
		// 遍历每一个ip的每一个端口看看属于哪一个服务
		v = parse.RemoveDuplicate(v) // 去个重
		sort.Ints(v)                 // 排序
		for _, p := range v {
			switch p {
			case 22:
				if s.noService == false {
					information := VersionSSH(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					})
					logger.JSONSave(k, logger.InformationSave, "ssh", information)
				}
				brute.NewBrute(user, pass, SshConnByUser, "ssh", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 21:
				// 未授权
				if ok, _ := FtpConn(config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, "", ""); ok {
					continue
				}
				// 爆破ftp
				brute.NewBrute(user, pass, FtpConn, "ftp", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 445:
				// 未授权
				if ok, _ := SmbConn(config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, "administrator", ""); ok {
					logger.Info(fmt.Sprintf("smb %s unauthorized", k))
					// 未授权,用户名密码均为null
					logger.JSONSave(k, logger.WeakPassSave, "smb", map[string]string{"null": "null"})
					continue
				}
				brute.NewBrute(user, pass, SmbConn, "smb", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 1433:
				if s.noService == false {
					ok, information := VersionMssql(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					})
					// 存在ok
					if ok {
						logger.JSONSave(k, logger.InformationSave, "mssql", information)
					}
				}
				brute.NewBrute(user, pass, MssqlConn, "mssql", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 2181:
				if s.noService == false {
					if ok, _ := ZookeeperConn(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						// 未授权
						logger.JSONSave(k, logger.WeakPassSave, "zookeeper", map[string]string{"null": "null"})
						continue
					}
				}
			case 3306:
				// 未授权
				if _, ok, _ := MySQLConn(config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, "", ""); ok {
					logger.Info(fmt.Sprintf("mysql %s unauthorized", k))
					// 未授权,用户名密码均为null
					logger.JSONSave(k, logger.WeakPassSave, "mysql", map[string]string{"null": "null"})
					continue
				} else {
					brute.NewBrute(user, pass, MySQLConn, "mysql", config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, s.thread, s.noBrute, "").RunEnumeration()
				}
			case 3389:
				// 仅探测主机版本
				if s.noService == false {
					if ok, information := VersionRdp(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						// 版本
						logger.JSONSave(k, logger.InformationSave, "rdp", information)
						continue
					}
				}
			case 6379:
				if s.noService == false {
					if _, ok, _ := RedisUnAuthConn(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						logger.JSONSave(k, logger.WeakPassSave, "redis", map[string]string{"null": "null"})
						continue
					}
				}
				brute.NewBrute(user, pass, RedisAuthConn, "redis", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()

			case 5432:
				brute.NewBrute(user, pass, PostgreConn, "postgres", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 5985:
				brute.NewBrute(user, pass, WinRMAuth, "winrm", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 11211:
				if s.noService == false {
					if ok, _ := MemcacheConn(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						logger.JSONSave(k, logger.WeakPassSave, "memcache", map[string]string{"null": "null"})
						continue
					}
				}
			case 27017:
				if s.noService == false {
					if ok, _ := MongoUnAuth(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						logger.JSONSave(k, logger.WeakPassSave, "mongodb", map[string]string{"null": "null"})
						break
					}
				}
				brute.NewBrute(user, pass, MongoAuth, "mongodb", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			default:
				if s.noService == false {
					webscan.DisMapConn(k, p, s.timeout)
				}
				continue
			}
		}
	}
	if s.noService == false {
		// 8. 进行win服务扫描扫描
		ipChannel = make(chan string, 1000) // 第四次复用
		for i := 0; i < s.thread; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range ipChannel {
					mutex.Lock()
					func(ip string) {
						ok, information := NbnsScanConn(ip, 137, s.timeout)
						if ok {
							logger.JSONSave(ip, logger.InformationSave, "netbios", information)
						}
					}(ip)
					func(ip string) {
						ok, information := SmbScanConn(ip, 445, s.timeout)
						if ok {
							logger.JSONSave(ip, logger.InformationSave, "smb", information)
						}
					}(ip)
					func(ip string) {
						ok, information := OxidScanConn(ip, 135, s.timeout)
						if ok {
							logger.JSONSave(ip, logger.InformationSave, "oxid", information)
						}
						ok, information = DceRpcOSVersion(ip, 135, s.timeout)
						if ok {
							logger.JSONSave(ip, logger.InformationSave, "dcerpc", information)
						}
					}(ip)
					mutex.Unlock()
				}
			}()
		}
		for _, ip := range ipAlive {
			// 带有端口的不进行扫描，直接加入
			if strings.Count(ip, ":") == 1 && (strings.Split(ip, ":")[0] != strconv.Itoa(139) || strings.Split(ip, ":")[0] != strconv.Itoa(135) || strings.Split(ip, ":")[0] != strconv.Itoa(445)) {
				continue
			} else if strings.Split(ip, ":")[0] == strconv.Itoa(139) || strings.Split(ip, ":")[0] == strconv.Itoa(135) || strings.Split(ip, ":")[0] == strconv.Itoa(445) {
				ipChannel <- strings.Split(ip, ":")[0]
			} else {
				ipChannel <- ip
			}
		}
		close(ipChannel) // 防止死锁
		wg.Wait()        // 等待结束

	}
	// 7. 进行主机漏洞扫描
	if s.noVulcan == false {
		ipChannel = make(chan string, 1000) // 第四次复用
		for i := 0; i < s.thread; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range ipChannel {
					// 做端口扫描
					mutex.Lock()
					func() {
						ok := Ms17010Conn(config.ServiceConn{
							Hostname:  ip,
							Port:      445,
							Domain:    "",
							Timeout:   s.timeout,
							PublicKey: "",
						})
						if ok {
							logger.JSONSave(ip, logger.VulnerabilitySave, "MS17010")
						}
					}()
					func() {
						ok := SmbGhostConn(config.ServiceConn{
							Hostname:  ip,
							Port:      445,
							Domain:    "",
							Timeout:   s.timeout,
							PublicKey: "",
						})
						if ok {
							logger.JSONSave(ip, logger.VulnerabilitySave, "CVE-2020-0796")
						}
					}()
					mutex.Unlock()
				}
			}()
		}
		for _, ip := range ipAlive {
			// 带有端口的不进行扫描，直接加入
			if strings.Count(ip, ":") == 1 && strings.Split(ip, ":")[0] != strconv.Itoa(445) {
				continue
			} else if strings.Split(ip, ":")[0] == strconv.Itoa(445) {
				ipChannel <- strings.Split(ip, ":")[0]
			} else {
				ipChannel <- ip
			}
		}

		close(ipChannel) // 防止死锁
		wg.Wait()        // 等待结束
	}
	logger.LoggerSave()
}
