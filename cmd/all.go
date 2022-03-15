package cmd

import (
	"Yasso/config"
	"fmt"
	"github.com/spf13/cobra"
	"sync"
	"time"
)

var allCmd = &cobra.Command{
	Use:   "all",
	Short: "Use all scanner module (.attention) Some service not support proxy,You might lose it [*]",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" {
			_ = cmd.Help()
			return
		}
		allRun(Hosts, Ports, JsonBool, Runtime, PingBool)
		return
	},
}

func init() {
	allCmd.Flags().StringVarP(&Hosts, "host", "H", "", "Set `hosts`(The format is similar to Nmap) or ips.txt file path")
	allCmd.Flags().StringVarP(&Ports, "ports", "P", "", "Set `ports`(The format is similar to Nmap)")
	allCmd.Flags().BoolVar(&PingBool, "noping", false, "No use ping to scanner alive host")
	allCmd.Flags().BoolVar(&RunICMP, "icmp", false, "Use icmp to scanner alive host")
	allCmd.Flags().IntVar(&Runtime, "runtime", 100, "Set scanner ants pool thread")
	allCmd.Flags().StringVar(&ProxyHost, "proxy", "", "Set socks5 proxy")
	allCmd.Flags().BoolVar(&JsonBool, "json", false, "Output json file")
	allCmd.Flags().DurationVar(&TimeDuration, "time", 1*time.Second, "Set timeout ")
	rootCmd.AddCommand(allCmd)
}

func allRun(hostString string, portString string, jsonbool bool, runtime int, noping bool) {
	defer func() {
		fmt.Println("[Yasso] scan task is completed")
	}()
	var (
		ips      []string
		ports    []int
		webports []int
		alive    []string
		wg       sync.WaitGroup
		lock     sync.Mutex
	)
	if hostString != "" {
		ips, _ = ResolveIPS(hostString) // 解析ip并获取ip列表
	}
	if Ports != "" {
		ports, _ = ResolvePORTS(portString)
		webports, _ = ResolvePORTS(config.DisMapPorts)
	} else {
		ports, _ = ResolvePORTS(DefaultPorts)
		webports, _ = ResolvePORTS(config.DisMapPorts)
	}

	if noping == true {
		// 不执行ping操作
		alive = ips
	} else {
		// 执行 ping 操作
		fmt.Println("----- [Yasso] Start do ping scan -----")
		alive = execute(ips, RunICMP)
	}
	fmt.Println("[Yasso get alive host] is", len(alive))
	// 做漏洞扫描
	var out []JsonOut
	//TODO:
	if len(alive) > 0 {
		fmt.Println("----- [Yasso] Start do vuln scan -----")
		VulScan(alive, false, true, false) // 做漏洞扫描
		if len(alive) != 0 {
			fmt.Println("----- [Yasso] Start do port scan -----")
		}
		PortResults := PortScan(alive, ports)
		if len(PortResults) != 0 {
			fmt.Println("----- [Yasso] Start do crack service -----")
			for _, v := range PortResults {
				var one JsonOut
				// 对json各式数据复制
				wg.Add(1)
				go func(v PortResult, one JsonOut) {
					defer wg.Done()
					one.Host = v.IP
					one.Ports = v.Port
					for _, p := range v.Port {
						lock.Lock()
						switch p {
						case 21:
							users, pass := ReadTextToDic("ftp", UserDic, PassDic)
							// add ftp "" pass
							flag, _ := FtpConn(config.HostIn{Host: v.IP, Port: p, TimeOut: TimeDuration}, "anonymous", "")
							if flag == true {
								if flag == true && jsonbool == true {
									one.WeakPass = append(one.WeakPass, map[string]map[string]string{"ftp": {"anonymous": "null"}})
								}
								continue
							}
							burpTask(v.IP, "ftp", users, pass, p, runtime, TimeDuration, "", false, jsonbool, &one)
						case 22:
							users, pass := ReadTextToDic("ssh", UserDic, PassDic)
							burpTask(v.IP, "ssh", users, pass, p, runtime, TimeDuration, "", false, jsonbool, &one)
						case 3306:
							users, pass := ReadTextToDic("mysql", UserDic, PassDic)
							burpTask(v.IP, "mysql", users, pass, p, runtime, TimeDuration, "", false, jsonbool, &one)
						case 6379:
							_, b, _ := RedisUnAuthConn(config.HostIn{Host: v.IP, Port: p, TimeOut: TimeDuration}, "test", "test")
							if b == true && jsonbool == true {
								one.WeakPass = append(one.WeakPass, map[string]map[string]string{"redis": {"null": "null"}})
							}
							users, pass := ReadTextToDic("redis", UserDic, PassDic)
							burpTask(v.IP, "redis", users, pass, p, runtime, 5*time.Second, "", false, jsonbool, &one)
						case 1433:
							users, pass := ReadTextToDic("mssql", UserDic, PassDic)
							burpTask(v.IP, "mssql", users, pass, p, runtime, TimeDuration, "", false, jsonbool, &one)
						case 5432:
							users, pass := ReadTextToDic("postgres", UserDic, PassDic)
							burpTask(v.IP, "postgres", users, pass, p, runtime, TimeDuration, "", false, jsonbool, &one)
						case 27017:
							b, _ := MongoUnAuth(config.HostIn{Host: v.IP, Port: p, TimeOut: TimeDuration}, "test", "test")
							if b == true && jsonbool == true {
								one.WeakPass = append(one.WeakPass, map[string]map[string]string{"mongodb": {"null": "null"}})
							}
							users, pass := ReadTextToDic("mongodb", UserDic, PassDic)
							burpTask(v.IP, "mongodb", users, pass, p, runtime, TimeDuration, "", false, jsonbool, &one)
						case 445:
							users, pass := ReadTextToDic("smb", UserDic, PassDic)
							burpTask(v.IP, "smb", users, pass, p, runtime, TimeDuration, "", false, jsonbool, &one)
						case 5985:
							users, pass := ReadTextToDic("rdp", UserDic, PassDic) // winrm与本地rdp认证相同
							burpTask(v.IP, "winrm", users, pass, p, runtime, TimeDuration, "", false, jsonbool, &one)
						case 11211:
							//memcached 未授权
							b, _ := MemcacheConn(config.HostIn{Host: v.IP, Port: p, TimeOut: TimeDuration})
							if b == true && jsonbool == true {
								one.WeakPass = append(one.WeakPass, map[string]map[string]string{"Memcached": {"null": "null"}})
							}
						case 2181:
							//zookeeper 未授权
							b, _ := ZookeeperConn(config.HostIn{Host: v.IP, Port: p, TimeOut: TimeDuration})
							if b == true && jsonbool == true {
								one.WeakPass = append(one.WeakPass, map[string]map[string]string{"zookeeper": {"null": "null"}})
							}
						}
						lock.Unlock()
					}
					out = append(out, one)
				}(v, one)
			}
			wg.Wait()
		}
		// 做网卡扫描
		fmt.Println("----- [Yasso] Start do Windows service scan -----")
		winscan(alive, true)
		fmt.Println("----- [Yasso] Start do web service scan -----")
		out = DisMapScanJson(&out, webports)
	}
	if jsonbool == true {
		Out("Yasso.json", out)
	}
}
