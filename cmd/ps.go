package cmd

import (
	"fmt"
	"github.com/panjf2000/ants/v2"
	"github.com/spf13/cobra"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	DefaultPorts = "21,22,80,81,135,139,443,445,1433,3306,5432,5985,6379,7001,3389,8000,8080,8089,9000,9200,11211,27017"
	//AlivePort []PortResult
)

type PortResult struct {
	IP   string
	Port []int
}

var PortCmd = &cobra.Command{
	Use:   "ps",
	Short: "The port scanning module will find vulnerable ports (not support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" {
			_ = cmd.Help()
			return
		}
		var ports []int
		hosts, _ := ResolveIPS(Hosts) // 解析获取ip地址
		if Ports != "" {
			ports, _ = ResolvePORTS(Ports)
		} else {
			ports, _ = ResolvePORTS(DefaultPorts)
		}
		Println(fmt.Sprintf("Yasso resolve host len is %v,need scan %v port", len(hosts), len(hosts)*len(ports)))
		if len(hosts) <= 0 || len(ports) <= 0 {
			// resolve failed
			return
		}
		var AlivePort []PortResult
		AlivePort = PortScan(hosts, ports)
		for _, rs := range AlivePort {
			Println(fmt.Sprintf("%v %v", rs.IP, rs.Port))
		}
	},
}

func init() {
	PortCmd.Flags().DurationVarP(&TimeDuration, "time", "t", 500*time.Millisecond, "Set timeout (eg.) -t 50ms(ns,ms,s,m,h)")
	PortCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "Set `Set `hosts`(The format is similar to Nmap) or ips.txt file path")
	PortCmd.Flags().StringVarP(&Ports, "ports", "p", "", "Set `ports`(The format is similar to Nmap)(eg.) 1-2000,3389")
	PortCmd.Flags().IntVarP(&Runtime, "runtime", "r", 100, "Set scanner ants pool thread")
	rootCmd.AddCommand(PortCmd)
}

// port scanner

func PortScan(host []string, ports []int) []PortResult {
	var tempPort []PortResult
	var wg sync.WaitGroup

	p, _ := ants.NewPoolWithFunc(len(host), func(ip interface{}) {
		_ = ants.Submit(func() {
			aport := EachScan(ip.(string), ports)
			//Println()(aport)
			if len(aport) != 0 {
				// 扫描完成，加入扫描结果队列
				tempPort = append(tempPort, PortResult{ip.(string), aport})
			} // 将ip赋值给AlivePort*/
			wg.Done()
		})
	})
	for _, ip := range host {
		if strings.Contains(ip, ":") {
			addr := strings.Split(ip, ":")[0]
			port, _ := strconv.Atoi(strings.Split(ip, ":")[1])
			if portConn(addr, port) {
				Println(fmt.Sprintf("[+] %v %v open", addr, port))
				tempPort = append(tempPort, PortResult{addr, []int{port}})
			}
		} else {
			wg.Add(1)
			_ = p.Invoke(ip)
		}
	}
	wg.Wait()
	return tempPort
}

func EachScan(host string, ports []int) []int {
	var aport []int
	var wg sync.WaitGroup
	// 计算一个协程需要扫描多少端口
	var thread int
	// 如果端口数小于协程数量,thread为端口数量
	if len(ports) <= Runtime {
		thread = len(ports)
	} else {
		// 计算端口数量
		thread = Runtime // 协程数量
	}
	num := int(math.Ceil(float64(len(ports)) / float64(thread))) // 每个协程的端口数量

	// 分割端口
	all := map[int][]int{}
	for i := 1; i <= thread; i++ {
		for j := 0; j < num; j++ {
			tmp := (i-1)*num + j
			if tmp < len(ports) {
				all[i] = append(all[i], ports[tmp])
			}
		}
	}
	//Println()(all)

	for i := 1; i <= thread; i++ {
		wg.Add(1)
		tmp := all[i]
		_ = ants.Submit(func() {
			// 1,2  2,3
			//Println()(i,thread)
			for _, port := range tmp {
				// 遍历每一个端口列表
				if portConn(host, port) {
					aport = append(aport, port) // 端口返回true，开放，加入aport列表
					Println(fmt.Sprintf("[+] %v %v open", host, port))
				}
			}
			wg.Done()
		})
	}
	wg.Wait()
	return aport
}

func portConn(addr string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%v", addr, port), TimeDuration)
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	if err == nil {
		return true
	} else {
		return false
	}
}
