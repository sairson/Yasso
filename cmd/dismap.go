package cmd

import (
	"Yasso/config"
	"fmt"
	"github.com/spf13/cobra"
	"math"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"
)

func init() {
	rootCmd.AddCommand(DisMapCmd)
	DisMapCmd.Flags().DurationVarP(&TimeDuration, "time", "t", 1*time.Second, "Set timeout (eg.) -t 50ms(ns,ms,s,m,h)")
	DisMapCmd.Flags().StringVarP(&Hosts, "hosts", "H", "", "Set `hosts`(The format is similar to Nmap) or ips.txt file path")
	DisMapCmd.Flags().StringVarP(&Ports, "ports", "p", "", "Set `ports`(The format is similar to Nmap)(eg.) 1-2000,3389")
	DisMapCmd.Flags().IntVarP(&Runtime, "runtime", "r", 508, "Set scanner ants pool thread")
	DisMapCmd.Flags().BoolVar(&PingBool, "ping", false, "Use ping to scan alive host")
	DisMapCmd.Flags().StringVar(&ProxyHost, "proxy", "", "Set socks5 proxy and use it ")
}

var lock sync.Mutex
var DisMapCmd = &cobra.Command{
	Use:   "webscan",
	Short: "Use dismap module discover Web fingerprints (support proxy)",
	Run: func(cmd *cobra.Command, args []string) {
		if Hosts == "" {
			_ = cmd.Help()
			return
		}
		var ports []int
		hosts, _ := ResolveIPS(Hosts)
		var runhosts []string

		if PingBool == true {
			runhosts = execute(hosts, false)
		} else {
			runhosts = hosts
		}
		// 解析获取ip地址

		if Ports != "" {
			ports, _ = ResolvePORTS(Ports)
		} else {
			ports, _ = ResolvePORTS(config.DisMapPorts)
		}
		Println(fmt.Sprintf("[Yasso] Find Host %v,Need scan %v", len(runhosts), len(runhosts)*len(ports)))
		if len(hosts) <= 0 || len(ports) <= 0 {
			// resolve failed
			return
		}
		DisMapScan(runhosts, ports)
		Println("[Yasso] scan Complete !")
	},
}

func DisMapScan(host []string, ports []int) {
	var wg sync.WaitGroup
	for _, ip := range host {
		wg.Add(1)
		EachDisMap(ip, ports, &wg, nil)
	}
	wg.Wait()
}

func DisMapScanJson(in *[]JsonOut, ports []int) (out []JsonOut) {
	var wg sync.WaitGroup
	for _, v := range *in {
		wg.Add(1)
		s := EachDisMap(v.Host, ports, &wg, &v)
		out = append(out, s)
	}
	wg.Wait()
	return out
}

func EachDisMap(host string, ports []int, w *sync.WaitGroup, v *JsonOut) JsonOut {
	defer w.Done()
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
	//Println(all)

	for i := 1; i <= thread; i++ {
		wg.Add(1)
		tmp := all[i]
		go func(out *JsonOut) {
			defer wg.Done()
			// 1,2  2,3
			//Println(i,thread)
			for _, port := range tmp {
				// 遍历每一个端口列表
				DisMapConn(host, port, v)
			}
		}(v)
	}
	wg.Wait()
	return *v
}

func DisMapConn(host string, port int, out *JsonOut) bool {

	url := ParseUrl(host, strconv.Itoa(port))
	for _, r := range Identify(url, TimeDuration) {
		if r.RespCode != "" {
			lock.Lock()
			out.WebHosts = append(out.WebHosts, fmt.Sprintf("%v %v %v %v", r.RespCode, r.Url, r.Result, r.Title))
			Println(fmt.Sprintf("[+] %v %v %v %v", r.RespCode, r.Url, r.Result, r.Title))
			lock.Unlock()
		}
	}
	return true
}

type IdentifyResult struct {
	Type     string
	RespCode string
	Result   string
	ResultNc string
	Url      string
	Title    string
}

func Identify(url string, timeout time.Duration) []IdentifyResult {
	var DefaultFavicon string
	var CustomFavicon string
	var DefaultTarget string
	var CustomTarget string
	var Favicon string
	var RequestRule string
	var RespTitle string
	var RespBody string
	var RespHeader string
	var RespCode string
	var DefaultRespTitle string
	var DefaultRespBody string
	var DefaultRespHeader string
	var DefaultRespCode string
	var CustomRespTitle string
	var CustomRespBody string
	var CustomRespHeader string
	var CustomRespCode string
	for _, resp := range DefaultRequests(url, timeout) { // Default Request
		DefaultRespBody = resp.RespBody
		DefaultRespHeader = resp.RespHeader
		DefaultRespCode = resp.RespStatusCode
		DefaultRespTitle = resp.RespTitle
		DefaultTarget = resp.Url
		DefaultFavicon = resp.FaviconMd5
	}
	// start identify
	var identifyData []string
	var successType string
	for _, rule := range config.RuleData {
		if rule.Http.ReqMethod != "" { // Custom Request Result
			for _, resp := range CustomRequests(url, timeout, rule.Http.ReqMethod, rule.Http.ReqPath, rule.Http.ReqHeader, rule.Http.ReqBody) {
				CustomRespBody = resp.RespBody
				CustomRespHeader = resp.RespHeader
				CustomRespCode = resp.RespStatusCode
				CustomRespTitle = resp.RespTitle
				CustomTarget = resp.Url
				CustomFavicon = resp.FaviconMd5
			}
			url = CustomTarget
			Favicon = CustomFavicon
			RespBody = CustomRespBody
			RespHeader = CustomRespHeader
			RespCode = CustomRespCode
			RespTitle = CustomRespTitle
			// If the http request fails, then RespBody and RespHeader are both null
			// At this time, it is considered that the url does not exist
			if RespBody == RespHeader {
				continue
			}
			if rule.Mode == "" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "CustomRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "or" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "and" {
				index := 0
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						index = index + 1
					}
				}
				if index == 2 {
					identifyData = append(identifyData, rule.Name)
					RequestRule = "CustomRequest"
				}
			}
			if rule.Mode == "and|and" {
				index := 0
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						index = index + 1
					}
				}
				if index == 3 {
					identifyData = append(identifyData, rule.Name)
					RequestRule = "CustomRequest"
				}
			}
			if rule.Mode == "or|or" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "and|or" {
				grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
				all_type := grep.FindStringSubmatch(rule.Type)
				//
				//Println(all_type)
				if len(regexp.MustCompile("header").FindAllStringIndex(all_type[1], -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(all_type[1], -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[1], -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "or|and" {
				grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
				all_type := grep.FindStringSubmatch(rule.Type)
				//Println(all_type)
				if len(regexp.MustCompile("header").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						successType = rule.Type
						continue
					}
				}
			}
		} else { // Default Request Result
			url = DefaultTarget
			Favicon = DefaultFavicon
			RespBody = DefaultRespBody
			RespHeader = DefaultRespHeader
			RespCode = DefaultRespCode
			RespTitle = DefaultRespTitle
			// If the http request fails, then RespBody and RespHeader are both null
			// At this time, it is considered that the url does not exist
			if RespBody == RespHeader {
				continue
			}
			if rule.Mode == "" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "or" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "and" {
				index := 0
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						index = index + 1
					}
				}
				if index == 2 {
					identifyData = append(identifyData, rule.Name)
					RequestRule = "DefaultRequest"
				}
			}
			if rule.Mode == "and|and" {
				index := 0
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						index = index + 1
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						index = index + 1
					}
				}
				if index == 3 {
					identifyData = append(identifyData, rule.Name)
					RequestRule = "DefaultRequest"
				}
			}
			if rule.Mode == "or|or" {
				if len(regexp.MustCompile("header").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(rule.Type, -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == true {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "and|or" {
				grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
				allType := grep.FindStringSubmatch(rule.Type)
				//Println(all_type)
				if len(regexp.MustCompile("header").FindAllStringIndex(allType[1], -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(allType[1], -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(allType[1], -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
			if rule.Mode == "or|and" {
				grep := regexp.MustCompile("(.*)\\|(.*)\\|(.*)")
				all_type := grep.FindStringSubmatch(rule.Type)
				//Println(all_type)
				if len(regexp.MustCompile("header").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("body").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) == checkFavicon(Favicon, rule.Rule.InIcoMd5) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
				if len(regexp.MustCompile("ico").FindAllStringIndex(all_type[3], -1)) == 1 {
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkHeader(url, RespHeader, rule.Rule.InHeader, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
					if checkFavicon(Favicon, rule.Rule.InIcoMd5) == checkBody(url, RespBody, rule.Rule.InBody, rule.Name, RespTitle, RespCode) {
						identifyData = append(identifyData, rule.Name)
						RequestRule = "DefaultRequest"
						successType = rule.Type
						continue
					}
				}
			}
		}
	}
	// identify
	if RequestRule == "DefaultRequest" {
		RespBody = DefaultRespBody
		RespHeader = DefaultRespHeader
		RespCode = DefaultRespCode
		RespTitle = DefaultRespTitle
		url = DefaultTarget
	} else if RequestRule == "CustomRequest" {
		url = CustomTarget
		RespBody = CustomRespBody
		RespHeader = CustomRespHeader
		RespCode = CustomRespCode
		RespTitle = CustomRespTitle
	}
	var identifyResult string
	var identifyResultNocolor string
	for _, result := range identifyData {
		if runtime.GOOS == "windows" {
			identifyResult += "[" + result + "]" + " "
		} else {
			identifyResult += "[" + result + "]" + " "
		}
	}
	for _, result := range identifyData {
		identifyResultNocolor += "[" + result + "]" + " "
	}

	Result := []IdentifyResult{
		{successType, RespCode, identifyResult, identifyResultNocolor, url, RespTitle},
	}
	return Result
}

func checkHeader(url, responseHeader string, ruleHeader string, name string, title string, RespCode string) bool {
	grep := regexp.MustCompile("(?i)" + ruleHeader)
	if len(grep.FindStringSubmatch(responseHeader)) != 0 {
		//fmt.Print("[header] ")
		return true
	} else {
		return false
	}
}

func checkBody(url, responseBody string, ruleBody string, name string, title string, RespCode string) bool {
	grep := regexp.MustCompile("(?i)" + ruleBody)
	if len(grep.FindStringSubmatch(responseBody)) != 0 {
		//fmt.Print("[body] ")
		return true
	} else {
		return false
	}
}

func checkFavicon(Favicon, ruleFaviconMd5 string) bool {
	grep := regexp.MustCompile("(?i)" + ruleFaviconMd5)
	if len(grep.FindStringSubmatch(Favicon)) != 0 {
		// fmt.Print("url")
		return true
	} else {
		return false
	}
}
