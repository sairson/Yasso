package parse

import (
	"Yasso/core/logger"
	"bufio"
	"errors"
	"fmt"
	"github.com/projectdiscovery/cdncheck"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ReadFile 从文件中读取数据
func ReadFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		logger.Fatal("open file has an error", err.Error())
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var re []string
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			re = append(re, text)
		}
	}
	re = Duplicate(re) // 去重
	return re, nil
}

// ConvertDomainToIpAddress 将域名转换成ip地址
func ConvertDomainToIpAddress(domains []string, thread int) ([]string, error) {
	checkChan := make(chan string, 100)
	var wg sync.WaitGroup
	var re []string
	for i := 0; i < thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range checkChan {
				if strings.Count(host, ".") == 3 && len(strings.Split(host, ":")) == 2 {
					// 这种是带有端口的ip地址
					re = append(re, host)
					continue
				}
				ip, err := net.LookupHost(host)
				if err != nil {
					continue
				}
				if ip != nil {
					// 证明存在cdn，直接丢掉即可(不跑带有cdn的域名)
					if len(ip) >= 2 {
						logger.Info(fmt.Sprintf("%s has cdn %v", host, ip[:]))
						continue
					} else {
						for _, i := range ip {
							re = append(re, i)
						}
					}
				}
			}
		}()
	}
	for _, domain := range domains {
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
	re = Duplicate(re) // 去重
	return re, nil
}

// cdnFilter cdn过滤器
func cdnFilter(ip string, client *cdncheck.Client) string {
	if found, _, err := client.Check(net.ParseIP(ip)); found && err == nil {
		return ip
	}
	return ""
}

// Duplicate 去重
func Duplicate(slc []string) []string {
	var re []string
	temp := map[string]byte{}
	for _, v := range slc {
		l := len(temp)
		temp[v] = 0
		if len(temp) != l {
			re = append(re, v)
		}
	}
	return re
}

// RegIpv4Address 匹配ipv4
func RegIpv4Address(context string) string {
	matched, err := regexp.MatchString("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}", context)
	if err != nil {
		return ""
	}
	if matched {
		return context
	}
	return ""
}

func HandleIps(ip string) ([]string, error) {
	var Unprocessed []string
	var err error
	var basic []string

	if strings.Contains(ip, ".txt") {
		if strings.ToLower(path.Ext(filepath.Base(ip))) == ".txt" {
			// 文件后缀为.txt的话,我们按照文件解析并获取数据结果
			Unprocessed, err = ReadFile(ip)
			if err != nil {
				return []string{}, err
			}
		}
		/*
			这里获取到的数据格式可能为
			192.168.248.1/24
			192.168.248.1-155
			www.baidu.com
			192.168.248.1:3389
			https://www.baidu.com
		*/

		// 第一波解析开始，解析ip地址格式
		for _, i := range Unprocessed {
			switch {
			case RegIpv4Address(i) != "" && (strings.Count(i, "/24") == 1 || strings.Count(i, "/16") == 1):
				temp, err := ConvertIpFormatA(i)
				if err != nil {
					logger.Fatal("parse ip address has an error", err.Error())
					return []string{}, err
				}
				basic = append(basic, temp...)
			case RegIpv4Address(i) != "" && strings.Count(i, "-") == 1 && !strings.Contains(i, "/"):
				fmt.Println(i)
				temp, err := ConvertIpFormatB(i)
				if err != nil {
					logger.Fatal("parse ip address has an error", err.Error())
					return []string{}, err
				}
				basic = append(basic, temp...)
			case strings.Contains(i, "https://") || strings.Contains(i, "http://"):
				if strings.Contains(i, "https://") {
					basic = append(basic, strings.ReplaceAll(i, "https://", ""))
				}
				if strings.Contains(i, "http://") {
					basic = append(basic, strings.ReplaceAll(i, "https", ""))
				}
			default:
				basic = append(basic, i)
			}
		}
		// 第一波解析完成，开始第二波解析，解析域名
		basic = Duplicate(basic) // 第一次去重
		basic, err = ConvertDomainToIpAddress(basic, 100)
		if err != nil {
			logger.Fatal("parse domain has an error", err.Error())
			return nil, err
		}
		basic = Duplicate(basic) // 第二次去重
	} else {
		basic, err = ConvertIpFormatAll(ip)
		if err != nil {
			logger.Fatal("parse ip address has an error", err.Error())
			return []string{}, err
		}
	}
	// 二次筛选
	var newBasic []string
	for _, ip := range basic {
		if strings.Contains(ip, "/") {
			newBasic = append(newBasic, strings.Split(ip, "/")[0])
		} else {
			newBasic = append(newBasic, ip)
		}
	}
	// 对获取到的ip地址进行排序进行后续操作
	sort.Strings(newBasic)
	return newBasic, err
}

// ConvertIpFormatA 不解析192.168.248.1/8格式目前
func ConvertIpFormatA(ip string) ([]string, error) {
	var ip4 = net.ParseIP(strings.Split(ip, "/")[0])
	if ip4 == nil {
		return []string{}, errors.New("not an ipv4 address")
	}
	var mark = strings.Split(ip, "/")[1]
	var temp []string
	var err error
	switch mark {
	case "24":
		var ip3 = strings.Join(strings.Split(ip[:], ".")[0:3], ".")
		for i := 0; i <= 255; i++ {
			temp = append(temp, ip3+"."+strconv.Itoa(i))
		}
		err = nil
	case "16":
		var ip2 = strings.Join(strings.Split(ip[:], ".")[0:2], ".")
		for i := 0; i <= 255; i++ {
			for j := 0; j <= 255; j++ {
				temp = append(temp, ip2+"."+strconv.Itoa(i)+"."+strconv.Itoa(j))
			}
		}
		err = nil
	default:
		temp = []string{}
		err = errors.New("not currently supported")
	}
	return temp, err
}

func ConvertIpFormatB(ip string) ([]string, error) {
	var ip4 = strings.Split(ip, "-")
	var ipA = net.ParseIP(ip4[0])
	if ip4 == nil {
		return []string{}, errors.New("not an ipv4 address")
	}
	var temp []string
	if len(ip4[1]) < 4 {
		iprange, err := strconv.Atoi(ip4[1])
		if ipA == nil || iprange > 255 || err != nil {
			return []string{}, errors.New("input format is not ccorrect")
		}
		var splitip = strings.Split(ip4[0], ".")
		ip1, err1 := strconv.Atoi(splitip[3])
		ip2, err2 := strconv.Atoi(ip4[1])
		prefixip := strings.Join(splitip[0:3], ".")
		if ip1 > ip2 || err1 != nil || err2 != nil {
			return []string{}, errors.New("input format is not ccorrect")
		}
		for i := ip1; i <= ip2; i++ {
			temp = append(temp, prefixip+"."+strconv.Itoa(i))
		}
	} else {
		var splitip1 = strings.Split(ip4[0], ".")
		var splitip2 = strings.Split(ip4[1], ".")
		if len(splitip1) != 4 || len(splitip2) != 4 {
			return []string{}, errors.New("input format is not ccorrect")
		}
		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(splitip1[i])
			ip2, err2 := strconv.Atoi(splitip2[i])
			if ip1 > ip2 || err1 != nil || err2 != nil {
				return []string{}, errors.New("input format is not ccorrect")
			}
			start[i], end[i] = ip1, ip2
		}
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
			temp = append(temp, ip)
		}
	}
	return temp, nil
}

func ConvertIpFormatAll(ip string) ([]string, error) {
	reg := regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case strings.Count(ip, "/") == 1:
		return ConvertIpFormatA(ip)
	case strings.Count(ip, "-") == 1:
		return ConvertIpFormatB(ip)
	case reg.MatchString(ip):
		_, err := net.LookupHost(ip)
		if err != nil {
			return []string{}, err
		}
		return []string{ip}, nil
	default:
		var isip = net.ParseIP(ip)
		if isip == nil {
			return []string{}, errors.New("input format is not ccorrect")
		}
		return []string{ip}, nil
	}
}
