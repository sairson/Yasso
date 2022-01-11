package cmd

import (
	"errors"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func ResolveIPS(ip string) ([]string, error) {
	if strings.Contains(ip, ".") && strings.Contains(ip, ".txt") {
		// 此时传入的是文件txt
		file, err := os.Open(ip)
		if err != nil {
			return []string{}, err
		}
		ips := Readiness(file)
		return ips, err
	}
	reg := regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case strings.Contains(ip, "/"):
		return resolveIP(ip)
	case strings.Count(ip, "-") == 1:
		return resolveIPC(ip)
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

// 解析192.168.1.1/*的格式

func resolveIP(ip string) ([]string, error) {
	var ip4 = net.ParseIP(strings.Split(ip, "/")[0]) // [192.168.1.1 *]
	if ip4 == nil {
		return []string{}, errors.New("not an ipv4 address")
	}
	var footmark = strings.Split(ip, "/")[1] // *
	var temp []string
	var err error
	switch footmark {
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

// 解析192.168.1.1-*格式

func resolveIPC(ip string) ([]string, error) {
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

func RemoveDuplicate(old []int) []int {
	result := make([]int, 0, len(old))
	temp := map[int]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// 解析为445,69,72-15这种以逗号隔开的端口

func ResolvePORTS(ports string) ([]int, error) {
	var scanPorts []int
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.Trim(port, " ")
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}
			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = RemoveDuplicate(scanPorts)
	return scanPorts, nil
}
