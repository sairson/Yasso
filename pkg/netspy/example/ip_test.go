package example

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func Test(t *testing.T) {
	inters, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, inter := range inters {
		// 判断网卡是否开启，过滤本地环回接口
		if inter.Flags&net.FlagUp != 0 && !strings.HasPrefix(inter.Name, "lo") {
			// 获取网卡下所有的地址
			addrs, err := inter.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					//判断是否存在IPV4 IP 如果没有过滤
					if strings.ContainsAny(ipnet.String(), ":") {
						continue
					} else {
						//fmt.Println(ipnet)
						minIp, maxIp := getCidrIpRange(ipnet.String())
						fmt.Println("CIDR最小IP：", minIp, " CIDR最大IP：", maxIp)
						mask, _ := ipnet.Mask.Size()
						fmt.Println("掩码：", getCidrIpMask(mask))
						fmt.Println("主机数量", getCidrHostNum(mask))
						fmt.Println("==============================")
					}
				}
			}
		}
	}
	return
}
