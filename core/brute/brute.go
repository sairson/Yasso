package brute

import (
	"Yasso/config"
	"Yasso/core/logger"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
)

type Brute struct {
	user        []string           // 被枚举的用户名
	pass        []string           // 被枚举的密码
	bruteMethod interface{}        // 枚举方法
	service     string             // 服务命令
	serviceConn config.ServiceConn // 服务连接
	thread      int                // 执行爆破的线程数
	output      string             // 结果输出路径
	noBrute     bool               // 是否执行爆破
}

func NewBrute(user, pass []string, method interface{}, service string, serviceConn config.ServiceConn, thread int, noBrute bool, output string) *Brute {
	return &Brute{
		user:        user,
		pass:        pass,
		bruteMethod: method,
		output:      output,
		service:     service,
		thread:      thread,
		serviceConn: serviceConn,
		noBrute:     noBrute,
	}
}

// RunEnumeration 开始蛮力枚举
func (b *Brute) RunEnumeration() {
	if b.noBrute == false {
		var wg sync.WaitGroup
		if len(b.user) == 0 {
			b.user = config.UserDict[b.service] // 获取对应端口的user列表
		}
		if len(b.pass) == 0 {
			b.pass = config.PassDict
		}
		var t int
		if len(b.pass) <= b.thread {
			t = len(b.pass)
		} else {
			t = b.thread
		}
		// 分割密码
		num := int(math.Ceil(float64(len(b.pass)) / float64(b.thread))) // 每个协程的user数量
		// 分割用户名
		all := map[int][]string{}
		for i := 1; i <= t; i++ {
			for j := 0; j < num; j++ {
				tmp := (i-1)*num + j
				if tmp < len(b.pass) {
					all[i] = append(all[i], b.pass[tmp])
				}
			}
		}
		for i := 1; i <= t; i++ {
			wg.Add(1)
			tmp := all[i]
			go func(tmp []string) {
				defer wg.Done()
				for _, p := range tmp {
					for _, u := range b.user {
						// 开始爆破,带有用户名密码的服务
						if strings.Contains(p, "{user}") {
							p = strings.ReplaceAll(p, "{user}", u)
						}
						if b.export(b.call(b.serviceConn, u, p), b.serviceConn.Hostname, b.serviceConn.Port, b.service, u, p, b.output) {
							return
						}
					}
				}
			}(tmp)
		}
		wg.Wait()
	}
}

// call 函数调用,爆破将会调用该模块去执行操作操作
func (b *Brute) call(params ...interface{}) []reflect.Value {
	f := reflect.ValueOf(b.bruteMethod)
	if len(params) != f.Type().NumIn() {
		logger.Fatal(fmt.Sprintf("call func %v has an error", b.bruteMethod))
		return nil
	}
	args := make([]reflect.Value, len(params))
	for k, param := range params {
		if param == "" || param == 0 {
			continue
		}
		args[k] = reflect.ValueOf(param)
	}
	return f.Call(args)
}

// 结果验证
func (b *Brute) export(v []reflect.Value, host string, port int, service, user, pass string, output string) bool {
	var mutex sync.Mutex
	for _, value := range v {
		switch value.Kind() {
		case reflect.Bool:
			if value.Bool() == true {
				mutex.Lock()
				logger.Success(fmt.Sprintf("brute %v:%v success [%v:%v][%v]", host, port, user, pass, service))
				logger.JSONSave(host, logger.WeakPassSave, service, map[string]string{user: pass})
				mutex.Unlock()
				return true
			}
		}
	}
	return false
}
