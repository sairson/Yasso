package logger

import (
	"Yasso/config"
	"encoding/json"
	"fmt"
	"github.com/gookit/color"
	"os"
	"sync"
)

var (
	Cyan       = color.Cyan.Render
	Red        = color.Red.Render
	LightGreen = color.Style{color.Green, color.OpBold}.Render
	LightRed   = color.Style{color.Red, color.OpBold}.Render
)

const (
	PortSave          = 1
	HostSave          = 2
	WeakPassSave      = 3
	InformationSave   = 4
	VulnerabilitySave = 5
)

var LogFile string
var LogJson string
var mutex sync.Mutex

func Info(in ...interface{}) {
	mutex.Lock()
	var all []interface{}
	for k, v := range in {
		if k == len(in)-1 {
			all = append(all, fmt.Sprintf("%v", v))
		} else {
			all = append(all, fmt.Sprintf("%v ", v))
		}
	}
	fmt.Println(fmt.Sprintf("[%s] ", Cyan("*")) + fmt.Sprint(all...))

	file, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_SYNC, 0666)
	if err != nil {
		Fatal("open file has an error", err.Error())
		return
	}
	defer file.Close()
	_, _ = file.WriteString(fmt.Sprintf("[*] " + fmt.Sprint(all...) + "\n"))
	mutex.Unlock()
}

func Success(in ...interface{}) {
	mutex.Lock()
	var all []interface{}
	for k, v := range in {
		if k == len(in)-1 {
			all = append(all, fmt.Sprintf("%v", v))
		} else {
			all = append(all, fmt.Sprintf("%v ", v))
		}
	}
	fmt.Println(fmt.Sprintf("[%s] ", LightGreen("+")) + fmt.Sprint(all...))

	file, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_SYNC, 0666)
	if err != nil {
		Fatal("open file has an error", err.Error())
		return
	}
	defer file.Close()
	_, err = file.WriteString(fmt.Sprintf("[+] " + fmt.Sprint(all...) + "\n"))
	mutex.Unlock()
}

func Fatal(in ...interface{}) {
	var all []interface{}
	for k, v := range in {
		if k == len(in)-1 {
			all = append(all, fmt.Sprintf("%v", v))
		} else {
			all = append(all, fmt.Sprintf("%v ", v))
		}
	}
	fmt.Println(fmt.Sprintf("[%s] ", Red("#")) + fmt.Sprint(all...))
}

// JSONSave 保存json格式数据
func JSONSave(host string, t int, in ...interface{}) {
	if LogJson != "" {
		switch t {
		case VulnerabilitySave:
			for _, v := range config.JSONSave {
				// 服务存在
				if v.Host == host {
					v.Vulnerability = append(v.Vulnerability, in[0].(string))
				}
			}
		case PortSave:
			// 端口存储
			var flag = false
			for _, v := range config.JSONSave {
				// 服务存在
				if v.Host == host {
					v.Port = in[0].([]int) // 将端口存储
					flag = true
				}
			}
			if flag == false {
				config.JSONSave = append(config.JSONSave, &config.Format{
					Host: host,
				})
				for _, v := range config.JSONSave {
					// 服务存在
					if v.Host == host {
						v.Port = in[0].([]int) // 将端口存储
						flag = true
					}
				}
			}
		case HostSave:
			// 主机存储
			config.JSONSave = append(config.JSONSave, &config.Format{
				Host: host,
			})
		case WeakPassSave:
			// 这里存储json的服务弱口令
			for _, v := range config.JSONSave {
				// 服务名称已经有了,那么将口令加到它的WeakPass种
				// 如果主机之前也是存活的
				if v.Host == host {
					// 遍历主机的服务列表
					var flag = false
					for _, value := range v.Service {
						if value.Name == in[0].(string) { // 服务名
							value.WeakPass = append(value.WeakPass, in[1].(map[string]string))
							flag = true // 证明服务存在
						}
					}
					// 证明host存在
					if flag == false {
						v.Service = append(v.Service, &config.Service{
							Name:     in[0].(string), //服务名
							WeakPass: []map[string]string{in[1].(map[string]string)},
						})
					}
					// 证明host存在
					if flag == false {
						v.Service = append(v.Service, &config.Service{
							Name:     in[0].(string), //服务名
							WeakPass: []map[string]string{in[1].(map[string]string)},
						})
					}
				}
			}
		case 4:
			// 这里information字段
			for _, v := range config.JSONSave {
				// 服务名称已经有了,那么将口令加到它的WeakPass种
				// 如果主机之前也是存活的
				if v.Host == host {
					// 遍历主机的服务列表
					var flag = false
					for _, value := range v.Service {
						if value.Name == in[0].(string) { // 服务名
							value.Information = append(value.Information, in[1].(string))
							flag = true // 证明服务存在
						}
					}
					// 证明host存在
					if flag == false {
						v.Service = append(v.Service, &config.Service{
							Name:        in[0].(string), //服务名
							Information: []string{in[1].(string)},
						})
					}
				}
			}
		}
		// 将以json格式保存,文件将会保存全局变量存储的结果集
	}
}

func LoggerSave() {
	if LogJson != "" {
		body, err := json.Marshal(config.JSONSave)
		if err != nil {
			Fatal("save json marshal failed", err.Error())
			return
		}
		filePtr, err := os.Create(LogJson)
		if err != nil {
			fmt.Println("文件创建失败", err.Error())
			return
		}
		defer filePtr.Close()
		// 创建Json编码器
		_, _ = filePtr.Write(body)
	}
}
