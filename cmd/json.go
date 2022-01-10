package cmd

import (
	"encoding/json"
	"fmt"
	"os"
)

// 输出json格式数据

type JsonOut struct {
	Host     string                         `json:"HostName"`
	Ports    []int                          `json:"Ports"`
	WeakPass []map[string]map[string]string `json:"WeakPass"`
	WebHosts []string                       `json:"Web"`
}

func Out(filename string, js []JsonOut) {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		Println(fmt.Sprintf("[!] create json file failed %v", err))
		return
	}
	b, err := json.Marshal(&js)
	if err != nil {
		Println(fmt.Sprintf("[!] json marshal is failed %v", err))
		return
	}
	_, _ = file.Write(b)
}
