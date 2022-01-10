package main

import "Yasso/cmd"

func main() {
	_ = cmd.JsonOut{
		Host:  "123456",
		Ports: []int{25, 12, 33, 14, 55, 80, 443},
		WeakPass: []map[string]map[string]string{
			{"redis": map[string]string{"admin": "123456"}},
		},
		WebHosts: nil,
	}
}
