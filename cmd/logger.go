package cmd

import (
	"fmt"
	"os"
)

var FileName string

func Println(s string) {
	fmt.Println(s)
	file, err := os.OpenFile(FileName, os.O_APPEND|os.O_WRONLY, 0666)
	defer file.Close()
	if err != nil {
		fmt.Println("[!] open log file failed", err)
		return
	}
	_, _ = file.WriteString("\n" + s)
}

func CreateLogFile(filename string) {
	FileName = filename
	_, err := os.Stat(filename)
	if err != nil {
		file, err := os.Create(filename)
		if err != nil {
			fmt.Println("[!] create log file failed", err)
			return
		}
		defer file.Close()
	}
}
