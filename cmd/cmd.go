package cmd

import (
	"Yasso/core/flag"
	"Yasso/core/logger"
	"os"
)

func Execute() {
	file, err := os.OpenFile(logger.LogFile, os.O_APPEND|os.O_CREATE|os.O_SYNC, 0666)
	if err != nil {
		logger.Fatal("open logger file has an error", err.Error())
		return
	}
	defer file.Close()
	flag.Execute()
}
