package main

import (
	"Yasso/cmd"
)

func init() {
	cmd.CreateLogFile("result.txt")
}

func main() {
	cmd.Execute()
}
