package main

import (
	"Yasso/cmd"
)

func init() {
	cmd.CreateLogFile("Yasso.log")
}

func main() {
	cmd.Execute()
}
