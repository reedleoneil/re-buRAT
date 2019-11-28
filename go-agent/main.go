package main

import (
	"fmt"
	"go-agent/inators/remoteshell"
)
	

func main() {
    fmt.Println("hello world")
	r := remoteshell.NewRemoteShell()
	r.Open("cmd.exe")
	r.On(remoteshell.Open, func () { fmt.Println("hi") })
}