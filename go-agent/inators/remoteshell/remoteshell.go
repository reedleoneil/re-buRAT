package remoteshell

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

const (
	Open = 1
	Close = 2
	Read = 3
	Write = 4
	Error = 5 
)

type Event byte
type EventCallback func()

type RemoteShell interface {
	RemoteShells() []string
	Open(shell string)
	Close(pid int)
	Write(pid int, data string)
	On(event Event, callback EventCallback)
}

type remoteShell struct {
	onOpen		func(pid int, shell string)
	onClose		func(pid int)			
	onRead		func(pid int, data string)	
	onWrite		func(pid int, data string)	
	onError		func(pid int, error string)	
}

func NewRemoteShell() RemoteShell {
	r := &remoteShell{}
	return r
}

func (o *remoteShell) RemoteShells() []string {
	s := make([]string, 0)
	return s
}

func (o *remoteShell) Open(shell string) {
	cmd := exec.Command("whoami")
	cmd.Stdin = strings.NewReader("some input")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("in all caps: %q\n", out.String())
}

func (o *remoteShell) Close(pid int) {

}

func (o *remoteShell) Write(pid int, data string) {

}

func (o *remoteShell) On(event Event, callback EventCallback) {
	if event == Open {
	
	} else if event == Close {
	
	} else if event == Read {
	
	} else if event == Write {
	
	} else if event == Error {
	
	}
}