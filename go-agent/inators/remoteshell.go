package remoteshell

import (
	"os/exec"
)

var RemoteShell []Cmd

type RemoteShell interface {
	RemoteShells() []Cmd
	Open(shell string)
	Close(pid int)
	Write(pid int, data string)
}

type RemoteShell struct {
	onOpen		func(pid int, shell string)
	onClose		func(pid int)			
	onRead		func(pid int, data string)	
	onWrite		func(pid int, data string)	
	onError		func(pid int, error string)	
}

func NewRemoteShell() RemoteShell {
	return remoteshell
}

func (o *ClientOptions) RemoteShells() []Cmd {
	return remoteShells
}

func (o *ClientOptions) Open(shell string) {
	
}

func (o *ClientOptions) Close(pid int) {

}

func (o *ClientOptions) Write(pid int, data string) {

}