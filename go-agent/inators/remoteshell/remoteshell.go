package remoteshell

import (
	"os/exec"
	"fmt"
	"bufio"
)

type RemoteShellInator interface {
	RemoteShells() []exec.Cmd
	Open(shell string)
	Close(pid int)
	Write(pid int, data string)
	OnOpen(callback func (pid int, shell string))
	OnClose(callback func (pid int, shell string))
	OnRead(callback func (pid int, shell string))
	OnWrite(callback func (pid int, shell string))
	OnError(callback func (pid int, shell string))
}

type remoteShellInator struct {
	remoteShells	[]exec.Cmd
	onOpen			func(pid int, shell string)
	onClose			func(pid int)			
	onRead			func(pid int, data string)	
	onWrite			func(pid int, data string)	
	onError			func(pid int, error string)	
}

func NewRemoteShellInator() *remoteShellInator {
	r := &remoteShellInator {}
	r.onOpen = func(pid int, shell string) {
		fmt.Printf("remoteshell@open %d %s\n", pid, shell)
	}
	r.onClose = func(pid int) {
		fmt.Printf("remoteshell@close %d\n", pid)
	}
	r.onRead = func(pid int, data string) {
		fmt.Printf("remoteshell@read %d %s\n", pid, data)
	}
	r.onWrite = func(pid int, data string) {
		fmt.Printf("remoteshell@write %d %s\n", pid, data)
	}
	r.onError = func(pid int, error string) {
		fmt.Printf("remoteshell@error %d %s\n", pid, error)
	}
	return r
}

func (r *remoteShellInator) RemoteShells() []exec.Cmd {
	return r.remoteShells
}

func (r *remoteShellInator) Open(shell string) {
	cmd := exec.Command(shell)

	cmdOutReader, err := cmd.StdoutPipe()
	if err != nil {
		r.onError(cmd.Process.Pid, err.Error())
	}

	cmdErrReader, err := cmd.StderrPipe()
	if err != nil {
		r.onError(cmd.Process.Pid, err.Error())
	}

	outScanner := bufio.NewScanner(cmdOutReader)
	go func() {
		for outScanner.Scan() {
			r.onRead(cmd.Process.Pid, outScanner.Text())
		}
	}()

	errScanner := bufio.NewScanner(cmdErrReader)
	go func() {
		for errScanner.Scan() {
			r.onError(cmd.Process.Pid, errScanner.Text())
		}
	}()

	err = cmd.Start()
	if err != nil {
		r.onError(cmd.Process.Pid, err.Error())
	}

	r.remoteShells = append(r.remoteShells, *cmd)
	r.onOpen(cmd.Process.Pid, cmd.Path)
}

func (r *remoteShellInator) Close(pid int) {
	for i := range r.remoteShells {
		if r.remoteShells[i].Process.Pid == pid {
			//kill
		}
	}
}

func (r *remoteShellInator) Write(pid int, data string) {
	for i := range r.remoteShells {
		if r.remoteShells[i].Process.Pid == pid {
			//write
		}
	}
}

func (r *remoteShellInator) OnOpen(callback func (pid int, shell string)) {
	r.onOpen = callback
}

func (r *remoteShellInator) OnClose(callback func (pid int)) {
	r.onClose = callback
}

func (r *remoteShellInator) OnRead(callback func (pid int, shell string)) {
	r.onRead = callback 
}

func (r *remoteShellInator) OnWrite(callback func (pid int, data string)) {
	r.onWrite = callback 
}

func (r *remoteShellInator) OnError(callback func (pid int, error string)) {
	r.onError = callback 
}

