package remoteshell

import (
	"os"
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
	r := &remoteShellInator { }
	return r
}

func (r *remoteShellInator) RemoteShells() []exec.Cmd {
	return r.remoteShells
}

func (r *remoteShellInator) Open(shell string) {
	cmd := exec.Command(shell)

	cmdOutReader, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating StdoutPipe for Cmd", err)
	}

	cmdErrReader, err := cmd.StderrPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating StdoutPipe for Cmd", err)
	}

	outScanner := bufio.NewScanner(cmdOutReader)
	go func() {
		for outScanner.Scan() {
			fmt.Printf("out | %s\n", outScanner.Text())
		}
	}()

	errScanner := bufio.NewScanner(cmdErrReader)
	go func() {
		for errScanner.Scan() {
			fmt.Printf("out | %s\n", errScanner.Text())
		}
	}()

	err = cmd.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error starting Cmd", err)
	}

	err = cmd.Wait()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error waiting for Cmd", err)
	}

	r.remoteShells = append(r.remoteShells, *cmd)
}

func (r *remoteShellInator) Close(pid int) {
	for i := range r.remoteShells {
		if r.remoteShells[i].Process.Pid == pid {
			// Found!
		}
	}
}

func (r *remoteShellInator) Write(pid int, data []byte) {
	for i := range r.remoteShells {
		if r.remoteShells[i].Process.Pid == pid {
			// Found!
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

