package remoteshell

import(
  	"os/exec"
    "syscall"
    "bufio"
    "io"
    "fmt"
)

type remoteShell struct {
  id        string
  shell     string
  onRead    func(data string)
  onError   func(error string)
  stdin	    io.WriteCloser
  stdout 	  io.ReadCloser
  stderr    io.ReadCloser
  cmd	      *exec.Cmd
}

type RemoteShell interface {
  Id()      string
  Shell()   string
  OnRead(callback func(data string))
  OnError(callback func(data string))
  Open()
  Close()
  Write(data string)
}

func NewRemoteShell(id string, shell string) *remoteShell {
  r := &remoteShell {
    id: id,
    shell: shell,
  }
  r.onRead = func(data string) { fmt.Println(data) }
  r.onError = func(error string) { fmt.Println(error) }
  return r
}

func (r *remoteShell) Id() string {
  return r.id
}

func (r *remoteShell) Shell() string {
  return r.shell
}

func (r *remoteShell) OnRead(callback func(data string)) {
  r.onRead = callback
}

func (r *remoteShell) OnError(callback func(error string)) {
  r.onError = callback
}

func (r *remoteShell) Open() {
  cmd := exec.Command(r.shell)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	cmdInReader, err := cmd.StdinPipe()
	if err != nil {
		r.onError(err.Error())
	}

	cmdOutReader, err := cmd.StdoutPipe()
	if err != nil {
		r.onError(err.Error())
	}

	cmdErrReader, err := cmd.StderrPipe()
	if err != nil {
		r.onError(err.Error())
	}

	outScanner := bufio.NewScanner(cmdOutReader)
	go func() {
		for outScanner.Scan() {
			r.onRead(outScanner.Text())
		}
	}()

	errScanner := bufio.NewScanner(cmdErrReader)
	go func() {
		for errScanner.Scan() {
			r.onError(errScanner.Text())
		}
	}()

	err = cmd.Start()
	if err != nil {
		r.onError(err.Error())
	}

  r.stdin = cmdInReader
  r.stdout = cmdOutReader
  r.stderr = cmdErrReader
  r.cmd = cmd
}

func (r *remoteShell) Close() {
  pgid, err := syscall.Getpgid(r.cmd.Process.Pid)
  if err == nil {
      syscall.Kill(-pgid, syscall.SIGKILL)
  }
}

func (r *remoteShell) Write(data string) {
  io.WriteString(r.stdin, data + "\n")
}
