package remoteshell

import(
    "bufio"
    "io"
    "fmt"
  	"os/exec"
    "runtime"
    "strconv"
    "syscall"
)

type remoteShell struct {
  id        string
  shell     string
  onRead    func(data string)
  onError   func(error error)
  stdin	    io.WriteCloser
  stdout 	  io.ReadCloser
  stderr    io.ReadCloser
  cmd	      *exec.Cmd
}

type RemoteShell interface {
  Id()      string
  Shell()   string
  OnRead(callback func(data string))
  OnError(callback func(data error))
  Open()
  Close()
  Write(data string)
}

func NewRemoteShell(id string, shell string) *remoteShell {
  r := &remoteShell {}
  r.id = id
  r.shell = shell
  r.onRead = func(data string) { fmt.Println(data) }
  r.onError = func(error error) { fmt.Println(error) }
  return r
}

func (r *remoteShell) Id() string { return r.id }

func (r *remoteShell) Shell() string { return r.shell }

func (r *remoteShell) OnRead(callback func(data string)) { r.onRead = callback }

func (r *remoteShell) OnError(callback func(error error)) { r.onError = callback }

func (r *remoteShell) Open() {
  cmd := exec.Command(r.shell)
  cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	cmdInReader, err := cmd.StdinPipe()
	if err != nil {
		r.onError(err)
	}

	cmdOutReader, err := cmd.StdoutPipe()
	if err != nil {
		r.onError(err)
	}

	cmdErrReader, err := cmd.StderrPipe()
	if err != nil {
		r.onError(err)
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
			r.onRead(errScanner.Text())
		}
	}()

	err = cmd.Start()
	if err != nil {
		r.onError(err)
	}

  r.stdin = cmdInReader
  r.stdout = cmdOutReader
  r.stderr = cmdErrReader
  r.cmd = cmd
}

func (r *remoteShell) Close() {
  switch os := runtime.GOOS; os {
	case "linux":
    exec.Command("pkill", "-P", strconv.Itoa(r.cmd.Process.Pid)).Run()
  case "windows":
    exec.Command("TASKKILL", "/T", "/F", "/PID", strconv.Itoa(r.cmd.Process.Pid)).Run()
	}
  r.cmd.Process.Kill()
}

func (r *remoteShell) Write(data string) {
  io.WriteString(r.stdin, data + "\n")
}
