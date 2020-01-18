/*package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
)

func main() {
	// docker build current directory
	cmdName := "cmd.exe"
	cmdArgs := []string{"google.com", "-t"}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating StdoutPipe for Cmd", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(cmdReader)
	go func() {
		for scanner.Scan() {
			fmt.Printf("docker build out | %s\n", scanner.Text())
		}
	}()

	err = cmd.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error starting Cmd", err)
		os.Exit(1)
	}

	err = cmd.Wait()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error waiting for Cmd", err)
		os.Exit(1)
	}

	for {
		//do nothing
	}
}

package main

import (
	"os"
	"fmt"
	"io"
)

func main() {
	f, err := os.OpenFile("notes.txt", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		fmt.Println(err)
	}

	buffer := make([]byte, 1024)
	n, err := f.ReadAt(buffer, 0)

	if err != nil && err != io.EOF {
                 panic(err)
    }

    fmt.Println(string(buffer[:n]))
	
	b := []byte("putang ina mo")
	fmt.Println(b)

	x, err := f.WriteAt(b, 0)
	if err != nil && err != io.EOF {
                 panic(err)
    }

	fmt.Println(x)

	if err := f.Close(); err != nil {
		fmt.Println(err)
	}
}
*/

package main

import (
	"go-agent/inators/remoteshell"
	"fmt"
	"time"
)
func main() {
	rs := remoteshell.NewRemoteShellInator()
	rs.OnRead(func (pid int, data string) {
		fmt.Printf("red@read %d %s\n", pid, data)
	})
	rs.OnError(func (pid int, error string) {
		fmt.Printf("red@error %d %s\n", pid, error)
	})
	rs.Open("bash")
	rs.Open("bash")
	time.Sleep(5000 * time.Millisecond)
	rss := rs.RemoteShells()
	for _, r := range rss {
		rs.Write(r.Cmd.Process.Pid, "ping google.com\n\r")
	}
	time.Sleep(5000 * time.Millisecond)
	for _, r := range rss {
		rs.Close(r.Cmd.Process.Pid)
	}
	for {
		// do nothing
	}
}
