package main

import (
	"go-agent/inators/remoteshell"
	"go-agent/inators/filerw"
	"fmt"
	"time"
	"strconv"
	
	"github.com/eclipse/paho.mqtt.golang"
)

func main() {
	//RemoteShell
	rs := remoteshell.NewRemoteShellInator()
	rs.OnRead(func (pid int, data string) {
		fmt.Printf("red@read %d %s\n", pid, data)
	})
	rs.OnError(func (pid int, error string) {
		fmt.Printf("red@error %d %s\n", pid, error)
	})
	rs.Open("bash")
	rs.Open("bash")
	time.Sleep(100 * time.Millisecond)
	rss := rs.RemoteShells()
	for _, r := range rss {
		rs.Write(r.Cmd.Process.Pid, "ping google.com\n\r")
	}
	time.Sleep(100 * time.Millisecond)
	for _, r := range rss {
		rs.Close(r.Cmd.Process.Pid)
	}

	//FileReadWrite
	frw := filerw.NewFileReadWriteInator()

	frw.OnRead(func (file string, length int, offset int, data []byte) {
		fmt.Printf("redfrw@read %s %d %d %s\n", file, length, offset, string(data))
	})

	frw.OnWrite(func (file string, data []byte, offset int, length int) {
		fmt.Printf("redfrw@write %s %s %d %d\n", file, data, offset, length)
	})

	frw.Read("test.txt", 1024, 4)
	frw.Write("test.txt", []byte("ONE OK ROCK"), 11)

	//MQTT Client
	rsOpenHandler := func (client mqtt.Client, msg mqtt.Message) {
		rs.Open(string(msg.Payload()))
	}

	rsCloseHandler := func (client mqtt.Client, msg mqtt.Message) {
		byteToInt, _ := strconv.Atoi(string(msg.Payload()))
		rs.Close(byteToInt)
	}

	rslWriteHandler := func (client mqtt.Client, msg mqtt.Message) {
		byteToInt, _ := strconv.Atoi(string(msg.Payload()))
		cmd := "whoami\n\r"
		rs.Write(byteToInt, cmd)
	}

	filerwReadHandler := func (client mqtt.Client, msg mqtt.Message) {
		//frw.Read(string(msg.Payload()))
	}

	filerwWriteHandler := func (client mqtt.Client, msg mqtt.Message) {
		//frw.Write(string(msg.Payload()))
	}

	opts := mqtt.NewClientOptions().AddBroker("tcp://localhost:1883")

	c := mqtt.NewClient(opts)
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	}

	if token := c.Subscribe("/rs/open", 0, rsOpenHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	if token := c.Subscribe("/rs/close", 0, rsCloseHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	if token := c.Subscribe("/rs/write", 0, rslWriteHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	if token := c.Subscribe("/frw/read", 0, filerwReadHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	if token := c.Subscribe("/frw/write", 0, filerwWriteHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	//Loop
	for {
		// do nothing
	}
}
