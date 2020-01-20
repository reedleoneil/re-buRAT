package main

import (
	"go-agent/inators/filerw"
	"go-agent/inators/remoteshell"

	"fmt"
	
	"github.com/eclipse/paho.mqtt.golang"
	"github.com/vmihailenco/msgpack"
)

type RemoteShellOpenPacket struct {
	Shell	string
}

type RemoteShellClosePacket struct {
	Pid	int
}

type RemoteShellWritePacket struct {
	Pid	int
	Data	string
}

type RemoteShellOnOpenPacket struct {
	Pid 	int
	Shell	string
}

type RemoteShellOnClosePacket struct {
	Pid 	int
}

type RemoteShellOnReadPacket struct {
	Pid 	int
	Data	string
}

type RemoteShellOnWritePacket struct {
	Pid 	int
	Data	string
}

type RemoteShellOnErrorPacket struct {
	Pid 	int
	Error	string
}

type FileReadWriteOnReadPacket struct {
	File 	string
	Length 	int
	Offset 	int
	Data 	[]byte
}

type FileReadWriteOnWritePacket struct {
	File 	string
	//Data 	[]byte
	Offset 	int
	Length 	int
}

type FileReadWriteOnErrorPacket struct {
	File 	string
	Mode	string
	Error	string
}

func main() {
	opts := mqtt.NewClientOptions().AddBroker("tcp://localhost:1883")

	c := mqtt.NewClient(opts)
	rs := remoteshell.NewRemoteShellInator()
	frw := filerw.NewFileReadWriteInator()

	rs.OnOpen(func (pid int, shell string) {
		b, _ := msgpack.Marshal(&RemoteShellOnOpenPacket{Pid: pid, Shell: shell})
		c.Publish("/rs/onopen", 0, false, b)
		fmt.Println(pid)
	})

	rs.OnClose(func (pid int) {
		b, _ := msgpack.Marshal(&RemoteShellOnClosePacket{Pid: pid})
		c.Publish("/rs/onclose", 0, false, b)
	})

	rs.OnRead(func (pid int, data string) {
		b, _ := msgpack.Marshal(&RemoteShellOnReadPacket{Pid: pid, Data: data})
		c.Publish("/rs/onread", 0, false, b)
	})

	rs.OnWrite(func (pid int, data string) {
		b, _ := msgpack.Marshal(&RemoteShellOnWritePacket{Pid: pid, Data: data})
		c.Publish("/rs/onwrite", 0, false, b)
	})

	rs.OnError(func (pid int, error string) {
		b, _ := msgpack.Marshal(&RemoteShellOnErrorPacket{Pid: pid, Error: error})
		c.Publish("/rs/onerror", 0, false, b)
	})

	frw.OnRead(func (file string, length int, offset int, data []byte) {
		b, _ := msgpack.Marshal(&FileReadWriteOnReadPacket{File: file, Length: length, Offset: offset, Data: data})
		c.Publish("/frw/onread", 0, false, b)
	})

	frw.OnWrite(func (file string, data []byte, offset int, length int) {
		b, _ := msgpack.Marshal(&FileReadWriteOnWritePacket{File: file, Offset: offset, Length: length})
		c.Publish("/frw/onwrite", 0, false, b)
	})

	frw.OnError(func (file string, mode string, error string) {
		b, _ := msgpack.Marshal(&FileReadWriteOnErrorPacket{File: file, Mode: mode, Error: error})
		c.Publish("/frw/onerror", 0, false, b)
	})

	rsOpenHandler := func (client mqtt.Client, msg mqtt.Message) {
		var packet RemoteShellOpenPacket
		err := msgpack.Unmarshal(msg.Payload(), &packet)
		if err != nil {
			panic(err)
		} else {
			rs.Open(packet.Shell)
		}
	}

	rsCloseHandler := func (client mqtt.Client, msg mqtt.Message) {
		var packet RemoteShellClosePacket
		err := msgpack.Unmarshal(msg.Payload(), &packet)
		if err != nil {
			panic(err)
		} else {
			rs.Close(packet.Pid)
		}
	}

	rslWriteHandler := func (client mqtt.Client, msg mqtt.Message) {
		var packet RemoteShellWritePacket
		err := msgpack.Unmarshal(msg.Payload(), &packet)
		if err != nil {
			panic(err)
		} else {
			rs.Write(packet.Pid, packet.Data + "\n")
		}
	}

	filerwReadHandler := func (client mqtt.Client, msg mqtt.Message) {
		//frw.Read(string(msg.Payload()))
		//frw.Read("test.txt", 1024, 4)
	}

	filerwWriteHandler := func (client mqtt.Client, msg mqtt.Message) {
		//frw.Write(string(msg.Payload()))
		//frw.Write("test.txt", []byte("ONE OK ROCK"), 11)
	}

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
