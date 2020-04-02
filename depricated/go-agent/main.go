package main

import (
	"go-agent/packets"
	"go-agent/inators/filerw"
	"go-agent/inators/remoteshell"

	"fmt"

	"github.com/eclipse/paho.mqtt.golang"
	"github.com/vmihailenco/msgpack"
)

func main() {
	opts := mqtt.NewClientOptions().AddBroker("tcp://localhost:1883")

	c := mqtt.NewClient(opts)
	rs := remoteshell.NewRemoteShellInator()
	frw := filerw.NewFileReadWriteInator()

	rs.OnOpen(func (pid int, shell string) {
		b, _ := msgpack.Marshal(&packets.RemoteShellOnOpenPacket{Pid: pid, Shell: shell})
		c.Publish("/bu/shinobi/123D/inators/remoteshell/events/open", 0, false, b)
		fmt.Println(pid)
	})

	rs.OnClose(func (pid int) {
		b, _ := msgpack.Marshal(&packets.RemoteShellOnClosePacket{Pid: pid})
		c.Publish("/bu/shinobi/123D/inators/remoteshell/events/close", 0, false, b)
	})

	rs.OnRead(func (pid int, data string) {
		b, _ := msgpack.Marshal(&packets.RemoteShellOnReadPacket{Pid: pid, Data: data})
		c.Publish("/bu/shinobi/123D/inators/remoteshell/events/read", 0, false, b)
	})

	rs.OnWrite(func (pid int, data string) {
		b, _ := msgpack.Marshal(&packets.RemoteShellOnWritePacket{Pid: pid, Data: data})
		c.Publish("/bu/shinobi/123D/inators/remoteshell/events/write", 0, false, b)
	})

	rs.OnError(func (pid int, error string) {
		b, _ := msgpack.Marshal(&packets.RemoteShellOnErrorPacket{Pid: pid, Error: error})
		c.Publish("/bu/shinobi/123D/inators/remoteshell/events/error", 0, false, b)
	})

	frw.OnRead(func (file string, length int, offset int, data []byte) {
		b, _ := msgpack.Marshal(&packets.FileReadWriteOnReadPacket{File: file, Length: length, Offset: offset, Data: data})
		c.Publish("/bu/shinobi/123D/inators/filerw/events/read", 0, false, b)
	})

	frw.OnWrite(func (file string, data []byte, offset int, length int) {
		b, _ := msgpack.Marshal(&packets.FileReadWriteOnWritePacket{File: file, Offset: offset, Length: length})
		c.Publish("/bu/shinobi/123D/inators/filerw/events/write", 0, false, b)
	})

	frw.OnError(func (file string, mode string, error string) {
		b, _ := msgpack.Marshal(&packets.FileReadWriteOnErrorPacket{File: file, Mode: mode, Error: error})
		c.Publish("/bu/shinobi/123D/inators/filerw/events/error", 0, false, b)
	})

	rsOpenHandler := func (client mqtt.Client, msg mqtt.Message) {
		var packet packets.RemoteShellOpenPacket
		err := msgpack.Unmarshal(msg.Payload(), &packet)
		if err != nil {
			panic(err)
		} else {
			rs.Open(packet.Shell)
		}
	}

	rsCloseHandler := func (client mqtt.Client, msg mqtt.Message) {
		var packet packets.RemoteShellClosePacket
		err := msgpack.Unmarshal(msg.Payload(), &packet)
		if err != nil {
			panic(err)
		} else {
			rs.Close(packet.Pid)
		}
	}

	rslWriteHandler := func (client mqtt.Client, msg mqtt.Message) {
		var packet packets.RemoteShellWritePacket
		err := msgpack.Unmarshal(msg.Payload(), &packet)
		if err != nil {
			panic(err)
		} else {
			rs.Write(packet.Pid, packet.Data + "\n")
		}
	}

	filerwReadHandler := func (client mqtt.Client, msg mqtt.Message) {
		var packet packets.FileReadWriteReadPacket
		err := msgpack.Unmarshal(msg.Payload(), &packet)
		if err != nil {
			panic(err)
		} else {
			frw.Read(packet.File, packet.Length, packet.Offset)
		}
	}

	filerwWriteHandler := func (client mqtt.Client, msg mqtt.Message) {
		var packet packets.FileReadWriteWritePacket
		err := msgpack.Unmarshal(msg.Payload(), &packet)
		if err != nil {
			panic(err)
		} else {
			frw.Write(packet.File, packet.Data, packet.Offset)
		}
	}

	if token := c.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	} else {
		payload, _ := msgpack.Marshal(&packets.IdentificationPacket {
			Id: "123D",
			Host: "go-agent",
			User: "reedleoneil",
			Status:	"online",
		})
		c.Publish("/bu/shinobi/" + "123D", 0, false, payload)
	}

	if token := c.Subscribe("/bu/shinobi/123D/inators/remoteshell/cmds/open", 0, rsOpenHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	if token := c.Subscribe("/bu/shinobi/123D/inators/remoteshell/cmds/close", 0, rsCloseHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	if token := c.Subscribe("/bu/shinobi/123D/inators/remoteshell/cmds/write", 0, rslWriteHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	if token := c.Subscribe("/bu/shinobi/123D/inators/filerw/cmds/read", 0, filerwReadHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	if token := c.Subscribe("/bu/shinobi/123D/inators/filerw/cmds/write", 0, filerwWriteHandler); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
	}

	//Loop
	for {
		// do nothing
	}
}
