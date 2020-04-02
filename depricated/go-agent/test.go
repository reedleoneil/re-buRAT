package main

import(
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

func main() {
	opts := mqtt.NewClientOptions().AddBroker("tcp://localhost:1883")
	c := mqtt.NewClient(opts)
	if token := c.Connect(); token.Wait() && token.Error() != nil {
		panic(token.Error())
	} 
	//b, _ := msgpack.Marshal(&RemoteShellOpenPacket{Shell: "bash"})
	//c.Publish("/rs/open", 0, false, b)
	
	//b, _ := msgpack.Marshal(&RemoteShellClosePacket{Pid: 14621})
	//c.Publish("/rs/close", 0, false, b)

	b, _ := msgpack.Marshal(&RemoteShellWritePacket{Pid: 16560, Data: "whoami"})
	c.Publish("/rs/write", 0, false, b)
}
