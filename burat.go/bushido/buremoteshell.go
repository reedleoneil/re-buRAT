package bushido

import(
  "fmt"

  "./remoteshell"
)

type buRemoteShell struct {
  remoteShells  []remoteshell.RemoteShell
  onOpen        func (id string)
  onClose       func (id string)
  onRead        func (id string, data string)
  onWrite       func (id string, data string)
  onError       func (id string, error error)
}

type BuRemoteShell interface {
  RemoteShells()  []remoteshell.RemoteShell
  OnOpen(func (id string))
  OnClose(func (id string))
  OnRead(func (id string, data string))
  OnWrite(func (id string, data string))
  OnError(func (id string, error error))
  Open(id string, shell string)
  Close(id string)
  Write(id string, data string)
}

func NewBuRemoteShell() *buRemoteShell {
  b := &buRemoteShell {}
  b.onOpen = func (id string) { fmt.Printf("remoteshell@onOpen id=%s", id) }
  b.onClose = func (id string) { fmt.Printf("remoteshell@onClose id=%s", id) }
  b.onRead = func (id string, data string) { fmt.Printf("remoteshell@onRead id=%s data=%s", id, data) }
  b.onWrite = func (id string, data string) { fmt.Printf("remoteshell@onWrite id=%s data=%s", id, data) }
  b.onError = func (id string, error error) { fmt.Printf("filerw@onWrite id=%s length=%d", id, error.Error()) }
  return b
}

func (b *buRemoteShell) RemoteShells() []remoteshell.RemoteShell { return b.remoteShells }

func (b *buRemoteShell) OnOpen(handler func (id string)) { b.onOpen = handler }

func (b *buRemoteShell) OnClose(handler func (id string)) { b.onClose = handler }

func (b *buRemoteShell) OnRead(handler func (id string, data string)) { b.onRead= handler }

func (b *buRemoteShell) OnWrite(handler func (id string, data string)) { b.onWrite = handler }

func (b *buRemoteShell) OnError(handler func (id string, error error)) { b.onError = handler }

func (b *buRemoteShell) Open(id string, shell string) {
  rs := remoteshell.NewRemoteShell(id, shell)
  rs.OnRead(func (data string) {
    b.onRead(id, data)
  })
  rs.OnError(func (error error) {
    b.onError(id, error)
  })
  rs.Open()
  b.remoteShells = append(b.remoteShells, rs)
  b.onOpen(id)
}

func (b *buRemoteShell) Close(id string) {
  var index int
  for i := range b.remoteShells {
		if b.remoteShells[i].Id() == id {
			b.remoteShells[i].Close()
      index = i
			b.onClose(id)
		}
	}
  b.remoteShells = append(b.remoteShells[:index], b.remoteShells[index+1:]...)
}

func (b *buRemoteShell) Write(id string, data string) {
  for i := range b.remoteShells {
    if b.remoteShells[i].Id() == id {
      b.remoteShells[i].Write(data)
      b.onWrite(id, data)
    }
  }
}
