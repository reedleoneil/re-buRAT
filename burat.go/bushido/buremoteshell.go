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
  onError       func (id string, error string)
}

type BuRemoteShell interface {
  RemoteShells()  []remoteshell.RemoteShell
  OnOpen(id string)
  OnClose(id string)
  OnRead(id string, data string)
  OnWrite(id string, data string)
  OnError(id string, error string)
  Open(id string, shell string)
  Close(id string)
  Write(id string, data string)
}

func NewBuRemoteShell() *buRemoteShell {
  r := &buRemoteShell {}
  r.onOpen = func (id string) { fmt.Printf("remoteshell@onOpen id=%s", id) }
  r.onClose = func (id string) { fmt.Printf("remoteshell@onClose id=%s", id) }
  r.onRead = func (id string, data string) { fmt.Printf("remoteshell@onRead id=%s data=%s", id, data) }
  r.onWrite = func (id string, data string) { fmt.Printf("remoteshell@onWrite id=%s data=%s", id, data) }
  return r
}

func (r *buRemoteShell) RemoteShells() []remoteshell.RemoteShell {
	return r.remoteShells
}

func (r *buRemoteShell) OnOpen(callback func (id string)) {
  r.onOpen = callback
}

func (r *buRemoteShell) OnClose(callback func (id string)) {
  r.onClose = callback
}

func (r *buRemoteShell) OnRead(callback func (id string, data string)) {
  r.onRead= callback
}

func (r *buRemoteShell) OnWrite(callback func (id string, data string)) {
  r.onWrite = callback
}

func (r *buRemoteShell) OnError(callback func (id string, error string)) {
  r.onError = callback
}

func (r *buRemoteShell) Open(id string, shell string) {
  rs := remoteshell.NewRemoteShell(id, shell)
  rs.OnRead(func (data string) {
    r.onRead(id, data)
  })
  rs.OnError(func (error string) {
    r.onError(id, error)
  })
  rs.Open()
  r.remoteShells = append(r.remoteShells, rs)
  r.onOpen(id)
}

func (r *buRemoteShell) Close(id string) {
  x := 0
  for i := range r.remoteShells {
		if r.remoteShells[i].Id() == id {
			r.remoteShells[i].Close()
      x = i
			r.onClose(id)
		}
	}
  r.remoteShells = append(r.remoteShells[:x], r.remoteShells[x+1:]...)
}

func (r *buRemoteShell) Write(id string, data string) {
  for i := range r.remoteShells {
    if r.remoteShells[i].Id() == id {
      r.remoteShells[i].Write(data)
      r.onWrite(id, data)
    }
  }
}
