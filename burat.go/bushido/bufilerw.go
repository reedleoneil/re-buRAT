package bushido

import (
  "fmt"

  "./filerw"
)

type bufilerw struct {
  files         []filerw.File
  onOpen        func (id string)
  onClose       func (id string)
  onRead        func (id string, data []byte)
  onWrite       func (id string, length int)
  onError       func (id string, error error)
}

type BuFileRW interface {
  Files() []filerw.File
  OnOpen(func (id string))
  OnClose(func (id string))
  OnRead(func (id string, data []byte))
  OnWrite(func (id string, length int))
  OnError(func (id string, error error))
  Open(id string, path string, mode string, size int)
  Close(id string)
  Read(id string, length int)
  Write(id string, data []byte)
}

func NewBuFileRW() *bufilerw {
  b := &bufilerw {}
  b.onOpen = func (id string) { fmt.Printf("filerw@onOpen id=%s", id) }
  b.onClose = func (id string) { fmt.Printf("filerw@onClose id=%s", id) }
  b.onRead = func (id string, data []byte) { fmt.Printf("filerw@onRead id=%s data=%s", id, data) }
  b.onWrite = func (id string, length int) { fmt.Printf("filerw@onWrite id=%s length=%d", id, length) }
  b.onError = func (id string, error error) { fmt.Printf("filerw@onWrite id=%s length=%d", id, error.Error()) }
  return b
}

func (b *bufilerw) Files() []filerw.File { return b.files }

func (b *bufilerw) OnOpen(handler func (id string)) { b.onOpen = handler }

func (b *bufilerw) OnClose(handler func (id string)) { b.onClose = handler }

func (b *bufilerw) OnRead(handler func (id string, data []byte)) { b.onRead= handler }

func (b *bufilerw) OnWrite(handler func (id string, length int)) { b.onWrite = handler }

func (b *bufilerw) OnError(handler func (id string, error error)) { b.onError = handler }

func (b *bufilerw) Open(id string, path string, mode string, size int) {
  f := filerw.NewFile(id, path, mode, size)
  b.files = append(b.files, f)
  b.onOpen(id)
}

func (b *bufilerw) Close(id string) {
  var index int
  for i := range b.files {
		if b.files[i].Id() == id {
      index = i
			b.onClose(id)
		}
	}
  b.files = append(b.files[:index], b.files[index+1:]...)
}

func (b *bufilerw) Read(id string, length int) {
  for i := range b.files {
		if b.files[i].Id() == id {
      data, err := b.files[i].Read(length)
      if err != nil {
        b.onError(id, err)
      } else {
        b.onRead(id, data)
      }
		}
	}
}

func (b *bufilerw) Write(id string, data []byte) {
  for i := range b.files {
    if b.files[i].Id() == id {
      length, err := b.files[i].Write(data)
      if err != nil {
        b.onError(id ,err)
      } else {
        b.onWrite(id, length)
      }
    }
  }
}
