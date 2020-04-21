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
  onError       func (id string, error string)
}

type BuFileRW interface {
  Files() []filerw.File
  OnOpen(func (id string))
  OnClose(func (id string))
  OnRead(func (id string, data []byte))
  OnWrite(func (id string, length int))
  OnError(func (id string, error string))
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
  b.onError = func (id string, error string) { fmt.Printf("filerw@onWrite id=%s length=%d", id, error) }
  return b
}

func (b *bufilerw) Files() []filerw.File {
	return b.files
}

func (b *bufilerw) OnOpen(callback func (id string)) {
  b.onOpen = callback
}

func (b *bufilerw) OnClose(callback func (id string)) {
  b.onClose = callback
}

func (b *bufilerw) OnRead(callback func (id string, data []byte)) {
  b.onRead= callback
}

func (b *bufilerw) OnWrite(callback func (id string, length int)) {
  b.onWrite = callback
}

func (b *bufilerw) OnError(callback func (id string, error string)) {
  b.onError = callback
}

func (b *bufilerw) Open(id string, path string, mode string, size int) {
  f := filerw.NewFile(id, path, mode, size)
  b.files = append(b.files, f)
  b.onOpen(id)
}

func (b *bufilerw) Close(id string) {
  x := 0
  for i := range b.files {
		if b.files[i].Id() == id {
      x = i
			b.onClose(id)
		}
	}
  b.files = append(b.files[:x], b.files[x+1:]...)
}

func (b *bufilerw) Read(id string, length int) {
  for i := range b.files {
		if b.files[i].Id() == id {
      data := b.files[i].Read(length)
			b.onRead(id, data)
		}
	}
}

func (b *bufilerw) Write(id string, data []byte) {
  for i := range b.files {
    if b.files[i].Id() == id {
      length := b.files[i].Write(data)
      b.onWrite(id, length)
    }
  }
}
