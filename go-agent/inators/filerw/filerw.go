package filerw

import(
	"os"
	"fmt"
)

type FileReadWriteInator interface {
	Read(file string, length int, offset int)
	Write(file string, data []byte, offset int)
	OnRead(callback func (file string, length int, offset int, data []byte))
	OnWrite(callback func (file string, data []byte, offset int, length int))
	OnError(callback func (file string, mode string, error string))
}

type fileReadWriteInator struct {
	onRead		func (file string, length int, offset int, data []byte)
	onWrite		func (file string, data []byte, offset int, length int)
	onError		func (file string, mode string, error string)
}

func NewFileReadWriteInator() *fileReadWriteInator {
	frw := &fileReadWriteInator {
		onRead 	: func (file string, length int, offset int, data []byte) { fmt.Println("filerw@read ") },
		onWrite : func (file string, data []byte, offset int, length int) { fmt.Println("filerw@write ") },
		onError	: func (file string, mode string, error string) { fmt.Println("filerw@error ") },
	}
	return frw
}

func (frw *fileReadWriteInator) Read(file string, length int, offset int) {
	data := make([]byte, length)
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		frw.onError(file, "READ", err.Error())
	}
	f.ReadAt(data, int64(offset))
	if err := f.Close(); err != nil {
		frw.onError(file, "READ", err.Error())
	}
	frw.onRead(file, length, offset, data)
}

func (frw *fileReadWriteInator) Write(file string, data []byte, offset int) {
	f, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		frw.onError(file, "WRITE", err.Error())
	}
	length, err := f.WriteAt(data, int64(offset))
	if err != nil {
		frw.onError(file, "WRITE", err.Error())
	}
	if err := f.Close(); err != nil {
		frw.onError(file, "WRITE", err.Error())
	}
	frw.onWrite(file, data, offset, length)
}

func (frw *fileReadWriteInator) OnRead(callback func (file string, length int, offset int, data []byte)) {
	frw.onRead = callback
}

func (frw *fileReadWriteInator) OnWrite(callback func (file string, data []byte, offset int, length int)) {
	frw.onWrite = callback
}

func (frw *fileReadWriteInator) OnError(callback func (file string, mode string, error string)) {
	frw.onError = callback
}

