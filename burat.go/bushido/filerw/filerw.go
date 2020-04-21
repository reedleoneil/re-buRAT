package filerw

import(
  "os"
)

type file struct {
  id      string
  path    string
  mode    string
  size    int
  bytesio int
}

type File interface {
  Id()                string
  Path()              string
  Mode()              string
  Size()              int
  BytesIO()           int
  Read(length int)    []byte
  Write(data []byte) int
}

func NewFile(id string, path string, mode string, size int) *file {
  f := &file {}
  f.id = id
  f.path = path
  f.mode = mode
  f.size = size
  f.bytesio = 0
  return f
}

func (f *file) Id() string { return f.id }

func (f *file) Path() string { return f.path }

func (f *file) Mode() string { return f.mode }

func (f *file) Size() int { return f.size }

func (f *file) BytesIO() int { return f.bytesio }

func (f *file) Read(length int) []byte {
  data := make([]byte, length)
	file, _ := os.OpenFile(f.path, os.O_RDWR|os.O_CREATE, 0755)
	file.ReadAt(data, int64(f.bytesio))
	file.Close()
  f.bytesio += length
	return data
}

func (f *file) Write(data []byte) int {
  file, _ := os.OpenFile(f.path, os.O_RDWR|os.O_CREATE, 0755)
	length, _ := file.WriteAt(data, int64(f.bytesio))
	file.Close()
	f.bytesio += length
  return length
}
