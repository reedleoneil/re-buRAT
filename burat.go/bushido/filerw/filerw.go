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
  Read(length int)    ([]byte, error)
  Write(data []byte)  (int, error)
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

func (f *file) Read(length int) ([]byte, error) {
  data := make([]byte, length)
	file, err := os.OpenFile(f.path, os.O_RDWR|os.O_CREATE, 0755)
  if err != nil { return nil, err }
	file.ReadAt(data, int64(f.bytesio))
  if err := file.Close(); err != nil { return nil, err }
  f.bytesio += length
	return data, nil
}

func (f *file) Write(data []byte) (int, error) {
  file, err := os.OpenFile(f.path, os.O_RDWR|os.O_CREATE, 0755)
  if err != nil { return 0, err }
	length, err := file.WriteAt(data, int64(f.bytesio))
	if err := file.Close(); err != nil { return 0, err }
	f.bytesio += length
  return length, nil
}
