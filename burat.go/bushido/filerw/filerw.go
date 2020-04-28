package filerw

import(
  "os"
)

type file struct {
  id      string
  path    string
}

type File interface {
  Id()                string
  Path()              string
  Read(length int, offset int)    ([]byte, error)
  Write(data []byte, offset int)  (int, error)
}

func NewFile(id string, path string) *file {
  f := &file {}
  f.id = id
  f.path = path
  return f
}

func (f *file) Id() string { return f.id }

func (f *file) Path() string { return f.path }

func (f *file) Read(length int, offset int) ([]byte, error) {
  data := make([]byte, length)
	file, err := os.OpenFile(f.path, os.O_RDWR|os.O_CREATE, 0755)
  if err != nil { return nil, err }
	file.ReadAt(data, int64(offset))
  if err := file.Close(); err != nil { return nil, err }
	return data, nil
}

func (f *file) Write(data []byte, offset int) (int, error) {
  file, err := os.OpenFile(f.path, os.O_RDWR|os.O_CREATE, 0755)
  if err != nil { return 0, err }
	length, err := file.WriteAt(data, int64(offset))
	if err := file.Close(); err != nil { return 0, err }
  return length, nil
}
