package internals

import (
  "github.com/vmihailenco/msgpack"
)

type serialization struct {

}

type Serialization interface {
  Serialize(packet interface{}) []byte
  Deserialize(data []byte, packet interface{})
}

func NewSerialization() *serialization {
	s := &serialization {}
	return s
}

func (s *serialization) Serialize(packet interface{}) []byte {
  b, _ := msgpack.Marshal(packet)
	return b
}

func (s *serialization) Deserialize(data []byte, packet interface{}) {
  msgpack.Unmarshal(data, packet)
}
