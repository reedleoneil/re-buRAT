package packets

type FilerwOpenPacket struct {
  Id        string  `msgpack:"id"`
  Path      string  `msgpack:"path"`
  Mode      string  `msgpack:"mode"`
  Size      int     `msgpack:"size"`
  BytesIO   int     `msgpack:"bytesio"`
}

type FilerwClosePacket struct {
  Id        string  `msgpack:"id"`
}

type FilerwReadPacket struct {
  Id        string  `msgpack:"id"`
  Length    int     `msgpack:"length"`
}

type FilerwWritePacket struct {
  Id        string  `msgpack:"id"`
	Data      []byte  `msgpack:"data"`
}

type FilerwOnOpenPacket struct {
  Id        string  `msgpack:"id"`
  Path      string  `msgpack:"path"`
  Mode      string  `msgpack:"mode"`
  Size      int     `msgpack:"size"`
  BytesIO   int     `msgpack:"bytesio"`
}

type FilerwOnClosePacket struct {
  Id        string  `msgpack:"id"`
}

type FilerwOnReadPacket struct {
	Id        string  `msgpack:"id"`
  Data      []byte  `msgpack:"data"`
}

type FilerwOnWritePacket struct {
  Id        string  `msgpack:"id"`
  Length    int     `msgpack:"length"`
}

type FilerwOnErrorPacket struct {
	Id        string	`msgpack:"id"`
	Error     string	`msgpack:"error"`
}
