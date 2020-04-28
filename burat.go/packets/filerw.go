package packets

type FilerwOpenPacket struct {
  Id        string  `msgpack:"id"`
  Path      string  `msgpack:"path"`
}

type FilerwClosePacket struct {
  Id        string  `msgpack:"id"`
}

type FilerwReadPacket struct {
  Id        string  `msgpack:"id"`
  Length    int     `msgpack:"length"`
  Offset    int     `msgpack:"offset"`
}

type FilerwWritePacket struct {
  Id        string  `msgpack:"id"`
	Data      []byte  `msgpack:"data"`
  Offset    int     `msgpack:"offset"`
}

type FilerwOnOpenPacket struct {
  Id        string  `msgpack:"id"`
  Path      string  `msgpack:"path"`
}

type FilerwOnClosePacket struct {
  Id        string  `msgpack:"id"`
}

type FilerwOnReadPacket struct {
	Id        string  `msgpack:"id"`
  Data      []byte  `msgpack:"data"`
  Offset    int     `msgpack:"offset"`
}

type FilerwOnWritePacket struct {
  Id        string  `msgpack:"id"`
  Length    int     `msgpack:"length"`
  Offset    int     `msgpack:"offset"`
}

type FilerwOnErrorPacket struct {
	Id        string	`msgpack:"id"`
	Error     string	`msgpack:"error"`
}
