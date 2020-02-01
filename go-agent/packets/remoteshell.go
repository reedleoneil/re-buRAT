package packets

type RemoteShellOpenPacket struct {
	Shell		string	`msgpack:"shell"`
}

type RemoteShellClosePacket struct {
	Pid			int			`msgpack:"pid"`
}

type RemoteShellWritePacket struct {
	Pid			int			`msgpack:"pid"`
	Data		string	`msgpack:"data"`
}

type RemoteShellOnOpenPacket struct {
	Pid 		int			`msgpack:"pid"`
	Shell		string	`msgpack:"shell"`
}

type RemoteShellOnClosePacket struct {
	Pid 		int			`msgpack:"pid"`
}

type RemoteShellOnReadPacket struct {
	Pid			int			`msgpack:"pid"`
	Data		string	`msgpack:"data"`
}

type RemoteShellOnWritePacket struct {
	Pid			int			`msgpack:"pid"`
	Data		string	`msgpack:"data"`
}

type RemoteShellOnErrorPacket struct {
	Pid			int			`msgpack:"pid"`
	Error		string	`msgpack:"error"`
}
