package packets

type IdentificationPacket struct {
	Id			string	`msgpack:"id"`
	Host		string	`msgpack:"host"`
	User		string	`msgpack:"user"`
	Status	string	`msgpack:"status"`
}

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

type FileReadWriteOnReadPacket struct {
	File 		string	`msgpack:"file"`
	Length 	int			`msgpack:"length"`
	Offset 	int			`msgpack:"offset"`
	Data 		[]byte	`msgpack:"data"`
}

type FileReadWriteOnWritePacket struct {
	File 		string	`msgpack:"file"`
	//Data 	[]byte
	Offset 	int			`msgpack:"offset"`
	Length 	int			`msgpack:"length"`
}

type FileReadWriteOnErrorPacket struct {
	File 		string	`msgpack:"file"`
	Mode		string	`msgpack:"mode"`
	Error		string	`msgpack:"error"`
}
