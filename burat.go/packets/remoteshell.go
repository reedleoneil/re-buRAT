package packets

type RemoteShellPacket struct {
	Id			string	`msgpack:"id"`
	Shell 	string	`msgpack:"shell"`
}

type RemoteShellWritePacket struct {
	Id			string	`msgpack:"id"`
	Data		string	`msgpack:"data"`
}

type RemoteShellOnOpenPacket struct {
	Id 			string	`msgpack:"id"`
}

type RemoteShellOnClosePacket struct {
	Id 			string	`msgpack:"id"`
}

type RemoteShellOnReadPacket struct {
	Id			string	`msgpack:"id"`
	Data		string	`msgpack:"data"`
}

type RemoteShellOnWritePacket struct {
	Id			string	`msgpack:"id"`
	Data		string	`msgpack:"data"`
}

type RemoteShellOnErrorPacket struct {
	Id			string	`msgpack:"id"`
	Error		string	`msgpack:"error"`
}
