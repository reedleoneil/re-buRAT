package packets

type FileReadWriteReadPacket struct {
	File 		string	`msgpack:"file"`
	Length 	int			`msgpack:"length"`
	Offset 	int			`msgpack:"offset"`
	Data 		[]byte	`msgpack:"data"`
}

type FileReadWriteWritePacket struct {
	File 		string	`msgpack:"file"`
	Data 	[]byte
	Offset 	int			`msgpack:"offset"`
	//Length 	int			`msgpack:"length"`
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
