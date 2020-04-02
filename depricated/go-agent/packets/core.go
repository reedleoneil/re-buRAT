package packets

type IdentificationPacket struct {
	Id			string	`msgpack:"id"`
	Host		string	`msgpack:"host"`
	User		string	`msgpack:"user"`
	Status	string	`msgpack:"status"`
}
