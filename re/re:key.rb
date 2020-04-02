require 'paho-mqtt'

require_relative 'internals/encryption'

re = {
	:internals => {
		:mqtt           => PahoMqtt::Client.new,
		:rsa            => Internals::RSA.new
	}
}

re[:internals][:rsa].config({
  :encoded_key => File.read('bu.key')
})

re[:internals][:mqtt].host = 'localhost'
re[:internals][:mqtt].port = 1883
re[:internals][:mqtt].persistent = true
re[:internals][:mqtt].blocking = true
re[:internals][:mqtt].reconnect_limit = 3
re[:internals][:mqtt].reconnect_delay = 60

re[:internals][:mqtt].on_connack do
  re[:internals][:mqtt].publish('/bu/public_key', re[:internals][:rsa].public_key, true, 2)
end

re[:internals][:mqtt].connect(
  re[:internals][:mqtt].host,
  re[:internals][:mqtt].port,
  re[:internals][:mqtt].keep_alive,
  re[:internals][:mqtt].persistent,
  re[:internals][:mqtt].blocking
)

loop do
	re[:internals][:mqtt].loop_read
	re[:internals][:mqtt].loop_write
end
