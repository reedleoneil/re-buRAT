require 'paho-mqtt'

re = {
	:internals => {
		:mqtt           => PahoMqtt::Client.new
	}
}

re[:internals][:mqtt].host = 'localhost'
re[:internals][:mqtt].port = 1883
re[:internals][:mqtt].persistent = true
re[:internals][:mqtt].blocking = true
re[:internals][:mqtt].reconnect_limit = 3
re[:internals][:mqtt].reconnect_delay = 60

re[:internals][:mqtt].on_message do |message|
  puts message.topic
  re[:internals][:mqtt].publish(message.topic, nil, true, 2)
end

re[:internals][:mqtt].connect(
  re[:internals][:mqtt].host,
  re[:internals][:mqtt].port,
  re[:internals][:mqtt].keep_alive,
  re[:internals][:mqtt].persistent,
  re[:internals][:mqtt].blocking
)

re[:internals][:mqtt].subscribe(['/bu/#', 2])

loop do
	re[:internals][:mqtt].loop_read
	re[:internals][:mqtt].loop_write
end
