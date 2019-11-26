require 'paho-mqtt'
require 'msgpacker'

client = PahoMqtt::Client.new
client.connect('localhost', 1883, client.keep_alive, true, true)
client.subscribe(["#", 2])

client.on_message do |p|
	puts "Topic: #{p.topic}\nPayload: #{MessagePack.unpack p.payload}\nQoS: #{p.qos}"
end

loop do
  client.loop_write
  client.loop_read
end
