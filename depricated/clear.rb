require 'paho-mqtt'

client = PahoMqtt::Client.new

client.on_message do |message|
  puts message.topic
  client.publish(message.topic, nil, true, 2)
end

client.connect('localhost', 1883, client.keep_alive, true, true)
client.subscribe(["#", 2])

loop do
  client.loop_write
  client.loop_read
end
