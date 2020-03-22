require 'base64'
require 'paho-mqtt'
require_relative 'bushi'

key = ''
client = PahoMqtt::Client.new
client.on_message do |message|
	key = message.payload
	client.disconnect
end
client.connect('localhost', 1883)
client.subscribe(["/bu/public_key", 2])
while key == ''
	sleep 1
end

bushi = Bushi.new

mqtt_topics = {
	:public_key						=> "/bu/public_key",
	:bushi								=> "/bu/bushi/#{bushi.id}",
	:remoteshell					=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+",
	:remoteshell_open			=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/cmds/open",
	:remoteshell_close		=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/cmds/close",
	:remoteshell_write		=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/cmds/write",
	:remoteshell_onread		=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/events/read",
	:remoteshell_onwrite	=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/events/write",
	:remoteshell_onerror	=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/events/error",
	:filerw								=> "/bu/bushi/#{bushi.id}/bushido/filerw/+",
	:filerw_open					=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/cmds/open",
	:filerw_close					=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/cmds/close",
	:filerw_read					=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/cmds/read",
	:filerw_write					=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/cmds/write",
	:filerw_onread				=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/events/read",
	:filerw_onwrite				=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/events/write",
	:filerw_error					=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/events/error"
}

cipher = OpenSSL::Cipher::AES.new(128, :CTR)
aes = {
  :key => cipher.random_key,
  :iv => cipher.random_iv,
}

bushi.internals[:aes].config({
	:key_lenght => 128,
	:mode => :CTR,
	:key => aes[:key],
	:iv => aes[:iv]
})

bushi.internals[:rsa].config({
	:encoded_key => key
})

profile = {
	:id => bushi.id,
	:host => bushi.host,
	:os => bushi.os,
	:ip => bushi.ip,
	:status => bushi.status,
	:aes => aes
}

bushi.internals[:mqtt].host = 'localhost'
bushi.internals[:mqtt].port = 1883
bushi.internals[:mqtt].persistent = true
bushi.internals[:mqtt].blocking = true
bushi.internals[:mqtt].reconnect_limit = 3
bushi.internals[:mqtt].reconnect_delay = 60
bushi.internals[:mqtt].will_topic = mqtt_topics[:bushi]
bushi.internals[:mqtt].will_payload = Base64.encode64(bushi.internals[:rsa].encrypt(bushi.internals[:serialization].serialize(profile)))
bushi.internals[:mqtt].will_qos = 2
bushi.internals[:mqtt].will_retain = true

#bushi.bushido[:remoteshell].open('531', 'bash')
#bushi.bushido[:remoteshell].write('531','whoami')
#bushi.bushido[:remoteshell].close('531')

# bushi.bushido[:filerw].open(456, 'test', :write, 100)
# bushi.bushido[:filerw].write(456, 'hi')
# bushi.bushido[:filerw].write(456, 'hellow')
# puts bushi.bushido[:filerw].files[0].bytesio
#
# bushi.bushido[:filerw].open(123, 'test', :read, 100)
# bushi.bushido[:filerw].read(123, 4)
# bushi.bushido[:filerw].read(123, 4)
# puts bushi.bushido[:filerw].files[0].bytesio
#
# bushi.bushido[:filerw].close(456)
# bushi.bushido[:filerw].close(123)

# test = { :test => 'hi' }
# s = bushi.internals[:serialization].serialize(test)
# puts s
# d = bushi.internals[:serialization].deserialize(s)
# puts d
#
# bushi.internals[:digest].config({
# 	:digest => "md5"
# })
# puts bushi.internals[:digest].digest(s)
#
#
# puts bushi.internals[:aes].encrypt(s)
#
# bushi.internals[:rsa].config({
#   :key_size => 2048
# })
#
# puts bushi.internals[:rsa].encrypt(s)

bushi.internals[:mqtt].on_connack do
	profile[:status] = :online
	packet = profile
	packet = bushi.internals[:serialization].serialize(packet)
	packet = bushi.internals[:rsa].encrypt(packet)
	packet = Base64.encode64(packet)
	bushi.internals[:mqtt].publish(mqtt_topics[:bushi], packet, false, 2)
end

# remoteshell commands
bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_open]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:remoteshell].open(packet['id'], packet['shell'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_close]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:remoteshell].close(packet['id'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_write]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:remoteshell].write(packet['id'], packet['data'])
end

# filerw commands
bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:filerw_open]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:filerw].open(packet['id'], packet['path'], packet['mode'], packet['size'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:filerw_close]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:filerw].close(packet['id'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:filerw_read]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:filerw].read(packet['id'], packet['length'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:filerw_write]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:filerw].write(packet['id'], packet['data'])
end

# remoteshell events
bushi.bushido[:remoteshell].on :open do |id|
  puts "remoteshell.open #{id}"
	remoteshell = bushi.bushido[:remoteshell].remoteshells.find { |remoteshell| remoteshell.id == id }
	packet = {
		:id			=> id,
		:shell	=> remoteshell.shell
	}
	packet = bushi.seen(packet)
	topic = mqtt_topics[:remoteshell].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, packet, true, 2)
end

bushi.bushido[:remoteshell].on :close do |id|
	puts "remoteshell.close #{id}"
	topic = mqtt_topics[:remoteshell].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, nil, true, 2)
end

bushi.bushido[:remoteshell].on :read do |id, data|
  puts "remoteshell.read #{id} #{data}"
	packet = {
		:id			=> id,
		:data		=> data
	}
	packet = bushi.seen(packet)
	topic = mqtt_topics[:remoteshell_onread].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, packet, false, 2)
end

bushi.bushido[:remoteshell].on :write do |id, data|
  puts "remoteshell.write #{id} #{data}"
end

bushi.bushido[:remoteshell].on :error do |id, error|
  puts "remoteshell.error #{id} #{error}"
	packet = {
		:id			=> id,
		:error	=> error
	}
	packet = bushi.seen(packet)
	topic = mqtt_topics[:remoteshell_onerror].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, packet, false, 2)
end

# filerw events
bushi.bushido[:filerw].on :open do |id|
  puts "filerw.open #{id}"
end

bushi.bushido[:filerw].on :close do |id|
	puts "filerw.close #{id}"
end

bushi.bushido[:filerw].on :read do |id, data|
	puts "filerw.read #{id} #{data}"
end

bushi.bushido[:filerw].on :write do |id, lenght|
  puts "filerw.read #{id} #{lenght}"
end

bushi.bushido[:filerw].on :error do |id, error|
  puts "filerw.error #{id} #{error}"
end

bushi.internals[:mqtt].connect(bushi.internals[:mqtt].host, bushi.internals[:mqtt].port, bushi.internals[:mqtt].keep_alive, bushi.internals[:mqtt].persistent, bushi.internals[:mqtt].blocking)
bushi.internals[:mqtt].subscribe(["#", 2])

loop do
	bushi.internals[:mqtt].loop_read
	bushi.internals[:mqtt].loop_write
end
