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
	:bushi									=> "/bu/bushi/#{bushi.id}",
	:remoteshell						=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+",
	:remoteshell_cmd_open		=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/cmd/open",
	:remoteshell_cmd_close	=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/cmd/close",
	:remoteshell_cmd_write	=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/cmd/write",
	:remoteshell_evt_read		=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/cmd/read",
	:remoteshell_evt_write	=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/evt/write",
	:remoteshell_evt_error	=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/+/evt/error",
	:filerw									=> "/bu/bushi/#{bushi.id}/bushido/filerw/+",
	:filerw_cmd_open				=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/cmd/open",
	:filerw_cmd_close				=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/cmd/close",
	:filerw_cmd_read				=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/cmd/read",
	:filerw_cmd_write				=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/cmd/write",
	:filerw_evt_read				=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/evt/read",
	:filerw_evt_write				=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/evt/write",
	:filerw_evt_error				=> "/bu/bushi/#{bushi.id}/bushido/filerw/+/evt/error"
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

bushi.internals[:mqtt].on_connack do
	profile[:status] = :online
	packet = profile
	packet = bushi.internals[:serialization].serialize(packet)
	packet = bushi.internals[:rsa].encrypt(packet)
	packet = Base64.encode64(packet)
	bushi.internals[:mqtt].publish(mqtt_topics[:bushi], packet, true, 2)
end

# remoteshell commands
bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_cmd_open]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:remoteshell].open(packet['id'], packet['shell'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_cmd_close]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:remoteshell].close(packet['id'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_cmd_write]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:remoteshell].write(packet['id'], packet['data'])
end

# filerw commands
bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:filerw_cmd_open]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:filerw].open(packet['id'], packet['path'], packet['mode'], packet['size'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:filerw_cmd_close]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:filerw].close(packet['id'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:filerw_cmd_read]) do |packet|
	packet = bushi.deseen(packet.payload)
	bushi.bushido[:filerw].read(packet['id'], packet['length'])
end

bushi.internals[:mqtt].add_topic_callback(mqtt_topics[:filerw_cmd_write]) do |packet|
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
	topic = mqtt_topics[:remoteshell_evt_read].dup
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
	topic = mqtt_topics[:remoteshell_evt_error].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, packet, false, 2)
end

# filerw events
bushi.bushido[:filerw].on :open do |id|
  puts "filerw.open #{id}"
	file = bushi.bushido[:filerw].files.find { |file| file.id == id }
	packet = {
		:id			=> id,
		:path		=> file.path,
		:mode		=> file.mode,
		:size		=> file.size
	}
	packet = bushi.seen(packet)
	topic = mqtt_topics[:filerw].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, packet, true, 2)
end

bushi.bushido[:filerw].on :close do |id|
	puts "filerw.close #{id}"
	topic = mqtt_topics[:filerw].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, nil, true, 2)
end

bushi.bushido[:filerw].on :read do |id, data|
	puts "filerw.read #{id} #{data}"
	packet = {
		:id			=> id,
		:data		=> data
	}
	packet = bushi.seen(packet)
	topic = mqtt_topics[:filerw_evt_read].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, packet, false, 2)

	file = bushi.bushido[:filerw].files.find { |file| file.id == id }
	packet = {
		:id			=> id,
		:path		=> file.path,
		:mode		=> file.mode,
		:size		=> file.size,
		:bytesio	=> file.bytesio
	}
	packet = bushi.seen(packet)
	topic = mqtt_topics[:filerw].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, packet, true, 2)
end

bushi.bushido[:filerw].on :write do |id, lenght|
  puts "filerw.read #{id} #{lenght}"
end

bushi.bushido[:filerw].on :error do |id, error|
  puts "filerw.error #{id} #{error}"
	packet = {
		:id			=> id,
		:error	=> error
	}
	packet = bushi.seen(packet)
	topic = mqtt_topics[:filerw_evt_error].dup
	topic['+'] = id
	bushi.internals[:mqtt].publish(topic, packet, false, 2)
end

bushi.internals[:mqtt].connect(bushi.internals[:mqtt].host, bushi.internals[:mqtt].port, bushi.internals[:mqtt].keep_alive, bushi.internals[:mqtt].persistent, bushi.internals[:mqtt].blocking)
bushi.internals[:mqtt].subscribe(["#", 2])

loop do
	bushi.internals[:mqtt].loop_read
	bushi.internals[:mqtt].loop_write
end
