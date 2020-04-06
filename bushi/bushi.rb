require 'base64'
require 'paho-mqtt'
require_relative 'burat'

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

burat = BuRat.new

mqtt_topics = {
	:nil										=> "/bu/nil",
	:bushi									=> "/bu/bushi/#{burat.id}",
	:remoteshell						=> "/bu/bushi/#{burat.id}/bushido/remoteshell/+",
	:remoteshell_cmd_open		=> "/bu/bushi/#{burat.id}/bushido/remoteshell/+/cmd/open",
	:remoteshell_cmd_close	=> "/bu/bushi/#{burat.id}/bushido/remoteshell/+/cmd/close",
	:remoteshell_cmd_write	=> "/bu/bushi/#{burat.id}/bushido/remoteshell/+/cmd/write",
	:remoteshell_evt_read		=> "/bu/bushi/#{burat.id}/bushido/remoteshell/+/evt/read",
	:remoteshell_evt_write	=> "/bu/bushi/#{burat.id}/bushido/remoteshell/+/evt/write",
	:remoteshell_evt_error	=> "/bu/bushi/#{burat.id}/bushido/remoteshell/+/evt/error",
	:filerw									=> "/bu/bushi/#{burat.id}/bushido/filerw/+",
	:filerw_cmd_open				=> "/bu/bushi/#{burat.id}/bushido/filerw/+/cmd/open",
	:filerw_cmd_close				=> "/bu/bushi/#{burat.id}/bushido/filerw/+/cmd/close",
	:filerw_cmd_read				=> "/bu/bushi/#{burat.id}/bushido/filerw/+/cmd/read",
	:filerw_cmd_write				=> "/bu/bushi/#{burat.id}/bushido/filerw/+/cmd/write",
	:filerw_evt_read				=> "/bu/bushi/#{burat.id}/bushido/filerw/+/evt/read",
	:filerw_evt_write				=> "/bu/bushi/#{burat.id}/bushido/filerw/+/evt/write",
	:filerw_evt_error				=> "/bu/bushi/#{burat.id}/bushido/filerw/+/evt/error"
}

cipher = OpenSSL::Cipher::AES.new(128, :CTR)
burat.internals[:aes].config({
	:key_length => 128,
	:mode => :CTR,
	:key => cipher.random_key,
	:iv => cipher.random_iv
})

burat.internals[:rsa].config({
	:encoded_key => key
})

burat.internals[:digest].config({
	:digest => 'md5'
})

burat.internals[:mqtt].host = 'localhost'
burat.internals[:mqtt].port = 1883
burat.internals[:mqtt].persistent = true
burat.internals[:mqtt].blocking = true
burat.internals[:mqtt].reconnect_limit = 3
burat.internals[:mqtt].reconnect_delay = 60
burat.internals[:mqtt].will_topic = mqtt_topics[:bushi]
burat.internals[:mqtt].will_payload = Base64.encode64(burat.internals[:rsa].encrypt(burat.internals[:serialization].serialize(burat.profile)))
burat.internals[:mqtt].will_qos = 2
burat.internals[:mqtt].will_retain = true

burat.internals[:mqtt].on_connack do
	burat.status = :online
	packet = burat.profile
	packet = burat.internals[:serialization].serialize(packet)
	packet = burat.internals[:rsa].encrypt(packet)
	packet = Base64.encode64(packet)
	burat.internals[:mqtt].publish(mqtt_topics[:bushi], packet, true, 2)
	Thread.new {
		loop do
			burat.internals[:mqtt].publish(mqtt_topics[:nil], 'nil', false, 2)
			sleep burat.internals[:mqtt].keep_alive
		end
	}
end

# remoteshell commands
burat.add_topic_callback(mqtt_topics[:remoteshell_cmd_open]) do |message|
	packet = burat.deseen(message.payload)
	burat.bushido[:remoteshell].open(packet['id'], packet['shell'])
end

burat.add_topic_callback(mqtt_topics[:remoteshell_cmd_close]) do |message|
	packet = burat.deseen(message.payload)
	burat.bushido[:remoteshell].close(packet['id'])
end

burat.add_topic_callback(mqtt_topics[:remoteshell_cmd_write]) do |message|
	packet = burat.deseen(message.payload)
	burat.bushido[:remoteshell].write(packet['id'], packet['data'])
end

# filerw commands
burat.add_topic_callback(mqtt_topics[:filerw_cmd_open]) do |message|
	packet = burat.deseen(message.payload)
	burat.bushido[:filerw].open(packet['id'], packet['path'], packet['mode'], packet['size'])
end

burat.add_topic_callback(mqtt_topics[:filerw_cmd_close]) do |message|
	packet = burat.deseen(message.payload)
	burat.bushido[:filerw].close(packet['id'])
end

burat.add_topic_callback(mqtt_topics[:filerw_cmd_read]) do |message|
	packet = burat.deseen(message.payload)
	burat.bushido[:filerw].read(packet['id'], packet['length'])
end

burat.add_topic_callback(mqtt_topics[:filerw_cmd_write]) do |message|
	packet = burat.deseen(message.payload)
	burat.bushido[:filerw].write(packet['id'], packet['data'])
end

# remoteshell events
burat.bushido[:remoteshell].on :open do |id|
  puts "remoteshell.open #{id}"
	remoteshell = burat.bushido[:remoteshell].remoteshells.find { |remoteshell| remoteshell.id == id }
	packet = {
		:id			=> id,
		:shell	=> remoteshell.shell
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:remoteshell]
	burat.publish(id, topic, packet, true, 2)
end

burat.bushido[:remoteshell].on :close do |id|
	puts "remoteshell.close #{id}"
	topic = mqtt_topics[:remoteshell]
	burat.publish(id, topic, nil, true, 2)
end

burat.bushido[:remoteshell].on :read do |id, data|
  puts "remoteshell.read #{id} #{data}"
	packet = {
		:id			=> id,
		:data		=> data
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:remoteshell_evt_read]
	burat.publish(id, topic, packet, false, 2)
end

burat.bushido[:remoteshell].on :write do |id, data|
  puts "remoteshell.write #{id} #{data}"
	packet = {
		:id			=> id,
		:data		=> data
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:remoteshell_evt_write]
	burat.publish(id, topic, packet, false, 2)
end

burat.bushido[:remoteshell].on :error do |id, error|
  puts "remoteshell.error #{id} #{error}"
	packet = {
		:id			=> id,
		:error	=> error
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:remoteshell_evt_error]
	burat.publish(id, topic, packet, false, 2)
end

# filerw events
burat.bushido[:filerw].on :open do |id|
  puts "filerw.open #{id}"
	file = burat.bushido[:filerw].files.find { |file| file.id == id }
	packet = {
		:id				=> id,
		:path			=> file.path,
		:mode			=> file.mode,
		:size			=> file.size,
		:bytesio	=> file.bytesio
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:filerw]
	burat.publish(id, topic, packet, true, 2)
end

burat.bushido[:filerw].on :close do |id|
	puts "filerw.close #{id}"
	topic = mqtt_topics[:filerw]
	burat.publish(id, topic, nil, true, 2)
end

burat.bushido[:filerw].on :read do |id, data|
	puts "filerw.read #{id} #{data}"
	packet = {
		:id			=> id,
		:data		=> data
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:filerw_evt_read]
	burat.publish(id, topic, packet, false, 2)

	file = burat.bushido[:filerw].files.find { |file| file.id == id }
	packet = {
		:id			=> id,
		:path		=> file.path,
		:mode		=> file.mode,
		:size		=> file.size,
		:bytesio	=> file.bytesio
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:filerw]
	burat.publish(id, topic, packet, true, 2)
end

burat.bushido[:filerw].on :write do |id, length|
  puts "filerw.read #{id} #{length}"
	packet = {
		:id			=> id,
		:length		=> length
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:filerw_evt_write]
	burat.publish(id, topic, packet, false, 2)

	file = burat.bushido[:filerw].files.find { |file| file.id == id }
	packet = {
		:id			=> id,
		:path		=> file.path,
		:mode		=> file.mode,
		:size		=> file.size,
		:bytesio	=> file.bytesio
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:filerw]
	burat.publish(id, topic, packet, true, 2)
end

burat.bushido[:filerw].on :error do |id, error|
  puts "filerw.error #{id} #{error}"
	packet = {
		:id			=> id,
		:error	=> error
	}
	packet = burat.seen(packet)
	topic = mqtt_topics[:filerw_evt_error]
	burat.publish(id, topic, packet, false, 2)
end

burat.internals[:mqtt].connect(
	burat.internals[:mqtt].host,
	burat.internals[:mqtt].port,
	burat.internals[:mqtt].keep_alive,
	burat.internals[:mqtt].persistent,
	burat.internals[:mqtt].blocking
)

burat.internals[:mqtt].subscribe(["#", 2])

loop do
	burat.internals[:mqtt].loop_read
	burat.internals[:mqtt].loop_write
end
