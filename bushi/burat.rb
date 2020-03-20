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
	:remoteshell					=> "/bu/bushi/#{bushi.id}/bushido/remoteshell",
	:remoteshell_open			=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/cmds/open",
	:remoteshell_close		=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/cmds/close",
	:remoteshell_write		=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/cmds/write",
	:remoteshell_onopen		=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/events/open",
	:remoteshell_onclose	=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/events/close",
	:remoteshell_onread		=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/events/read",
	:remoteshell_onwrite	=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/events/write",
	:remoteshell_onerror	=> "/bu/bushi/#{bushi.id}/bushido/remoteshell/events/error",
	:filerw								=> "/bu/bushi/#{bushi.id}/bushido/filerw",
	:filerw_open					=> "/bu/bushi/#{bushi.id}/bushido/filerw/cmds/open",
	:filerw_close					=> "/bu/bushi/#{bushi.id}/bushido/filerw/cmds/close",
	:filerw_read					=> "/bu/bushi/#{bushi.id}/bushido/filerw/cmds/read",
	:filerw_write					=> "/bu/bushi/#{bushi.id}/bushido/filerw/cmds/write",
	:filerw_onopen				=> "/bu/bushi/#{bushi.id}/bushido/filerw/events/open",
	:filerw_onclose				=> "/bu/bushi/#{bushi.id}/bushido/filerw/events/close",
	:filerw_onread				=> "/bu/bushi/#{bushi.id}/bushido/filerw/events/read",
	:filerw_onwrite				=> "/bu/bushi/#{bushi.id}/bushido/filerw/events/write",
	:filerw_error					=> "/bu/bushi/#{bushi.id}/bushido/filerw/events/error"
}

cipher = OpenSSL::Cipher::AES.new(128, :CTR)
aes = {
  :key => cipher.random_key,
  :iv => cipher.random_iv,
}

bushi.bushido[:aes].config({
	:key_lenght => 128,
	:mode => :CTR,
	:key => aes[:key],
	:iv => aes[:iv]
})

bushi.bushido[:rsa].config({
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

bushi.bushido[:mqtt].host = 'localhost'
bushi.bushido[:mqtt].port = 1883
bushi.bushido[:mqtt].persistent = true
bushi.bushido[:mqtt].blocking = true
bushi.bushido[:mqtt].reconnect_limit = 3
bushi.bushido[:mqtt].reconnect_delay = 60
bushi.bushido[:mqtt].will_topic = mqtt_topics[:bushi]
bushi.bushido[:mqtt].will_payload = Base64.encode64(bushi.bushido[:rsa].encrypt(bushi.bushido[:serialization].serialize(profile)))
bushi.bushido[:mqtt].will_qos = 2
bushi.bushido[:mqtt].will_retain = false

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
# s = bushi.bushido[:serialization].serialize(test)
# puts s
# d = bushi.bushido[:serialization].deserialize(s)
# puts d
#
# bushi.bushido[:digest].config({
# 	:digest => "md5"
# })
# puts bushi.bushido[:digest].digest(s)
#
#
# puts bushi.bushido[:aes].encrypt(s)
#
# bushi.bushido[:rsa].config({
#   :key_size => 2048
# })
#
# puts bushi.bushido[:rsa].encrypt(s)

bushi.bushido[:mqtt].on_connack do
	profile[:status] = :online
	packet = profile
	packet = bushi.bushido[:serialization].serialize(packet)
	packet = bushi.bushido[:rsa].encrypt(packet)
	packet = Base64.encode64(packet)
	bushi.bushido[:mqtt].publish(mqtt_topics[:bushi], packet, false, 2)
end

# remoteshell commands
bushi.bushido[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_open]) do |packet|
	packet = bushi.bushido[:aes].decrypt(packet.payload)
	packet = bushi.bushido[:serialization].deserialize(packet)
	bushi.bushido[:remoteshell].open(packet['id'], packet['shell'])
end

bushi.bushido[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_close]) do |packet|
	packet = bushi.bushido[:aes].decrypt(packet.payload)
	packet = bushi.bushido[:serialization].deserialize(packet)
	bushi.bushido[:remoteshell].close(packet['id'])
end

bushi.bushido[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_write]) do |packet|
	packet = bushi.bushido[:aes].decrypt(packet.payload)
	packet = bushi.bushido[:serialization].deserialize(packet)
	bushi.bushido[:remoteshell].write(packet['id'], packet['data'])
end

# remoteshell
bushi.bushido[:remoteshell].on :open do |id|
  puts "remoteshell.open #{id}"
end

bushi.bushido[:remoteshell].on :close do |id|
	puts "remoteshell.close #{id}"
end

bushi.bushido[:remoteshell].on :read do |id, data|
  puts "remoteshell.read #{id} #{data}"
end

bushi.bushido[:remoteshell].on :write do |id, data|
  puts "remoteshell.write #{id} #{data}"
end

bushi.bushido[:remoteshell].on :error do |id, error|
  puts "remoteshell.error #{id} #{error}"
end

# filerw
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

bushi.bushido[:mqtt].connect(bushi.bushido[:mqtt].host, bushi.bushido[:mqtt].port, bushi.bushido[:mqtt].keep_alive, bushi.bushido[:mqtt].persistent, bushi.bushido[:mqtt].blocking)
bushi.bushido[:mqtt].subscribe(["#", 2])

loop do
	bushi.bushido[:mqtt].loop_read
	bushi.bushido[:mqtt].loop_write
end
