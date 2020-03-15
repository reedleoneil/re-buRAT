require_relative 'bushi'

bushi = Bushi.new

mqtt_topics = {
	:shinobi => "test"
}

bushi.bushido[:mqtt].host = 'localhost'
bushi.bushido[:mqtt].port = 1883
bushi.bushido[:mqtt].persistent = true
bushi.bushido[:mqtt].blocking = true
bushi.bushido[:mqtt].reconnect_limit = 3
bushi.bushido[:mqtt].reconnect_delay = 60
#bushi.bushido[:mqtt].will_topic = mqtt_topics[:shinobi]
#bushi.bushido[:mqtt].will_payload = Base64.encode64(Encryption::AES.encrypt(Serialization.serialize(shinobi)))
#bushi.bushido[:mqtt].will_qos = 2
#bushi.bushido[:mqtt].will_retain = false

bushi.bushido[:mqtt].on_connack do
	bushi.status = :online
end

# bushi.bushido[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_open]) do |packet|
# 	bushi.bushido[:remoteshell].open(packet.id, packet.shell)
# end

# remoteshell
bushi.bushido[:remoteshell].on :open do |id|
  puts "open #{id}"
	packet = {
		:id => id
	}
	bushi.bushido[:mqtt].publish(mqtt_topics[:shinobi], packet, true, 1)
end

bushi.bushido[:remoteshell].on :close do |id|
	puts "close #{id}"
  bushi.bushido[:mqtt].publish(mqtt_topics[:shinobi], nil, true, 1)
end

bushi.bushido[:remoteshell].on :read do |id, data|
  puts "read #{id} #{data}"
end

bushi.bushido[:remoteshell].on :write do |id, data|
  puts "write #{id} #{data}"
end

bushi.bushido[:remoteshell].on :error do |id, error|
  puts "error #{id} #{error}"
end

# filerw
bushi.bushido[:filerw].on :open do |id|
  puts "open #{id}"
	packet = {
		:id => id
	}
	bushi.bushido[:mqtt].publish(mqtt_topics[:shinobi], packet, true, 1)
end

bushi.bushido[:filerw].on :close do |id|
	puts "close #{id}"
  bushi.bushido[:mqtt].publish(mqtt_topics[:shinobi], nil, true, 1)
end

bushi.bushido[:filerw].on :read do |id, data|
  puts "read #{id} #{data}"
end

bushi.bushido[:filerw].on :write do |id, lenght|
  puts "write #{id} #{lenght}"
end

bushi.bushido[:filerw].on :error do |id, error|
  puts "error #{id} #{error}"
end

bushi.bushido[:mqtt].connect(bushi.bushido[:mqtt].host, bushi.bushido[:mqtt].port, bushi.bushido[:mqtt].keep_alive, bushi.bushido[:mqtt].persistent, bushi.bushido[:mqtt].blocking)

#bushi.bushido[:remoteshell].open('531', 'bash')
#bushi.bushido[:remoteshell].write('531','whoami')
#bushi.bushido[:remoteshell].close('531')

bushi.bushido[:filerw].open(456, 'test', :write, 100)
bushi.bushido[:filerw].write(456, 'hi')
bushi.bushido[:filerw].write(456, 'hellow')
puts bushi.bushido[:filerw].files[0].bytesio

bushi.bushido[:filerw].open(123, 'test', :read, 100)
bushi.bushido[:filerw].read(123, 4)
bushi.bushido[:filerw].read(123, 4)
puts bushi.bushido[:filerw].files[0].bytesio

bushi.bushido[:filerw].close(456)
bushi.bushido[:filerw].close(123)

test = { :test => 'hi' }
s = bushi.bushido[:serialization].serialize(test)
puts s
d = bushi.bushido[:serialization].deserialize(s)
puts d

bushi.bushido[:digest].config({
	:digest => "md5"
})
puts bushi.bushido[:digest].digest(s)

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

puts bushi.bushido[:aes].encrypt(s)

bushi.bushido[:rsa].config({
  :key_size => 2048
})

puts bushi.bushido[:rsa].encrypt(s)

loop do
	bushi.bushido[:mqtt].loop_read
	bushi.bushido[:mqtt].loop_write
end
