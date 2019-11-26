require 'paho-mqtt'
require 'msgpacker'
require 'ostruct'
require 'securerandom'

require_relative "inators/remote_shell"
require_relative "inators/file_rw"

agent = {
	id: SecureRandom.uuid,
	host: `uname -a`,
	user: `whoami`,
	inators: [
		:remote_shell,
		:file_rw
	]
}

client = PahoMqtt::Client.new
rs_inator = RemoteShellInator.new
frw_inator = FileReadWriteInator.new

client.on_connack do
	client.publish("/bu/agents/#{agent[:id]}", agent.to_msgpack, false, 1)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/remote_shell/cmds/open") do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	rs_inator.open(packet.shell)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/remote_shell/cmds/close") do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	rs_inator.close(packet.pid)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/remote_shell/cmds/write") do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	rs_inator.write(packet.pid, packet.data)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/file_rw/cmds/read") do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	frw_inator.read(packet.file, packet.length, packet.offset)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/file_rw/cmds/write") do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	frw_inator.write(packet.file, packet.data, packet.offset)
end

client.on_message do |p|
	#puts "Topic: #{p.topic}\nPayload: #{p.payload}\nQoS: #{p.qos}"
end

rs_inator.on :open do |pid, shell|
	packet = {
		pid: pid,
		shell: shell
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/open", packet.to_msgpack, false, 1)
	remote_shells = []
	rs_inator.remote_shells.each do |remote_shell|
		remote_shells << { :pid => remote_shell[2].pid, :shell => remote_shell[4] }
	end
	packet = {
		remote_shells: remote_shells
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell", packet.to_msgpack, false, 1)
end

rs_inator.on :close do |pid|
	packet = {
		pid: pid
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/close", packet.to_msgpack, false, 1)
	remote_shells = []
	rs_inator.remote_shells.each do |remote_shell|
		remote_shells << { :pid => remote_shell[2].pid, :shell => remote_shell[4] }
	end
	packet = {
		remote_shells: remote_shells
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell", packet.to_msgpack, false, 1)
end

rs_inator.on :read do |pid, data|
	packet = {
		pid: pid,
		data: data
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/read", packet.to_msgpack, false, 1)
end

rs_inator.on :write do |pid, data|
	packet = {
		pid: pid,
		data: data
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/write", packet.to_msgpack, false, 1)
end

rs_inator.on :error do |pid, error|
	packet = {
		pid: pid,
		error: error
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/error", packet.to_msgpack, false, 1)
end

frw_inator.on :read do |file, length, offset, data|
	packet = {
		file: file,
		length: length,
		offset: offset,
		data: data
	}
	puts packet[:data]
	client.publish("/bu/agents/#{agent[:id]}/inators/file_rw/events/read", packet.to_msgpack, false, 1)
end

frw_inator.on :write do |file, data, offset, length|
	packet = {
		file: file,
		offset: offset,
		length: length
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/file_rw/events/write", packet.to_msgpack, false, 1)
end

frw_inator.on :error do |file, error|
	packet = {
		file: file,
		error: error
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/file_rw/events/error", packet.to_msgpack, false, 1)
end

client.connect('localhost', 1883, client.keep_alive, true, true)
client.subscribe(["#", 2])

loop do
  client.loop_write
  client.loop_read
end
