require 'paho-mqtt'
require 'json'
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
	client.publish("/bu/agents/#{agent[:id]}", agent, false, 1)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/remote_shell/cmds/open") do |packet|
	packet = JSON.parse(packet.payload, object_class: OpenStruct)
	rs_inator.open(packet.shell)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/remote_shell/cmds/close") do |packet|
	packet = JSON.parse(packet.payload, object_class: OpenStruct)
	rs_inator.close(packet.pid)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/remote_shell/cmds/write") do |packet|
	packet = JSON.parse(packet.payload, object_class: OpenStruct)
	rs_inator.write(packet.pid, packet.data)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/file_rw/cmds/read") do |packet|
	packet = JSON.parse(packet.payload, object_class: OpenStruct)
	frw_inator.read(packet.file, packet.length, packet.offset)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/file_rw/cmds/write") do |packet|
	packet = JSON.parse(packet.payload, object_class: OpenStruct)
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
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/open", packet, false, 1)
	packet = {
		remote_shells: rs_inator.remote_shells
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell", packet, false, 1)
end

rs_inator.on :close do |pid|
	packet = {
		pid: pid
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/close", packet, false, 1)
	packet = {
		remote_shells: rs_inator.remote_shells
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell", packet, false, 1)
end

rs_inator.on :read do |pid, data|
	packet = {
		pid: pid,
		data: data
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/read", packet, false, 1)
end

rs_inator.on :write do |pid, data|
	packet = {
		pid: pid,
		data: data
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/write", packet, false, 1)
end

rs_inator.on :error do |pid, error|
	packet = {
		pid: pid,
		error: error
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/remote_shell/events/error", packet, false, 1)
end

frw_inator.on :read do |file, length, offset, data|
	packet = {
		file: file,
		length: length,
		offset: offset,
		data: data
	}
	puts packet[:data]
	client.publish("/bu/agents/#{agent[:id]}/inators/file_rw/events/read", packet, false, 1)
end

frw_inator.on :write do |file, data, offset, length|
	packet = {
		file: file,
		offset: offset,
		length: length
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/file_rw/events/write", packet, false, 1)
end

frw_inator.on :error do |file, error|
	packet = {
		file: file,
		error: error
	}
	client.publish("/bu/agents/#{agent[:id]}/inators/file_rw/events/error", packet, false, 1)
end

client.connect('localhost', 1883, client.keep_alive, true, true)
client.subscribe(["#", 2])

loop do
  client.loop_write
  client.loop_read
end
