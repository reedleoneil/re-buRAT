require_relative "inators/remote_shell"
require_relative "inators/file_rw"
require 'paho-mqtt'

client = PahoMqtt::Client.new
rs_inator = RemoteShellInator.new
frw_inator = FileReadWriteInator.new

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

client.connect('broker.hivemq.com', 1883, client.keep_alive, true, true)
client.subscribe(["reedleoneil", 2])

loop do
  client.loop_write
  client.loop_read
end
