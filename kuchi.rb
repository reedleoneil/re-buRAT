require 'paho-mqtt'
require 'msgpacker'
require 'ostruct'

client = PahoMqtt::Client.new
client.connect('localhost', 1883, client.keep_alive, true, true)
client.subscribe(["#", 2])

client.add_topic_callback("/bu/agents/#{ARGV[1]}/inators/file_rw/events/read") do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	if ARGV[5] then File.binwrite(ARGV[5], packet.data, 0) else puts packet.data end
end

client.add_topic_callback("/bu/agents/#{ARGV[1]}/inators/remote_shell/events/read") do |packet|
	packet = OpenStruct.new MessagePack.unpack(packet.payload)
	if ARGV[4] then
		File.binwrite(ARGV[4], packet.data, File.exists?(ARGV[4]) ? File.size(ARGV[4]) + 1 : 0) 
	else 
		puts packet.data 
	end
end

case ARGV[0].to_i
	when 1
		@p = {
			topic: "/bu/agents/#{ARGV[1]}/inators/remote_shell/cmds/open",
			payload: { shell:  ARGV[2] }
		}
	when 2
		@p = {
			topic: "/bu/agents/#{ARGV[1]}/inators/remote_shell/cmds/close",
			payload: { pid: ARGV[2].to_i }
		}
	when 3
		@p = {
			topic: "/bu/agents/#{ARGV[1]}/inators/remote_shell/cmds/write",
			payload: { pid: ARGV[2].to_i, data: ARGV[3] }
		}
	when 4
		@p = {
			topic: "/bu/agents/#{ARGV[1]}/inators/file_rw/cmds/read",
			payload: { file: ARGV[2], length: ARGV[3].to_i, offset: ARGV[4].to_i }
		}
	when 5
		@p = {
			topic: "/bu/agents/#{ARGV[1]}/inators/file_rw/cmds/write",
			payload: { file: ARGV[2], data: File.binread(ARGV[3]), offset: ARGV[4].to_i }
		}
	else
		puts "Usage: ruby kuchi.rb 1..5 [REQUIRED:optional]..[REQUIRED:optional]"
		puts "  1 [AGENT] [SHELL]".ljust(75) +														"Open a remote shell."
		puts "  2 [AGENT] [PID]".ljust(75) +														"Close a remote shell."
		puts "  3 [AGENT] [PID] [DATA] [local output file]".ljust(75) +								"Write data to a remote shell."
		puts "  4 [AGENT] [REMOTE INPUT FILE] [LENGHT] [OFFSET] [local output file]".ljust(75) +	"Read a remote file."
		puts "  5 [AGENT] [REMOTE OUTPUT FILE] [LOCAL INPUT FILE] [OFFSET]".ljust(75) +				"Read a remote file."
		return
end

puts topic = @p[:topic]
puts payload = MessagePack.pack(@p[:payload])
client.publish(topic, payload, false, 1)

Thread.new {
	loop do
		client.loop_write
		client.loop_read
	end
}

STDIN.gets