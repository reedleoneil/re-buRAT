require 'optparse'
require 'paho-mqtt'

require_relative 're'

params = {
	:topic => 'bu/#'
}

OptionParser.new do |opts|
  opts.program_name = "re:clear"
  opts.version = "0.0.1"
	opts.on('-t', '--topic', '=TOPIC', 'topic to be cleared')
end.parse!(into: params)

re = Re.new

re.internals[:digest].config({
	:digest => 'md5'
})

re.internals[:mqtt].on_message do |message|
  puts message.topic
  re.internals[:mqtt].publish(message.topic, nil, true, 2)
end

loop do
	begin
		re.internals[:mqtt].loop_read
		re.internals[:mqtt].loop_write
	rescue StandardError => error
		puts error
		re.internals[:mqtt].host = 'localhost'
		re.internals[:mqtt].port = 1883
		re.internals[:mqtt].persistent = true
		re.internals[:mqtt].blocking = true
		re.internals[:mqtt].reconnect_limit = 3
		re.internals[:mqtt].reconnect_delay = 60
		re.internals[:mqtt].connect()
		re.internals[:mqtt].subscribe([re.digest_topic(params[:topic]), 2])
		#re.internals[:mqtt].subscribe([params[:topic], 2])
	end
end
