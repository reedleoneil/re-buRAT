require_relative 're'

params = {
	:topic => 'bu/#',
	:host => 'localhost',
	:port => 1883
}

re = Re.new

re.internals[:optparse].program_name = "re:clear"
re.internals[:optparse].version = "0.0.1"
re.internals[:optparse].on('-t', '--topic', '=TOPIC', 'topic to be cleared')
re.internals[:optparse].on('-h', '--host', 	'=HOST', 'host default localhost')
re.internals[:optparse].on('-p', '--port', 	'=PORT', 'port default 1883')
re.internals[:optparse].parse!(into: params)

re.internals[:digest].config({
	:digest => 'md5'
})

re.add_topics({
	:topic => params[:topic]
})

re.add_topic_callback(:topic) do |message|
	if message.payload != '' then
	  puts message.topic
	  re.internals[:mqtt].publish(message.topic, nil, true, 2)
	end
end

loop do
	begin
		re.internals[:mqtt].loop_read
		re.internals[:mqtt].loop_write
	rescue StandardError => error
		puts error.full_message
		re.internals[:mqtt].host = params[:host]
		re.internals[:mqtt].port = params[:port]
		re.internals[:mqtt].persistent = true
		re.internals[:mqtt].blocking = true
		re.internals[:mqtt].reconnect_limit = 3
		re.internals[:mqtt].reconnect_delay = 60
		re.connect()
	end
end
