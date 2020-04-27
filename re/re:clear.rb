require 'json'

require_relative 're'

params = {
	:topic => 'bu/#'
}

re = Re.new

re.internals[:ui].render_banner('re:CLEAR')

re.internals[:optparse].program_name = "re:clear"
re.internals[:optparse].version = "0.0.1"
re.internals[:optparse].on('-t', '--topic', '=TOPIC', 'topic to be cleared')
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

last_ping_time = Time.now
loop do
	begin
		if re.internals[:mqtt].connected? then
			re.internals[:mqtt].mqtt_loop
			if last_ping_time <= Time.now - re.internals[:mqtt].keep_alive then
				re.ping
				last_ping_time = Time.now
			end
		else
			re.connect() if !re.connecting?
		end
	rescue StandardError => error
		puts error.full_message
		re.connect() if !re.connecting?
	end
end
