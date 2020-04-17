require 'json'

require_relative 're'

params = {}
bushi = {}

re = Re.new

re.internals[:optparse].program_name = "re:ls"
re.internals[:optparse].version = "0.0.1"
re.internals[:optparse].parse!(into: params)

re.internals[:rsa].config({
  :encoded_key => File.read('re.key')
})

re.internals[:digest].config({
	:digest => 'md5'
})

re.add_topics({
  :nil    => "bu/nil",
  :bushi  => "bu/bushi/+"
})

re.add_topic_callback(:bushi) do |message|
  begin
    packet = re.decoryse(message.payload)
    bushi[packet[:id]] = packet
		re.internals[:ui].render_table_bushi(bushi)
  rescue StandardError => error
    puts error.full_message
  end
end

Thread.new {
  loop do
    sleep re.internals[:mqtt].keep_alive
    if re.internals[:mqtt].connected? then
      re.internals[:mqtt].publish(re.topics[:nil], nil, false, 2)
    end
  end
}

loop do
	begin
		re.internals[:mqtt].loop_read
		re.internals[:mqtt].loop_write
	rescue StandardError => error
		puts error.full_message
    config = JSON.parse(File.read('re.conf'))
		re.internals[:mqtt].host = config['host']
		re.internals[:mqtt].port = config['port']
		re.internals[:mqtt].persistent = true
		re.internals[:mqtt].blocking = true
		re.internals[:mqtt].reconnect_limit = 3
		re.internals[:mqtt].reconnect_delay = 60
		re.connect()
	end
end
