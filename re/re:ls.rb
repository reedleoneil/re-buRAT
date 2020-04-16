require 'optparse'
require 'paho-mqtt'

require_relative 're'

params = {}

OptionParser.new do |opts|
  opts.program_name = "re:ls"
  opts.version = "0.0.1"
end.parse!(into: params)

bushi = {}

re = Re.new

re.internals[:digest].config({
	:digest => 'md5'
})

re.internals[:rsa].config({
  :encoded_key => File.read('bu.key')
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
		puts error
		re.internals[:mqtt].host = 'localhost'
		re.internals[:mqtt].port = 1883
		re.internals[:mqtt].persistent = true
		re.internals[:mqtt].blocking = true
		re.internals[:mqtt].reconnect_limit = 3
		re.internals[:mqtt].reconnect_delay = 60
		re.connect()
	end
end
