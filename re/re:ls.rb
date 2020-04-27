require 'json'

require_relative 're'

params = {}
bushi = {}

re = Re.new

  re.internals[:ui].render_banner('re:LS')

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
