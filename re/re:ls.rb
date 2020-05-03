require_relative 're'

params = {}

re = Re.new

re.internals[:ui].render_banner('re:LS')

re.internals[:optparse].program_name = "re:ls"
re.internals[:optparse].version = "0.0.1"
re.internals[:optparse].on('-b', '--bushi',  '=BUSHI',  'target bushi')
re.internals[:optparse].parse!(into: params)

re.internals[:rsa].config({
  :encoded_key => File.read('re.key')
})

re.internals[:digest].config({
	:digest => 'md5'
})

if !params[:bushi] then
  bushi = {}

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
else
  bushi = nil
  remoteshell = []
  filerw = []

  re.add_topics({
    :nil          => "bu/nil",
    :bushi        => "bu/bushi/#{params[:bushi]}",
    :remoteshell  => "bu/bushi/#{params[:bushi]}/bushido/remoteshell/+",
    :filerw       => "bu/bushi/#{params[:bushi]}/bushido/filerw/+"
  })

  re.add_topic_callback(:bushi) do |message|
    packet = re.decoryse(message.payload)
    bushi = packet

    re.internals[:aes].config({
      :key_length => 128,
      :mode => :CTR,
      :key => packet[:aes]['key'],
      :iv => packet[:aes]['iv']
    })

    re.internals[:ui].render_profile(bushi, remoteshell, filerw)
  end

  re.add_topic_callback(:remoteshell) do |message|
    if message.payload != '' then
      packet = re.decryse(message.payload)
      remoteshell << packet
      re.internals[:ui].render_profile(bushi, remoteshell, filerw)
    end
  end

  re.add_topic_callback(:filerw) do |message|
    if message.payload != '' then
      packet = re.decryse(message.payload)
      filerw << packet
      re.internals[:ui].render_profile(bushi, remoteshell, filerw)
    end
  end
end


last_ping_time = Time.now
loop do
  sleep 0.1
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
