require 'securerandom'

require_relative 're'

params = {
  :id => SecureRandom.hex(2)
}

re = Re.new

re.internals[:ui].render_banner('re:MOTESHELL')

re.internals[:optparse].program_name = "re:moteshell"
re.internals[:optparse].version = "0.0.1"
re.internals[:optparse].on('-b', '--bushi',  '=BUSHI',  'target bushi')
re.internals[:optparse].on('-i', '--id',     '=ID',     'id of remote shell')
re.internals[:optparse].on('-s', '--shell',  '=SHELL',  'shell to spawn')
re.internals[:optparse].parse!(into: params)

re.internals[:rsa].config({
  :encoded_key => File.read('re.key')
})

re.internals[:digest].config({
	:digest => 'md5'
})

re.add_topics({
  :nil                    => "bu/nil",
  :bushi									=> "bu/bushi/#{params[:bushi]}",
  :remoteshell						=> "bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}",
  :remoteshell_cmd_write	=> "bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/cmd/write",
  :remoteshell_evt_open		=> "bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/open",
  :remoteshell_evt_close	=> "bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/close",
  :remoteshell_evt_read		=> "bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/read",
  :remoteshell_evt_write	=> "bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/write",
  :remoteshell_evt_error	=> "bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/error"
})

re.add_packets({
  :open =>  { :id => params[:id], :shell => params[:shell] },
  :close => { :id => params[:id] },
  :write => { :id => params[:id], :data => nil }
})

re.add_topic_callback(:bushi) do |message|
  packet = re.decoryse(message.payload)
  puts packet.to_yaml

  case packet[:status]
  when 'online'
    re.internals[:aes].config({
      :key_length => 128,
      :mode => :CTR,
      :key => packet[:aes]['key'],
      :iv => packet[:aes]['iv']
    })

    packet = re.packets(:open)
    packet = re.seen(packet)
    re.publish(:remoteshell, packet, false, 2)
  when 'offline'
    exit
  end
end

re.add_topic_callback(:remoteshell_evt_open) do |message|
  packet = re.decryse(message.payload)
  puts "remoteshell.opened #{packet.id}"
end

re.add_topic_callback(:remoteshell_evt_close) do |message|
  packet = re.decryse(message.payload)
  puts "remoteshell.closed #{packet.id}"
  exit
end

re.add_topic_callback(:remoteshell_evt_read) do |message|
  packet = re.decryse(message.payload)
  puts packet.data
end

re.add_topic_callback(:remoteshell_evt_write) do |message|
  packet = re.decryse(message.payload)
  #puts packet.data
end

re.add_topic_callback(:remoteshell_evt_error) do |message|
  packet = re.decryse(message.payload)
  puts packet.error
end

Thread.new {
  loop do
    packet = re.packets(:write)
    packet[:data] = $stdin.gets.chomp
    packet = re.internals[:serialization].serialize(packet)
    packet = re.internals[:aes].encrypt(packet)
    re.publish(:remoteshell_cmd_write, packet, false, 2)
  end
}

END {
  re.publish(:remoteshell, nil, false, 2)
  loop do
    re.internals[:mqtt].mqtt_loop
  end
}

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
