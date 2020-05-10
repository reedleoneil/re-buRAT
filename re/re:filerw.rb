require 'securerandom'

require_relative 're'

params = {
  :id => SecureRandom.hex(2),
  :rate => 10240
}
progressbar = nil

re = Re.new

re.internals[:ui].render_banner('re:FILERW')

re.internals[:optparse].program_name = "re:filerw"
re.internals[:optparse].version = "0.0.1"
re.internals[:optparse].on('-b', '--bushi',        '=ID',              'target bushi')
re.internals[:optparse].on('-i', '--id',           '=ID',              'id of remote shell')
re.internals[:optparse].on('-m', '--mode',         '=MODE',            'file mode read | write')
re.internals[:optparse].on('-s', '--source',       '=PATH',            'remote file path to read from')
re.internals[:optparse].on('-d', '--destination',  '=PATH',            'local file path to read to')
re.internals[:optparse].on('-z', '--size',         '=SIZE', Integer,   'file size to read or write')
re.internals[:optparse].on('-r', '--rate',         '=BITS', Integer,   'transfer rate default: 1024')
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
  :filerw									=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}",
  :filerw_cmd_read				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/cmd/read",
  :filerw_cmd_write				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/cmd/write",
  :filerw_evt_open				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/evt/open",
  :filerw_evt_close				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/evt/close",
  :filerw_evt_read				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/evt/read",
  :filerw_evt_write				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/evt/write",
  :filerw_evt_error				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/evt/error"
})

re.add_packets({
  :open =>  {
    :id => params[:id],
    :path => params[:mode] == 'read' ? params[:source] : params[:destination]
  },
  :close => { :id => params[:id] },
  :read => { :id => params[:id], :length => nil, :offset => nil },
  :write => { :id => params[:id], :data => nil, :offset => nil }
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
    re.publish(:filerw, packet, false, 2)
  when 'offline'
    exit
  end
end

re.add_topic_callback(:filerw_evt_open) do |message|
  file = re.decryse(message.payload)
  puts file.to_yaml

  case params[:mode]
  when 'read'
    Thread.new {
      bytesio = 0
      while bytesio <= params[:size]
        packet = re.packets(:read)
        length = bytesio + params[:rate] <= params[:size] ? params[:rate] : params[:size] - bytesio
        packet[:length] = length
        packet[:offset] = bytesio
        packet = re.seen(packet)
        re.publish(:filerw_cmd_read, packet, false, 2)
        bytesio += params[:rate]
        sleep 0.01
      end
    }
  when 'write'
    Thread.new {
      bytesio = 0
      while bytesio <= params[:size]
        packet = re.packets(:write)
        length = bytesio + params[:rate] <= params[:size] ? params[:rate] : params[:size] - bytesio
        packet[:data] = File.binread(params[:source], length, bytesio)
        packet[:offset] = bytesio
        packet = re.seen(packet)
        re.publish(:filerw_cmd_write, packet, false, 2)
        bytesio += params[:rate]
        sleep 0.01
      end
    }
  end
end

re.add_topic_callback(:filerw_evt_close) do |message|
  packet = re.decryse(message.payload)
  puts "filerw.closed #{packet.id}"
  exit
end

re.add_topic_callback(:filerw_evt_read) do |message|
  packet = re.decryse(message.payload)
  progressbar.advance(params[:rate])
  File.binwrite(params[:destination], packet.data, packet.offset)
end

re.add_topic_callback(:filerw_evt_write) do |message|
  packet = re.decryse(message.payload)
  progressbar.advance(params[:rate])
end

re.add_topic_callback(:filerw_evt_error) do |message|
  packet = re.decryse(message.payload)
  puts packet.error
end

re.internals[:mqtt].on_connack do
  progressbar = re.internals[:ui].progressbar_filerw(params[:size])
end

END {
  re.publish(:filerw, nil, false, 2)
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
