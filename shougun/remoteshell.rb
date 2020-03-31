require 'optparse'
require 'base64'
require 'securerandom'
require_relative 'shougun'

params = {
  :id => SecureRandom.hex(2),
  :shell => 'bash'
}

OptionParser.new do |opts|
  opts.program_name = "burs"
  opts.version = "0.0.1"
  opts.on('-b', '--bushi',  '=BUSHI',   'target bushi')
  opts.on('-i', '--id',     '[=ID]',    'id of remote shell')
  opts.on('-s', '--shell',  '[=ID]',    'shell')
end.parse!(into: params)

mqtt_topics = {
	:bushi									=> "/bu/bushi/#{params[:bushi]}",
	:remoteshell						=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/",
	:remoteshell_cmd_open		=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/cmd/open",
	:remoteshell_cmd_close	=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/cmd/close",
	:remoteshell_cmd_write	=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/cmd/write",
	:remoteshell_evt_read		=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/read",
	:remoteshell_evt_write	=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/write",
	:remoteshell_evt_error	=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/error"
}

packets = {
  :open => { :id => params[:id], :shell => params[:shell] },
  :close => { :id => params[:id] },
  :write => { :id => params[:id], :data => nil }
}

shougun = Shougun.new

shougun.internals[:rsa].config({
  :encoded_key => File.read('bu.key')
})

shougun.internals[:mqtt].host = 'localhost'
shougun.internals[:mqtt].port = 1883
shougun.internals[:mqtt].persistent = true
shougun.internals[:mqtt].blocking = true
shougun.internals[:mqtt].reconnect_limit = 3
shougun.internals[:mqtt].reconnect_delay = 60

shougun.internals[:mqtt].on_connack do

end

shougun.internals[:mqtt].add_topic_callback(mqtt_topics[:bushi]) do |packet|
  packet = Base64.decode64(packet.payload)
  packet = shougun.internals[:rsa].decrypt(packet)
  packet = shougun.internals[:serialization].deserialize(packet)

  shougun.internals[:aes].config({
    :key_lenght => 128,
    :mode => :CTR,
    :key => packet['aes']['key'],
    :iv => packet['aes']['iv']
  })

  packet = packets[:open]
  packet = shougun.internals[:serialization].serialize(packet)
  packet = shougun.internals[:aes].encrypt(packet)
  shougun.internals[:mqtt].publish(mqtt_topics[:remoteshell_cmd_open], packet, false, 2)
end

shougun.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell]) do |packet|
  if packet.payload != '' then
    packet = shougun.internals[:aes].decrypt(packet.payload)
    packet = shougun.internals[:serialization].deserialize(packet)
    puts packet
  else
    exit
  end
end

shougun.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_evt_read]) do |packet|
  packet = shougun.internals[:aes].decrypt(packet.payload)
  packet = shougun.internals[:serialization].deserialize(packet)
  puts packet['data']
end

shougun.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_evt_write]) do |packet|
  packet = shougun.internals[:aes].decrypt(packet.payload)
  packet = shougun.internals[:serialization].deserialize(packet)
  puts packet
end

shougun.internals[:mqtt].add_topic_callback(mqtt_topics[:remoteshell_evt_error]) do |packet|
  packet = shougun.internals[:aes].decrypt(packet.payload)
  packet = shougun.internals[:serialization].deserialize(packet)
  puts packet
end

shougun.internals[:mqtt].connect(shougun.internals[:mqtt].host, shougun.internals[:mqtt].port, shougun.internals[:mqtt].keep_alive, shougun.internals[:mqtt].persistent, shougun.internals[:mqtt].blocking)
shougun.internals[:mqtt].subscribe(["#", 2])

Thread.new {
  loop do
    shougun.internals[:mqtt].loop_read
    shougun.internals[:mqtt].loop_write
  end
}

Thread.new {
  loop do
    data = $stdin.gets.chomp
    packet = packets[:write].dup
    packet[:data] = data
    packet = shougun.internals[:serialization].serialize(packet)
    packet = shougun.internals[:aes].encrypt(packet)
    shougun.internals[:mqtt].publish(mqtt_topics[:remoteshell_cmd_write], packet, false, 2)
  end
}

END {
  packet = packets[:close]
  packet = shougun.internals[:serialization].serialize(packet)
  packet = shougun.internals[:aes].encrypt(packet)
  shougun.internals[:mqtt].publish(mqtt_topics[:remoteshell_cmd_close], packet, false, 2)
  shougun.internals[:mqtt].loop_write
  puts "exiting..."
  loop do

  end
}

loop do

end
