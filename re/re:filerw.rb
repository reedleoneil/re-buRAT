require 'base64'
require 'optparse'
require 'paho-mqtt'
require 'pp'
require 'securerandom'
require 'tty-reader'

require_relative 're'

params = {
  :id => SecureRandom.hex(2),
  :rate => 1024
}

OptionParser.new do |opts|
  opts.program_name = "re:filerw"
  opts.version = "0.0.1"
  opts.on('-b', '--bushi',        '=ID',              'target bushi')
  opts.on('-i', '--id',           '=ID',              'id of remote shell')
  opts.on('-m', '--mode',         '=MODE',            'file mode read | write')
  opts.on('-s', '--source',       '=PATH',            'remote file path to read from')
  opts.on('-d', '--destination',  '=PATH',            'local file path to read to')
  opts.on('-z', '--size',         '=SIZE', Integer,   'file size to read or write')
  opts.on('-r', '--rate',         '=BITS', Integer,   'transfer rate default: 1024')
end.parse!(into: params)

re = Re.new

re.internals[:rsa].config({
  :encoded_key => File.read('bu.key')
})

re.internals[:digest].config({
	:digest => 'md5'
})

re.add_topics({
  :bushi									=> "bu/bushi/#{params[:bushi]}",
  :filerw									=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}",
  :filerw_cmd_open				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/cmd/open",
  :filerw_cmd_close				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/cmd/close",
  :filerw_cmd_read				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/cmd/read",
  :filerw_cmd_write				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/cmd/write",
  :filerw_evt_read				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/evt/read",
  :filerw_evt_write				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/evt/write",
  :filerw_evt_error				=> "bu/bushi/#{params[:bushi]}/bushido/filerw/#{params[:id]}/evt/error"
})

packets = {
  :open =>  {
    :id => params[:id],
    :path => params[:mode] == 'read' ? params[:source] : params[:destination],
    :mode => params[:mode],
    :size => params[:size]
  },
  :close => { :id => params[:id] },
  :read => { :id => params[:id], :length => nil },
  :write => { :id => params[:id], :data => nil }
}

progressbar = nil

re.add_topic_callback(:bushi) do |message|
  packet = Base64.decode64(message.payload)
  packet = re.internals[:rsa].decrypt(packet)
  packet = re.internals[:serialization].deserialize(packet)
  packet = packet.transform_keys(&:to_sym)
  pp packet

  case packet[:status]
  when 'online'
    re.internals[:aes].config({
      :key_length => 128,
      :mode => :CTR,
      :key => packet[:aes]['key'],
      :iv => packet[:aes]['iv']
    })

    packet = packets[:open]
    packet = re.seen(packet)
    re.internals[:mqtt].publish(re.topics[:filerw_cmd_open], packet, false, 2)
  when 'offline'
    exit
  end
end

re.add_topic_callback(:filerw) do |message|
  case message.payload
  when ''
    exit
  else
    file = re.decryse(message.payload)
    #pp file

    progressbar.advance(params[:rate])

    case file.mode
    when 'read'
      topic = re.topics[:filerw_cmd_read]
      packet = packets[:read]
      remaining_bytesio = file.size.to_i - file.bytesio.to_i
      packet[:length] = remaining_bytesio >= params[:rate] ? params[:rate] : remaining_bytesio
    when 'write'
      topic = re.topics[:filerw_cmd_write]
      packet = packets[:write]
      packet[:data] = File.binread(params[:source], params[:rate], file.bytesio.to_i)
    end

    if file.size.to_i > file.bytesio.to_i then
      packet = re.seen(packet)
      re.internals[:mqtt].publish(topic, packet, false, 2)
    end
  end
end

re.add_topic_callback(:filerw_evt_read) do |message|
  packet = re.decryse(message.payload)
  #puts packet[:data]
  offset = File.exist?(params[:destination]) ? File.size(params[:destination]) : 0
  File.binwrite(params[:destination], packet.data, offset)
end

re.add_topic_callback(:filerw_evt_write) do |message|
  packet = re.decryse(message.payload)
  # packet[:length]
end

re.add_topic_callback(:filerw_evt_error) do |message|
  packet = re.decryse(message.payload)
  puts packet.error
end

re.internals[:mqtt].on_connack do
  re.internals[:ui].render_banner('re:FILERW')
  progressbar = re.internals[:ui].progressbar(params[:size])
end

END {
  packet = packets[:close]
  packet = re.seen(packet)
  re.internals[:mqtt].publish(re.topics[:filerw_cmd_close], packet, false, 2)
  loop do
    re.internals[:mqtt].loop_read
    re.internals[:mqtt].loop_write
  end
}

loop do
	begin
		re.internals[:mqtt].loop_read
		re.internals[:mqtt].loop_write
	rescue StandardError => error
		puts error.full_message
		re.internals[:mqtt].host = 'localhost'
		re.internals[:mqtt].port = 1883
		re.internals[:mqtt].persistent = true
		re.internals[:mqtt].blocking = true
		re.internals[:mqtt].reconnect_limit = 3
		re.internals[:mqtt].reconnect_delay = 60
		re.connect()
	end
end
