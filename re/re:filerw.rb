require 'json'
require 'pp'
require 'securerandom'

require_relative 're'

params = {
  :id => SecureRandom.hex(2),
  :rate => 10240
}
progressbar = nil

re = Re.new

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

re.add_packets({
  :open =>  {
    :id => params[:id],
    :path => params[:mode] == 'read' ? params[:source] : params[:destination],
    :mode => params[:mode],
    :size => params[:size]
  },
  :close => { :id => params[:id] },
  :read => { :id => params[:id], :length => nil },
  :write => { :id => params[:id], :data => nil }
})

re.add_topic_callback(:bushi) do |message|
  packet = re.decoryse(message.payload)
  pp packet

  case packet[:status]
  when 'online'
    re.internals[:aes].config({
      :key_length => 128,
      :mode => :CTR,
      :key => packet[:aes]['key'],
      :iv => packet[:aes]['iv']
    })

    packet = re.packets[:open]
    packet = re.seen(packet)
    re.internals[:mqtt].publish(re.topics[:filerw_cmd_open], packet, false, 2)
  when 'offline'
    exit
  end
end

re.add_topic_callback(:filerw) do |message|
  if message.payload != '' then
    file = re.decryse(message.payload)
    #pp file

    progressbar.advance(params[:rate])

    case file.mode
    when 'read'
      topic = re.topics[:filerw_cmd_read]
      packet = re.packets[:read]
      remaining_bytesio = file.size.to_i - file.bytesio.to_i
      packet[:length] = remaining_bytesio >= params[:rate] ? params[:rate] : remaining_bytesio
    when 'write'
      topic = re.topics[:filerw_cmd_write]
      packet = re.packets[:write]
      packet[:data] = File.binread(params[:source], params[:rate], file.bytesio.to_i)
    end

    if file.size.to_i > file.bytesio.to_i then
      packet = re.seen(packet)
      re.internals[:mqtt].publish(topic, packet, false, 2)
    end
  else
    exit
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
  progressbar = re.internals[:ui].progressbar_filerw(params[:size])
end

END {
  packet = re.packets[:close]
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
