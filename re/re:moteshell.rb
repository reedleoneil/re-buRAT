require 'base64'
require 'optparse'
require 'paho-mqtt'
require 'pp'
require 'securerandom'
require 'tty-reader'

require_relative 'internals/encryption'
require_relative 'internals/serialization'
require_relative 'internals/ui'

params = {
  :id => SecureRandom.hex(2)
}

OptionParser.new do |opts|
  opts.program_name = "re:moteshell"
  opts.version = "0.0.1"
  opts.on('-b', '--bushi',  '=BUSHI',   'target bushi')
  opts.on('-i', '--id',     '=ID',      'id of remote shell')
  opts.on('-s', '--shell',  '=SHELL',      'shell to spawn')
end.parse!(into: params)

re = {
  :topics => {
    :bushi									=> "/bu/bushi/#{params[:bushi]}",
  	:remoteshell						=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}",
  	:remoteshell_cmd_open		=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/cmd/open",
  	:remoteshell_cmd_close	=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/cmd/close",
  	:remoteshell_cmd_write	=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/cmd/write",
  	:remoteshell_evt_read		=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/read",
  	:remoteshell_evt_write	=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/write",
  	:remoteshell_evt_error	=> "/bu/bushi/#{params[:bushi]}/bushido/remoteshell/#{params[:id]}/evt/error"
  },
  :packets => {
    :open =>  { :id => params[:id], :shell => params[:shell] },
    :close => { :id => params[:id] },
    :write => { :id => params[:id], :data => nil }
  },
	:internals => {
		:mqtt           => PahoMqtt::Client.new,
		:serialization  => Internals::Serialization.new,
		:rsa            => Internals::RSA.new,
		:aes            => Internals::AES.new,
		:digest         => Internals::Digest.new,
		:ui             => Internals::UI.new
	}
}

re[:internals][:rsa].config({
  :encoded_key => File.read('bu.key')
})

re[:internals][:mqtt].host = 'localhost'
re[:internals][:mqtt].port = 1883
re[:internals][:mqtt].persistent = true
re[:internals][:mqtt].blocking = true
re[:internals][:mqtt].reconnect_limit = 3
re[:internals][:mqtt].reconnect_delay = 60

re[:internals][:mqtt].on_connack do
  re[:internals][:ui].render_banner('re:MOTESHELL')
end

re[:internals][:mqtt].add_topic_callback(re[:topics][:bushi]) do |message|
  packet = Base64.decode64(message.payload)
  packet = re[:internals][:rsa].decrypt(packet)
  packet = re[:internals][:serialization].deserialize(packet)
  packet = packet.transform_keys(&:to_sym)
  pp packet

  case packet[:status]
  when 'online'
    re[:internals][:aes].config({
      :key_length => 128,
      :mode => :CTR,
      :key => packet[:aes]['key'],
      :iv => packet[:aes]['iv']
    })

    packet = re[:packets][:open]
    packet = re[:internals][:serialization].serialize(packet)
    packet = re[:internals][:aes].encrypt(packet)
    re[:internals][:mqtt].publish(re[:topics][:remoteshell_cmd_open], packet, false, 2)
  when 'offline'
    exit
  end
end

re[:internals][:mqtt].add_topic_callback(re[:topics][:remoteshell]) do |message|
  case message.payload
  when ''
    exit
  else
    packet = re[:internals][:aes].decrypt(message.payload)
    packet = re[:internals][:serialization].deserialize(packet)
    remoteshell = packet.transform_keys(&:to_sym)
    pp remoteshell
  end
end

re[:internals][:mqtt].add_topic_callback(re[:topics][:remoteshell_evt_read]) do |message|
  packet = re[:internals][:aes].decrypt(message.payload)
  packet = re[:internals][:serialization].deserialize(packet)
  packet = packet.transform_keys(&:to_sym)
  puts packet[:data]
end

re[:internals][:mqtt].add_topic_callback(re[:topics][:remoteshell_evt_write]) do |message|
  packet = re[:internals][:aes].decrypt(message.payload)
  packet = re[:internals][:serialization].deserialize(packet)
  packet = packet.transform_keys(&:to_sym)
  #puts packet[:data]
end

re[:internals][:mqtt].add_topic_callback(re[:topics][:remoteshell_evt_error]) do |message|
  packet = re[:internals][:aes].decrypt(message.payload)
  packet = re[:internals][:serialization].deserialize(packet)
  packet = packet.transform_keys(&:to_sym)
  puts packet[:error]
end

re[:internals][:mqtt].connect(
  re[:internals][:mqtt].host,
  re[:internals][:mqtt].port,
  re[:internals][:mqtt].keep_alive,
  re[:internals][:mqtt].persistent,
  re[:internals][:mqtt].blocking
)

re[:internals][:mqtt].subscribe(
  [re[:topics][:bushi], 2],
  [re[:topics][:remoteshell], 2],
  [re[:topics][:remoteshell_evt_read], 2],
  [re[:topics][:remoteshell_evt_write], 2],
  [re[:topics][:remoteshell_evt_error], 2]
)

Thread.new {
  loop do
    packet = re[:packets][:write].dup
    packet[:data] = $stdin.gets.chomp
    packet = re[:internals][:serialization].serialize(packet)
    packet = re[:internals][:aes].encrypt(packet)
    re[:internals][:mqtt].publish(re[:topics][:remoteshell_cmd_write], packet, false, 2)
  end
}

END {
  packet = re[:packets][:close]
  packet = re[:internals][:serialization].serialize(packet)
  packet = re[:internals][:aes].encrypt(packet)
  re[:internals][:mqtt].publish(re[:topics][:remoteshell_cmd_close], packet, false, 2)
  loop do
    re[:internals][:mqtt].loop_read
    re[:internals][:mqtt].loop_write
  end
}

loop do
	re[:internals][:mqtt].loop_read
	re[:internals][:mqtt].loop_write
end
