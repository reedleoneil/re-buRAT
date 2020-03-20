require 'base64'
require_relative 'shougun'

mqtt_topics = {
	:public_key						=> "/bu/public_key",
	:bushi								=> "/bu/bushi/+",
	:remoteshell					=> "/bu/bushi/+/bushido/remoteshell",
	:remoteshell_open			=> "/bu/bushi/+/bushido/remoteshell/cmds/open",
	:remoteshell_close		=> "/bu/bushi/+/bushido/remoteshell/cmds/close",
	:remoteshell_write		=> "/bu/bushi/+/bushido/remoteshell/cmds/write",
	:remoteshell_onopen		=> "/bu/bushi/+/bushido/remoteshell/events/open",
	:remoteshell_onclose	=> "/bu/bushi/+/bushido/remoteshell/events/close",
	:remoteshell_onread		=> "/bu/bushi/+/bushido/remoteshell/events/read",
	:remoteshell_onwrite	=> "/bu/bushi/+/bushido/remoteshell/events/write",
	:remoteshell_onerror	=> "/bu/bushi/+/bushido/remoteshell/events/error",
	:filerw								=> "/bu/bushi/+/bushido/filerw",
	:filerw_open					=> "/bu/bushi/+/bushido/filerw/cmds/open",
	:filerw_close					=> "/bu/bushi/+/bushido/filerw/cmds/close",
	:filerw_read					=> "/bu/bushi/+/bushido/filerw/cmds/read",
	:filerw_write					=> "/bu/bushi/+/bushido/filerw/cmds/write",
	:filerw_onopen				=> "/bu/bushi/+/bushido/filerw/events/open",
	:filerw_onclose				=> "/bu/bushi/+/bushido/filerw/events/close",
	:filerw_onread				=> "/bu/bushi/+/bushido/filerw/events/read",
	:filerw_onwrite				=> "/bu/bushi/+/bushido/filerw/events/write",
	:filerw_error					=> "/bu/bushi/+/bushido/filerw/events/error"
}

shougun = Shougun.new

shougun.bushido[:rsa].config({
  :key_size => 2048
})

shougun.bushido[:mqtt].host = 'localhost'
shougun.bushido[:mqtt].port = 1883
shougun.bushido[:mqtt].persistent = true
shougun.bushido[:mqtt].blocking = true
shougun.bushido[:mqtt].reconnect_limit = 3
shougun.bushido[:mqtt].reconnect_delay = 60

shougun.bushido[:mqtt].on_connack do

end

shougun.bushido[:mqtt].add_topic_callback(mqtt_topics[:bushi]) do |packet|
  begin
    packet = Base64.decode64(packet.payload)
    packet = shougun.bushido[:rsa].decrypt(packet)
    packet = shougun.bushido[:serialization].deserialize(packet)

    if packet['status'] == 'online' then
      bushi = Bushi.new({
        :id => packet['id'],
        :host => packet['host'],
        :os => packet['os'],
        :ip => packet['ip'],
        :status => packet['status']
      })

      bushi.bushido[:aes].config({
        :key_lenght => 128,
        :mode => :CTR,
        :key => packet['aes']['key'],
        :iv => packet['aes']['iv']
      })

      shougun.bushi.push(bushi)
    elsif packet['status'] == 'offline' then
      bushi = shougun.bushi.find { |bushi| bushi.id == packet['id'] }
      bushi.status = :offline
    end
  rescue StandardError => error
    puts error.backtrace
  end
end

shougun.bushido[:mqtt].connect(shougun.bushido[:mqtt].host, shougun.bushido[:mqtt].port, shougun.bushido[:mqtt].keep_alive, shougun.bushido[:mqtt].persistent, shougun.bushido[:mqtt].blocking)
shougun.bushido[:mqtt].subscribe(["#", 2])

Thread.new {
	loop do
		shougun.bushido[:mqtt].loop_read
		shougun.bushido[:mqtt].loop_write
	end
}

while command = $stdin.gets.chomp
	case command
	when 'pub key'
		`gnome-terminal`
		packet = shougun.bushido[:rsa].public_key
	  shougun.bushido[:mqtt].publish(mqtt_topics[:public_key], packet, true, 2)
	when 'list'
		shougun.bushi.each do |bushi|
			puts "#{bushi.id} #{bushi.status}"
		end
	when 'rs open'
		topic = mqtt_topics[:remoteshell_open].dup
		id = $stdin.gets.chomp
		topic['+'] = id
		packet = {
			:id => $stdin.gets.chomp,
			:shell => $stdin.gets.chomp
		}
		bushi = shougun.bushi.find { |bushi| bushi.id == id }
		packet = shougun.bushido[:serialization].serialize(packet)
		packet = bushi.bushido[:aes].encrypt(packet)
		shougun.bushido[:mqtt].publish(topic, packet, false, 2)
	when 'rs write'
		topic = mqtt_topics[:remoteshell_write].dup
		id = $stdin.gets.chomp
		topic['+'] = id
		packet = {
			:id => $stdin.gets.chomp,
			:data => $stdin.gets.chomp
		}
		bushi = shougun.bushi.find { |bushi| bushi.id == id }
		packet = shougun.bushido[:serialization].serialize(packet)
		packet = bushi.bushido[:aes].encrypt(packet)
		shougun.bushido[:mqtt].publish(topic, packet, false, 2)
	end
end
