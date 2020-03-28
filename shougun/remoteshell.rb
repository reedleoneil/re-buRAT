require 'base64'
require_relative 'shougun'

mqtt_topics = {
	:public_key							=> "/bu/public_key",
	:bushi									=> "/bu/bushi/+",
	:remoteshell						=> "/bu/bushi/+/bushido/remoteshell/+/",
	:remoteshell_cmd_open		=> "/bu/bushi/+/bushido/remoteshell/+/cmd/open",
	:remoteshell_cmd_close	=> "/bu/bushi/+/bushido/remoteshell/+/cmd/close",
	:remoteshell_cmd_write	=> "/bu/bushi/+/bushido/remoteshell/+/cmd/write",
	:remoteshell_evt_read		=> "/bu/bushi/+/bushido/remoteshell/+/evt/read",
	:remoteshell_evt_write	=> "/bu/bushi/+/bushido/remoteshell/+/evt/write",
	:remoteshell_evt_error	=> "/bu/bushi/+/bushido/remoteshell/+/evt/error"
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

end

shougun.internals[:mqtt].connect(shougun.internals[:mqtt].host, shougun.internals[:mqtt].port, shougun.internals[:mqtt].keep_alive, shougun.internals[:mqtt].persistent, shougun.internals[:mqtt].blocking)
shougun.internals[:mqtt].subscribe(["#", 2])

Thread.new {
	loop do
		shougun.internals[:mqtt].loop_read
		shougun.internals[:mqtt].loop_write
	end
}
