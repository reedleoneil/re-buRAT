require 'paho-mqtt'
require 'msgpacker'
require 'json'
require 'tty-table'
require 'tty-cursor'
require 'time'

client = PahoMqtt::Client.new
client.connect('localhost', 1883, client.keep_alive, true, true)
client.subscribe(["/bu/#", 2])

@shinobis = []

client.add_topic_callback("/bu/#") do |p|
	#cursor = TTY::Cursor
	#print cursor.move_to(7, 7)
end

client.add_topic_callback("/bu/shinobi/+") do |p|
	begin
		#puts "Topic: #{p.topic}\nPayload: #{MessagePack.unpack p.payload}\nQoS: #{p.qos}"
		payload = MessagePack.unpack p.payload
		test payload
	rescue
		#puts "Topic: #{p.topic}\nPayload: #{JSON.parse p.payload}\nQoS: #{p.qos}"
		payload = JSON.parse p.payload
		test payload
	end
end

def test(payload)
	if @shinobis.any? { |shinobi| shinobi[0].to_s == payload["id"] } then
		@shinobis.map! do |shinobi| 
			if shinobi[0] == payload["id"] then
				shinobi = [payload["id"], payload["host"], payload["user"], payload["status"]]
			else
				shinobi
			end
		end
	else
		@shinobis << [payload["id"], payload["host"], payload["user"], payload["status"]]
	end
	#cursor = TTY::Cursor
	#print cursor.clear_screen_down
	#print cursor.move_to(0, 0)
	table = TTY::Table.new header: ['ID', 'HOST', 'USER', 'STATUS'], rows: @shinobis
	puts table.render(:unicode)
end

loop do
  client.loop_write
  client.loop_read
end
