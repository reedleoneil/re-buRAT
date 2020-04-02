require 'optparse'
require 'base64'
require 'paho-mqtt'

require_relative 'internals/serialization'
require_relative 'internals/encryption'
require_relative 'internals/ui'

params = {}

OptionParser.new do |opts|
  opts.program_name = "re:ls"
  opts.version = "0.0.1"
end.parse!(into: params)

re = {
  :topics => {
    :bushi => "/bu/bushi/+"
  },
	:internals => {
		:mqtt           => PahoMqtt::Client.new,
		:serialization  => Internals::Serialization.new,
		:rsa            => Internals::RSA.new,
		:aes            => Internals::AES.new,
		:digest         => Internals::Digest.new,
		:ui             => Internals::UI.new
	},
  :bushi => {}
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

end

re[:internals][:mqtt].add_topic_callback(re[:topics][:bushi]) do |message|
  begin
    packet = Base64.decode64(message.payload)
    packet = re[:internals][:rsa].decrypt(packet)
    packet = re[:internals][:serialization].deserialize(packet)
    packet = packet.transform_keys(&:to_sym)

    re[:bushi][packet[:id]] = packet

    puts re[:bushi]

		data = []
		re[:bushi].each_value do |value|
			data.push(value.fetch_values(:id, :host, :os, :ip, :status))
		end
		re[:internals][:ui].render_bushi_table(data)
  rescue StandardError => error
    puts error.backtrace
  end
end

re[:internals][:mqtt].connect(
  re[:internals][:mqtt].host,
  re[:internals][:mqtt].port,
  re[:internals][:mqtt].keep_alive,
  re[:internals][:mqtt].persistent,
  re[:internals][:mqtt].blocking
)

re[:internals][:mqtt].subscribe([re[:topics][:bushi], 2])

loop do
	re[:internals][:mqtt].loop_read
	re[:internals][:mqtt].loop_write
end
