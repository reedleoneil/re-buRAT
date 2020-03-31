require 'paho-mqtt'

require_relative 'bushi'
require_relative 'internals/serialization'
require_relative 'internals/encryption'
require_relative 'internals/ui'

class Shougun
  attr_accessor :bushi, :internals, :bushido
  def initialize()
    @bushi = []
    @internals = {
      :mqtt           => PahoMqtt::Client.new,
      :serialization  => Internals::Serialization.new,
      :rsa            => Internals::RSA.new,
      :aes            => Internals::AES.new,
      :digest         => Internals::Digest.new,
      :ui             => Internals::UI.new
    }
  end
end
