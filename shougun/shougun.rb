require 'paho-mqtt'

require_relative 'bushi'
require_relative 'bushido/core/serialization'
require_relative 'bushido/core/encryption'

class Shougun
  attr_accessor :bushi, :bushido

  def initialize()
    @bushi = []
    @bushido = {
      :mqtt           => PahoMqtt::Client.new,
      :serialization  => Bushido::Serialization.new,
      :rsa            => Bushido::RSA.new,
      :aes            => Bushido::AES.new,
      :digest         => Bushido::Digest.new
    }
  end
end
