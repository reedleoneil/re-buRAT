require_relative 'bushido/core/serialization'
require_relative 'bushido/core/encryption'
require_relative 'bushido/remoteshell/buremoteshell'
require_relative 'bushido/filerw/bufilerw'

class Bushi
  attr_accessor :id, :host, :os, :ip, :status, :bushido
  def initialize()
    @bushido = {
      :mqtt           => PahoMqtt::Client.new,
      :serialization  => Bushido::Serialization.new,
      :rsa            => Bushido::RSA.new,
      :aes            => Bushido::AES.new,
      :digest         => Bushido::Digest.new,
      :remoteshell    => Bushido::BuRemoteShell.new,
      :filerw         => Bushido::BuFileReadWrite.new
    }
  end
end
