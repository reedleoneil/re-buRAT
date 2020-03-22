require_relative 'internals/encryption'
require_relative 'internals/serialization'
require_relative 'bushido/filerw/bufilerw'
require_relative 'bushido/remoteshell/buremoteshell'

class Bushi
  attr_accessor :id, :host, :os, :ip, :status, :internals, :bushido
  def initialize()
    @internals = {
      :mqtt           => PahoMqtt::Client.new,
      :serialization  => Internals::Serialization.new,
      :rsa            => Internals::RSA.new,
      :aes            => Internals::AES.new,
      :digest         => Internals::Digest.new
    }
    @bushido = {
      :remoteshell    => Bushido::BuRemoteShell.new,
      :filerw         => Bushido::BuFileReadWrite.new
    }
  end
end
