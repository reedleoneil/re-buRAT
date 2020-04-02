require_relative 'internals/encryption'
require_relative 'internals/serialization'

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
  end
end
