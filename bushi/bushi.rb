require 'securerandom'
require 'os'
require 'open-uri'
require 'paho-mqtt'

require_relative 'bushido/core/serialization'
require_relative 'bushido/core/encryption'
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
