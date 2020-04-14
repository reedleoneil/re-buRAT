require 'ostruct'
require 'paho-mqtt'

require_relative 'internals/encryption'
require_relative 'internals/serialization'
require_relative 'internals/ui'

class Re
  attr_accessor :internals
  attr_reader :topics, :evt_topics
  def initialize()
    @internals = {
      :mqtt           => PahoMqtt::Client.new,
      :serialization  => Internals::Serialization.new,
      :rsa            => Internals::RSA.new,
      :aes            => Internals::AES.new,
      :digest         => Internals::Digest.new,
      :ui             => Internals::UI.new
    }
    @evt_topics = []
    @topics = {}
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
    @evt_topics.push([topic, 2])
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
    begin
      @internals[:mqtt].connect()
      @internals[:mqtt].subscribe(@evt_topics)
    rescue StandardError => error
      puts error.full_message
      sleep 11
      connect()
    end
  end

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
