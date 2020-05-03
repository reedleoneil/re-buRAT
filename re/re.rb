require 'base64'
require 'json'
require 'optparse'
require 'ostruct'
require 'paho-mqtt'

require_relative 'internals/encryption'
require_relative 'internals/serialization'
require_relative 'internals/ui'

class Re
  attr_reader :internals
  def initialize()
    @internals = {
      :optparse       => OptionParser.new,
      :mqtt           => PahoMqtt::Client.new,
      :serialization  => Internals::Serialization.new,
      :rsa            => Internals::RSA.new,
      :aes            => Internals::AES.new,
      :digest         => Internals::Digest.new,
      :ui             => Internals::UI.new
    }
    @evt_topics = []
    @topics = {}
    @packets = {}
    @connect_thread
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

  def decoryse(data)
    data = Base64.decode64(data)
    data = @internals[:rsa].decrypt(data)
    data = @internals[:serialization].deserialize(data)
    return data.transform_keys(&:to_sym)
  end

  def add_topic_callback(topic, &block)
    topic = @topics[topic]
    @evt_topics.push([topic, 2])
    @internals[:mqtt].add_topic_callback(topic, block)
  end

  def publish(topic, payload="", retain=false, qos=0)
    @internals[:mqtt].publish(@topics[topic], payload, retain, qos)
  end

  def add_topics(topics)
    topics.each do |key, value|
      topics[key] = digest_topic(value)
    end
    @topics = topics
  end

  def add_packets(packets)
    @packets = packets
  end

  def packets(packet)
    @packets[packet].dup
  end

  def connect()
    @connect_thread = Thread.new do
      begin
        init_mqtt()
        @internals[:mqtt].connect()
        @internals[:mqtt].subscribe(@evt_topics)
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

  def init_mqtt()
    config = JSON.parse(File.read('re.conf'))
    @internals[:mqtt].host = config['host']
    @internals[:mqtt].port = config['port']
    @internals[:mqtt].persistent = true
    @internals[:mqtt].blocking = true
  end
end
