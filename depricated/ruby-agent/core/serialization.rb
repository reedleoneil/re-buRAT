require 'msgpacker'
require 'ostruct'

class Serialization
  def Serialization.config(config)

  end

  def Serialization.serialize(data)
    MessagePack.pack(data)
  end

  def Serialization.deserialize(data)
    OpenStruct.new MessagePack.unpack(data)
  end
end
