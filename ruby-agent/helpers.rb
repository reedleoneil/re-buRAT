require 'msgpacker'
require 'ostruct'

module Serialization
  def Serialization.serialize(data)
    MessagePack.pack(data)
  end

  def Serialization.deserialize(data)
    OpenStruct.new MessagePack.unpack(data)
  end
end

module Encryption
  def Encryption.encrypt(data)
    data
  end

  def Encryption.decrypt(data)
    data
  end
end
