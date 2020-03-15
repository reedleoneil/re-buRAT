require 'msgpacker'

module Bushido
  class Serialization
    def serialize(data)
      MessagePack.pack(data)
    end

    def deserialize(data)
      MessagePack.unpack(data)
    end
  end
end
