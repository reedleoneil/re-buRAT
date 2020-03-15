require 'msgpacker'

<<<<<<< HEAD
module Bushido
=======
module Core
>>>>>>> 78cd2d2dda941bbe0cd0385c823d9ab551f61517
  class Serialization
    def serialize(data)
      MessagePack.pack(data)
    end

    def deserialize(data)
      MessagePack.unpack(data)
    end
  end
end
