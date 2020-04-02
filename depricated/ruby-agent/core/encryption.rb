require 'openssl'

module Encryption
  class RSA
    def RSA.config(config)
      @@key = OpenSSL::PKey::RSA.new(config[:key_size] || config[:encoded_key])
    end

    def RSA.public_key
      @@key.public_key.to_pem
    end

    def RSA.encrypt(data)
      @@key.public_encrypt(data)
    end

    def RSA.decrypt(data)
      @@key.private_decrypt(data)
    end
  end

  class AES
    def AES.config(config)
      @@key_lenght = config[:key_lenght]
      @@mode = config[:mode]
      @@key = config[:key]
      @@iv = config[:iv]
    end

    def AES.encrypt(data)
      cipher = OpenSSL::Cipher::AES.new(@@key_lenght, @@mode)
      cipher.key = @@key
      cipher.iv = @@iv
      cipher.encrypt
      cipher.update(data) + cipher.final
    end

    def AES.decrypt(data)
      decipher = OpenSSL::Cipher::AES.new(@@key_lenght, @@mode)
      decipher.key = @@key
      decipher.iv = @@iv
      decipher.decrypt
      decipher.update(data) + decipher.final
    end
  end

  class Digest
    def Digest.config(config)
      @@digest = OpenSSL::Digest.new(config[:digest])
    end

    def Digest.digest(data)
      @@digest.hexdigest(data)
    end
  end
end
