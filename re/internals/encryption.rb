require 'openssl'

module Internals
  class RSA
    def config(config)
      @key = OpenSSL::PKey::RSA.new(config[:key_size] || config[:encoded_key])
    end

    def public_key
      @key.public_key.to_pem
    end

    def encrypt(data)
      @key.public_encrypt(data)
    end

    def decrypt(data)
      @key.private_decrypt(data)
    end
  end

  class AES
    def config(config)
      @key_length = config[:key_length]
      @mode = config[:mode]
      @key = config[:key]
      @iv = config[:iv]
    end

    def encrypt(data)
      cipher = OpenSSL::Cipher::AES.new(@key_length, @mode)
      cipher.key = @key
      cipher.iv = @iv
      cipher.encrypt
      cipher.update(data) + cipher.final
    end

    def decrypt(data)
      decipher = OpenSSL::Cipher::AES.new(@key_length, @mode)
      decipher.key = @key
      decipher.iv = @iv
      decipher.decrypt
      decipher.update(data) + decipher.final
    end
  end

  class Digest
    def config(config)
      @digest = OpenSSL::Digest.new(config[:digest])
    end

    def digest(data)
      @digest.hexdigest(data)
    end
  end
end
