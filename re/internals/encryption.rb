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
    attr_reader :key, :iv
    def config(config)
      @cipher = OpenSSL::Cipher::AES.new(config[:key_length], config[:mode])
      @key = config[:key] ? config[:key] : @cipher.random_key
      @iv = config[:iv] ? config[:iv] : @cipher.random_iv
    end

    def encrypt(data)
      cipher = @cipher
      cipher.key = @key
      cipher.iv = @iv
      cipher.encrypt
      cipher.update(data) + cipher.final
    end

    def decrypt(data)
      decipher = @cipher
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
