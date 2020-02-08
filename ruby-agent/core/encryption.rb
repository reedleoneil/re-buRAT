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
        @@cipher = OpenSSL::Cipher::AES.new(config[:key_lenght], config[:mode])
        @@cipher.key = config[:key]
        @@cipher.iv = config[:iv]
      end

      def AES.encrypt(data)
        @@cipher.encrypt
        @@cipher.update(data) + @@cipher.final
      end

      def AES.decrypt(data)
        @@cipher.decrypt
        @@cipher.update(data) + @@cipher.final
      end
  end
end
