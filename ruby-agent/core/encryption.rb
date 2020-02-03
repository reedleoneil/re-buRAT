require 'openssl'
require 'singleton'

class Encryption
  def Encryption.config(config)
    @@bu_key = config[:bu_key]
    @key = OpenSSL::PKey::RSA.new(2408)
    @@public_key = @key.public_key
  end

  def Encryption.encrypt(data)
    puts @@bu_key
    test = OpenSSL::PKey::RSA.new(@@bu_key)
    test.public_encrypt(data)
  end

  def Encryption.decrypt(data)
    @key.private_decrypt(data)
  end

  def Encryption.public_key
    @public_key
  end
end
