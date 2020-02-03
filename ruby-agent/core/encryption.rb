require 'openssl'
require 'singleton'

class Encryption
  def Encryption.config(config)
    @@bu_key = OpenSSL::PKey::RSA.new(config[:bu_key])
    @@key = OpenSSL::PKey::RSA.new(2408)
  end

  def Encryption.encrypt(data)
    @@bu_key.public_encrypt(data)
  end

  def Encryption.decrypt(data)
    @@key.private_decrypt(data)
  end

  def Encryption.public_key
    @@key.public_key.to_pem
  end
end
