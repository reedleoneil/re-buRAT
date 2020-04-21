package internals

import(
  cryptoaes "crypto/aes"
	"crypto/cipher"
)

type aes struct {
  key     []byte
  iv      []byte
  block   cipher.Block
}

type AES interface {
  Key()     []byte
  Iv()      []byte
  Config()
  Encrypt() []byte
  Decrypt() []byte
}

func NewAES() *aes {
	a := &aes {}
	return a
}

func (a *aes) Key() []byte {
  return a.key
}

func (a *aes) Iv() []byte {
  return a.iv
}

func (a *aes) Config(key []byte, iv []byte) {
  block, _ := cryptoaes.NewCipher(key)
  a.block = block
  a.key = key
  a.iv = iv
}

func (a *aes) Encrypt(data []byte) []byte {
  encryptedData := make([]byte, len(data))
  stream := cipher.NewCTR(a.block, a.iv)
  stream.XORKeyStream(encryptedData, data)
  return encryptedData
}

func (a *aes) Decrypt(data []byte) []byte {
  decryptedData := make([]byte, len(data))
  stream := cipher.NewCTR(a.block, a.iv)
  stream.XORKeyStream(decryptedData, data)
  return decryptedData
}
