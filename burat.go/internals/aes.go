package internals

import(
  cryptoaes "crypto/aes"
	"crypto/cipher"
	"crypto/rand"
  "io"
)

type aes struct {
  key     []byte
  iv      []byte
  block   cipher.Block
}

type AES interface {
  Key()                         []byte
  Iv()                          []byte
  Encrypt(data []byte)          []byte
  Decrypt(data []byte)          []byte
}

func NewAES() *aes {
  key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

  block, _ := cryptoaes.NewCipher(key)

	a := &aes {}
  a.block = block
  a.key = key
  a.iv = iv
	return a
}

func (a *aes) Key() []byte { return a.key }

func (a *aes) Iv() []byte { return a.iv }

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
