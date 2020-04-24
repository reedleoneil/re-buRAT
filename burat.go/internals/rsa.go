package internals

import(
  cryptorsa "crypto/rsa"
  "crypto/rand"
	"crypto/x509"
  "encoding/pem"
  "errors"
)

type rsa struct {
  Key *cryptorsa.PublicKey
}

type RSA interface {
  Config(encodedKey string)
  Encrypt(data []byte) []byte
}

func NewRSA() *rsa {
	r := &rsa {}
	return r
}

func (r *rsa) Config(encodedKey string) {
  publicKey, _ := parseRsaPublicKeyFromPemStr(encodedKey)
  r.Key = publicKey
}

func (r *rsa) Encrypt(data []byte) []byte {
  encryptedData, _ := cryptorsa.EncryptPKCS1v15(rand.Reader, r.Key, data)
  return encryptedData
}

func exportRsaPrivateKeyAsPemStr(privkey *cryptorsa.PrivateKey) string {
    privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
    privkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PRIVATE KEY",
                    Bytes: privkey_bytes,
            },
    )
    return string(privkey_pem)
}

func parseRsaPrivateKeyFromPemStr(privPEM string) (*cryptorsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    return priv, nil
}

func exportRsaPublicKeyAsPemStr(pubkey *cryptorsa.PublicKey) (string, error) {
    pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
    if err != nil {
            return "", err
    }
    pubkey_pem := pem.EncodeToMemory(
            &pem.Block{
                    Type:  "RSA PUBLIC KEY",
                    Bytes: pubkey_bytes,
            },
    )

    return string(pubkey_pem), nil
}

func parseRsaPublicKeyFromPemStr(pubPEM string) (*cryptorsa.PublicKey, error) {
    block, _ := pem.Decode([]byte(pubPEM))
    if block == nil {
            return nil, errors.New("failed to parse PEM block containing the key")
    }

    pub, err := x509.ParsePKIXPublicKey(block.Bytes)
    if err != nil {
            return nil, err
    }

    switch pub := pub.(type) {
    case *cryptorsa.PublicKey:
            return pub, nil
    default:
            break // fall through
    }
    return nil, errors.New("Key type is not RSA")
}
