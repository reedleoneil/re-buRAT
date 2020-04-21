package internals

import(
  "crypto/md5"
  "io"
  "encoding/hex"
)

type digest struct {

}

type Digest interface {
  Digest(data string) string
}

func NewDigest() *digest {
  d := &digest {}
  return d
}

func (d *digest) Digest(data string) string {
  h := md5.New()
	io.WriteString(h, data)
  return hex.EncodeToString(h.Sum(nil))
}
