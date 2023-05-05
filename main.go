package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

var help = `
Usage: unpacify [ARGUMENTS]

unpacify is a utility for decrypting source code of re: buRAT.

ARGUMENTS:
  key               The key to be used to decrypt the source code.

EXAMPLES:
  unpacify 2560ec90c6b2eeb75bc1d82d08aa1a7b
`

var banner = `
         $               ██▀███  ▓█████     ▄▄▄▄    █    ██  ██▀███   ▄▄▄     ▄▄▄█████▓
   *1▒g▒#▒$▒▒1▒,Q       ▓██ ▒ ██▒▓█   ▀    ▓█████▄  ██  ▓██▒▓██ ▒ ██▒▒████▄   ▓  ██▒ ▓▒
  ▒▒▒▒▒▒▒▒▓▒▒▒▒▒        ▓██ ░▄█ ▒▒███      ▒██▒ ▄██▓██  ▒██░▓██ ░▄█ ▒▒██  ▀█▄ ▒ ▓██░ ▒░
 #/▒▒▒▒▓▒▒▒▓▒▒▓▒g       ▒██▀▀█▄  ▒▓█  ▄    ▒██░█▀  ▓▓█  ░██░▒██▀▀█▄  ░██▄▄▄▄██░ ▓██▓ ░ 
 1▒▒▒▒▒R▒▒▒▓▓▓▒▒▒▒▓\    ░██▓ ▒██▒░▒████▒   ░▓█  ▀█▓▒▒█████▓ ░██▓ ▒██▒ ▓█   ▓██▒ ▒██▒ ░ 
 /@ $@@,0▒▒1▒|7$e$,     ░ ▒▓ ░▒▓░░░ ▒░ ░   ░▒▓███▀▒░▒▓▒ ▒ ▒ ░ ▒▓ ░▒▓░ ▒▒   ▓▒█░ ▒ ░░   
       4j7▒4!             ░▒ ░ ▒░ ░ ░  ░   ▒░▒   ░ ░░▒░ ░ ░   ░▒ ░ ▒░  ▒   ▒▒ ░   ░    
|       #7Y*       \      ░░   ░    ░       ░    ░  ░░░ ░ ░   ░░   ░   ░   ▒    ░      
4▒    #▒4▒▓9      4        ░        ░  ░    ░         ░        ░           ░  ░        
$▒9g e@▒▒!4▒▒$-  #e                              ░                                     
|▒▒▒▒▒#|   |e▓▒▒▓$e     				Re: mote Administration Tool
 Yeg▒▓\,   $9▒▒▒e÷4     				Re: mastered for IoT
 gp@l▒▒,▒▒Y@▒▒M7 7      				Re: written in Go
 , ▒▒@1▒▒▒▓9÷▒▒4Q       				© 2014 ~ 2023 reedleoneil
    "▓  /Q▒-▒▒7,0$    
 !     ▒▒                                       
 \▒\▒         ▒440    
 1▒\▒    *▒0    ▒     
  1▓9▒▒▓# ▒*▓   ÷     
    e▒▒▒▓▒▒  ▓▒▒▒     
       g       
`

type file struct {
	name string
}

type crypto struct {
	key string
}

// HIRO's key fragment and signature hash
// the last 12 digits would approximately take years to brute force (at the time of this writing)
const (
	fragmentCount int    = 12
	keyFragment   string = "4c7aa27fb1e4c3e4e4b5" // 4c7aa27fb1e4c3e4e4b5XXXXXXXXXXXX
	sigHash       string = "7c6e3bf7782502e0a4e29cb627e46801"
)

var (
	digits []rune    = []rune{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}
	tStart time.Time = time.Now()
)

//go:embed re-buRAT.hiro
var hiro []byte

// https://www.youtube.com/watch?v=7NK_JOkuSVY
// https://www.youtube.com/watch?v=v2H4l9RpkwM
// https://www.youtube.com/watch?v=eVTXPUF4Oz4
func main() {
	if len(os.Args) == 1 {
		fmt.Println(help)
		return
	}

	sc := file{
		name: "re-buRAT.zip", // source code deleted, unpacify rei to obtain source code
	}
	rei := file{
		name: "re-buRAT.rei", // rei, the pacified source code
	}
	hiro := file{
		name: "re-buRAT.hiro", // hiro, the pacified rei file
	}
	c1 := crypto{
		key: "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", // key deleted, craft the key
	}
	c2 := crypto{
		key: "4c7aa27fb1e4c3e4e4b5XXXXXXXXXXXX", // key fragment (last 12 digit) deleted, brute force the key fragment
	}

	// pacify(c1)(sc.read(), rei)
	// pacify(c2)(rei.read(), hiro)
	// return

	u := func(k1, k2 string) {
		c1.key = k1
		c2.key = k2
		unpacify(c2)(hiro.read(), rei)
		unpacify(c1)(rei.read(), sc)
	}

	keyFragment := func() string {
		return keyFragment
		//return key[:32-fragmentCount]
	}

	isMatch := func(fragment string) bool {
		key := strings.ToLower(keyFragment() + fragment)
		if hash(key) == sigHash {
			return true
		}
		return false
	}

	var generateCombinations func(digits []rune, prefix string, level int)
	generateCombinations = func(digits []rune, prefix string, level int) {
		if level == fragmentCount {
			if isMatch(prefix) {
				tEnd := time.Now()
				k1 := os.Args[1]
				k2 := keyFragment() + prefix
				fmt.Print(banner)
				fmt.Println("HIRO's KEY : " + k2 + " found in " + tEnd.Sub(tStart).String())
				fmt.Println("REI's KEY : " + k1)
				u(k1, k2)
				os.Exit(0)
			}
			return
		}

		for _, digit := range digits {
			generateCombinations(digits, prefix+string(digit), level+1)
		}
	}

	generateCombinations(digits, "", 0)
	fmt.Println("☠︎")
}

func unpacify(c crypto) func(i []byte, fo file) {
	return func(i []byte, fo file) {
		b, _ := c.decryptWithKey(i, c.key)
		fo.write(b)
	}
}

func pacify(c crypto) func(i []byte, fo file) {
	return func(i []byte, fo file) {
		b, _ := c.encryptWithKey(i, c.key)
		fo.write(b)
	}
}

func (s *crypto) encryptWithKey(data []byte, encodedKey string) (ciphertext []byte, err error) {
	block, err := newCipher(encodedKey)
	if err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	return
}

func (s *crypto) decryptWithKey(ciphertext []byte, encodedKey string) (data []byte, err error) {
	block, err := newCipher(encodedKey)
	if err != nil {
		return nil, err
	}
	data = make([]byte, len(ciphertext)-aes.BlockSize)
	stream := cipher.NewCTR(block, ciphertext[:aes.BlockSize])
	stream.XORKeyStream(data, ciphertext[aes.BlockSize:])
	return
}

func (f *file) read() (data []byte) {
	data, err := ioutil.ReadFile(f.name)
	if err != nil {
		panic(err)
	}
	return
}

func (f *file) write(data []byte) {
	file, err := os.Create(f.name)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	err = ioutil.WriteFile(f.name, data, 0644)
	if err != nil {
		panic(err)
	}
}

func newCipher(encodedKey string) (block cipher.Block, err error) {
	key, _ := hex.DecodeString(encodedKey)
	block, err = aes.NewCipher(key)
	return
}

func hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}
