require 'json'

class Termux
  attr_reader :id
  def initialize(params)
    @id = params[:id]
  end

  def audio_info()
    JSON.parse(`termux-audio-info`)
  end

  def battery_status()
    JSON.parse(`termux-battery-status`)
  end

  def call_log(limit, offset)
    JSON.parse(`termux-call-log -l #{limit} -o #{offset}`)
  end

  def camera_info()
    JSON.parse(`termux-camera-info`)
  end

  def camera_photo(camera_id, output_file)
    `termux-camera-photo -c #{camera_id} #{output_file}`
    `pkill com.termux.api`
    File.binread(output_file)
  end

  def contact_list()
    JSON.parse(`termux-camera-info`)
  end

  def sms_list(limit, offset, type)
    JSON.parse(`termux-sms-list -d -n -l #{limit} -o #{offset} -t #{type}`)
  end

  def sms_send(number, text)
    `termux-sms-send -n #{number} #{text}`
  end

  def telephony_call(number)
    `termux-telephony-call #{number}`
  end

  def device_info()
    JSON.parse(`termux-telephony-deviceinfo`)
  end

  def wifi_connection_info()
    JSON.parse(`termux-wifi-connectioninfo`)
  end

  def wifi_scan_info()
    JSON.parse(`termux-wifi-scaninfo`)
  end
end
