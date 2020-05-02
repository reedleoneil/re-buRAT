class Termux
  attr_reader :id
  def initialize(params)
    @id = params[:id]
  end

  def audio_info()
    parse(`termux-audio-info`)
  end

  def battery_status()
    parse(`termux-battery-status`)
  end

  def call_log(limit, offset)
    parse(`termux-call-log -l #{limit} -o #{offset}`)
  end

  def camera_info()
    parse(`termux-camera-info`)
  end

  def camera_photo(camera_id, output_file)
    `termux-camera-info -c #{camera_id} #{output_file}`
    File.read(output_file)
  end

  def contact_list()
    parse(`termux-camera-info`)
  end

  def sms_list(limit, offset, type)
    parse(`termux-sms-list -d -n -l #{limit} -o #{offset} -t #{type}`)
  end

  def sms_send(number, text)
    `termux-sms-send -n #{number} #{text}`
  end

  def telephony_call(number)
    `termux-telephony-call #{number}`
  end

  def device_info()
    parse(`termux-telephony-deviceinfo`)
  end

  def wifi_connection_info()
    parse(`termux-wifi-connectioninfo`)
  end

  def wifi_scan_info()
    parse(`termux-wifi-scaninfo`)
  end

  private
  def parse(data)
    return OpenStruct.new JSON.parse(data)
  end
end
