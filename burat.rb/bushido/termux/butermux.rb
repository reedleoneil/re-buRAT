require_relative 'termux'

module Bushido
  class BuTermux
    attr_reader :termuxs

    def initialize
      @termuxs = []
      @on_open = lambda { |id| puts "termux@on_open id=#{id}" }
      @on_close = lambda { |id| puts "termux@on_close id=#{id}" }
      @on_audio_info = lambda { |id, data| puts "termux@on_audio_info id=#{id} data=#{data}" }
      @on_battery_status = lambda { |id, data| puts "termux@on_battery_status id=#{id} data=#{data}" }
      @on_call_log = lambda { |id, data| puts "termux@on_call_log id=#{id} data=#{data}" }
      @on_camera_info = lambda { |id, data| puts "termux@on_camera_info id=#{id} data=#{data}" }
      @on_camera_photo = lambda { |id, data| puts "termux@on_camera_photo id=#{id} data=#{data}" }
      @on_contact_list = lambda { |id, data| puts "termux@on_contact_list id=#{id} data=#{data}" }
      @on_sms_list = lambda { |id, data| puts "termux@on_sms_list id=#{id} data=#{data}" }
      @on_device_info = lambda { |id, data| puts "termux@on_device_info id=#{id} data=#{data}" }
      @on_wifi_connection_info = lambda { |id, data| puts "termux@on_wifi_connection_info id=#{id} data=#{data}" }
      @on_wifi_scan_info = lambda { |id, data| puts "termux@on_wifi_scan_info id=#{id} data=#{data}" }
    end

    def on(event, &handler)
      case event
      when :open
        @on_open = handler
      when :close
        @on_close = handler
      when :audio_info
        @on_audio_info = handler
      when :battery_status
        @on_battery_status = handler
      when :call_log
        @on_call_log = handler
      when :camera_info
        @on_camera_info = handler
      when :camera_photo
        @on_camera_photo = handler
      when :contact_list
        @on_contact_list = handler
      when :sms_list
        @on_sms_list = handler
      when :device_info
        @on_device_info = handler
      when :wifi_connection_info
        @on_wifi_connection_info = handler
      when :wifi_scan_info
        @on_wifi_scan_info = handler
      end
    end

    def open(id)
      termux = Termux.new({
        :id => id
      })
      @termuxs.push termux
      @on_open.call(id)
    end

    def close(id)
      termux = @termuxs.find { |termux| termux.id = id }
      @termuxs.delete termux
      @on_close.call(id)
    end

    def audio_info(id)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_audio_info.call(id, termux.audio_info())
    end

    def battery_status(id)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_battery_status.call(id, termux.battery_status())
    end

    def call_log(id, limit = 10, offset = 0)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_call_log.call(id, termux.call_log(limit, offset))
    end

    def camera_info(id)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_camera_info.call(id, termux.camera_info())
    end

    def camera_photo(id, camera_id = 0, output_file)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_camera_photo.call(id, termux.camera_photo(camera_id, output_file))
    end

    def contact_list(id)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_contact_list.call(id, termux.contact_list())
    end

    def sms_list(id, limit = 10, offset = 0, type = 'all')
      termux = @termuxs.find { |termux| termux.id = id }
      @on_sms_list.call(id, termux.sms_list(limit, offset, type))
    end

    def sms_send(id, number, text)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_sms_send.call(id, termux.sms_send(number, text))
    end

    def telephony_call(id, number)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_telephony_call.call(id, termux.telephony_call(number))
    end

    def device_info(id)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_device_info.call(id, termux.device_info())
    end

    def wifi_connection_info(id)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_wifi_connection_info.call(id, termux.wifi_connection_info())
    end

    def wifi_scan_info(id)
      termux = @termuxs.find { |termux| termux.id = id }
      @on_wifi_scan_info.call(id, termux.wifi_scan_info())
    end

  end
end
