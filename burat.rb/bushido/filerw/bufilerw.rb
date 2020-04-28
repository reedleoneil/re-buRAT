require_relative 'filerw'

module Bushido
  class BuFileReadWrite
    attr_reader :files

    def initialize
      @files = []
      @on_open  = lambda { |id| puts "remoteshell@on_open id=#{id}" }
      @on_close = lambda { |id| puts "remoteshell@on_close id=#{id}" }
      @on_read  = lambda { |id, data, offset| puts "filerw@read id=#{id} data=#{data} offset=#{offset}" }
      @on_write = lambda { |id, length, offset| puts "filerw@write id=#{id} length=#{length} offset=#{offset}" }
      @on_error = lambda { |id, error| puts "filerw@error = id=#{id} error=#{error}" }
    end

    def on(event, &handler)
      case event
      when :open
        @on_open = handler
      when :close
        @on_close = handler
      when :read
        @on_read = handler
      when :write
        @on_write = handler
      when :error
        @on_error = handler
      end
    end

    def open(id, path)
      file = File.new({
        :id => id,
        :path => path
      })
      @files.push file
      @on_open.call(id)
    end

    def close(id)
      file = @files.find { |file| file.id == id }
      @files.delete file
      @on_close.call(id)
    end

    def read(id, length, offset)
      file = @files.find { |file| file.id == id }
      begin
        data = file.read(length, offset)
        @on_read.call(id, data, offset)
      rescue StandardError => error
        @on_error.call(id, error.full_message)
      end
    end

    def write(id, data, offset)
      file = @files.find { |file| file.id == id }
      begin
        length = file.write(data, offset)
        @on_write.call(id, length, offset)
      rescue StandardError => error
        @on_error.call(id, error.full_message)
      end
    end
  end
end
