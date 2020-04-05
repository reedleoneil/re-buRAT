require_relative 'filerw'

module Bushido
  class BuFileReadWrite
    attr_reader :files

    def initialize
      @files = []
      @on_open  = lambda { |id| puts "remoteshell@on_open id=#{id}" }
      @on_close = lambda { |id| puts "remoteshell@on_close id=#{id}" }
      @on_read  = lambda { |id, data| puts "filerw@read id=#{id} data=#{data}" }
      @on_write = lambda { |id, length| puts "filerw@write id=#{id} length=#{length}" }
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

    def open(id, path, mode, size)
      file = File.new({
        :id => id,
        :path => path,
        :mode => mode,
        :size => size
      })
      @files.push file
      @on_open.call(id)
    end

    def close(id)
      file = @files.find { |file| file.id == id }
      @files.delete file
      @on_close.call(id)
    end

    def read(id, length)
      file = @files.find { |file| file.id == id }
      begin
        data = file.read(length)
        @on_read.call(id, data)
      rescue StandardError => error
        @on_error.call(id, error.full_message)
      end
    end

    def write(id, data)
      file = @files.find { |file| file.id == id }
      begin
        length = file.write(data)
        @on_write.call(id, length)
      rescue StandardError => error
        @on_error.call(id, error.full_message)
      end
    end
  end
end
