require_relative 'remoteshell'

module Bushido
  class BuRemoteShell
    attr_reader :remoteshells

    def initialize
      @remoteshells = []
      @on_open  = lambda { |id| puts "remoteshell@on_open id=#{id}" }
      @on_close = lambda { |id| puts "remoteshell@on_close id=#{id}" }
      @on_read  = lambda { |id, data| puts "remoteshell@on_read id=#{id} data=#{data}" }
      @on_write = lambda { |id, data|puts "remoteshell@on_write id=#{id} data=#{data}" }
      @on_error = lambda { |id, error|puts "remoteshell@on_error id=#{id} error=#{error}" }
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

    def open(id, shell)
      remoteshell = RemoteShell.new({
        :id => id,
        :shell => shell
      })
      remoteshell.on :read do |data|
        @on_read.call(id, data)
      end
      remoteshell.on :error do |error|
        @on_error.call(id, error)
      end
      remoteshell.open
      @remoteshells.push remoteshell
      @on_open.call(id)
    end

    def close(id)
      remoteshell = @remoteshells.find { |remote_shell| remote_shell.id == id }
      remoteshell.close
      @remoteshells.delete remoteshell
      @on_close.call(id)
    end

    def write(id, data)
      remoteshell = @remoteshells.find { |remote_shell| remote_shell.id == id }
      remoteshell.write(data)
      @on_write.call(id, data)
    end
  end
end
