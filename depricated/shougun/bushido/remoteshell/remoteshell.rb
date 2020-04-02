require 'open3'

class RemoteShell
  attr_reader :id, :shell

  def initialize(params)
    @id = params[:id]
    @shell = params[:shell]
    @on_read = lambda { |data| puts data}
    @on_error = lambda { |error| puts error}
  end

  def on(event, &handler)
    case event
    when :read
      @on_read = handler
    when :error
      @on_error = handler
    end
  end

  def open
    @remote_shell = Open3.popen2e(@shell)
    @remote_shell[0].binmode
    @remote_shell[1].binmode
    @remote_shell.push Thread.new {
      begin
        while data = @remote_shell[1].gets
          @on_read.call(data)
        end
      rescue StandardError => error
        @on_error.call(error)
      end
    }
  end

  def close
    @remote_shell[3].kill
    @remote_shell[2].kill
    @remote_shell[1].close
    @remote_shell[0].close
  end

  def write(data)
    @remote_shell[0].puts(data)
  end
end
