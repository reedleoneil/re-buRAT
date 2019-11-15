require 'open3'

class RemoteShellInator
	attr_reader :remote_shells
	def initialize
		@remote_shells = []
		@on_open = lambda { |pid, shell| puts "@on_open" }
		@on_close = lambda { |pid| puts "@on_close" }
		@on_read = lambda { |pid, data| puts "@on_read" }
		@on_write = lambda { |pid, data| puts "@on_write" }
		@on_error = lambda { |pid, error| puts "@on_error" }
	end

	def on(event, &callback)
		case event
		when :open	
			@on_open = callback
		when :close
			@on_close = callback
		when :read
			@on_read = callback
		when :write
			@on_write = callback
		when :error
			@on_error = callback
		end
	end

	def open(shell)
		remote_shell = Open3.popen2e(shell)
		remote_shell.push shell
		@remote_shells.push remote_shell
		Thread.new {
			begin
				while line = remote_shell[1].gets
					@on_read.call(remote_shell[2].pid, line)
				end
			rescue StandardError => msg
				@on_error.call(remote_shell[2].pid, msg)
			end
		}
		@on_open.call(remote_shell[2].pid, shell)
	end

	def close(pid)
		remote_shell = @remote_shells.find { |remote_shell| remote_shell[2].pid == pid }
		remote_shell[0].close
		remote_shell[1].close
		Process.kill("KILL", remote_shell[2].pid)
		@remote_shells.delete remote_shell
		@on_close.call(remote_shell[2].pid)
	end

	def write(pid, data)
		remote_shell = @remote_shells.find { |remote_shell| remote_shell[2].pid == pid }
		remote_shell[0].puts data
		@on_write.call(remote_shell[2].pid, data)
	end
end
