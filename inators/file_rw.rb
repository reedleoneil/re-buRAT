class FileReadWriteInator
	def initialize
		@on_read = lambda { |file, length, offset, data| puts "file_rw@on_read" }
		@on_write = lambda { |file, data, offset, length| puts "file_rw@on_write" }
		@on_error = lambda { |file, error| puts "file_rw@on_error" }
	end

	def on(event, &callback)
		case event
		when :read
			@on_read = callback
		when :write
			@on_write = callback
		when :error
			@on_error = callback
		end
	end

	def read(file, length, offset)
		begin
			data = File.binread(file, length, offset)
			@on_read.call(file, length, offset, data)
		rescue StandardError => msg
			@on_error.call(file, msg)
		end
	end

	def write(file, data, offset)
		begin
			length = File.binwrite(file, data, offset)
			@on_write.call(file, data, offset, length)
		rescue StandardError => msg
			@on_error.call(file, msg)
		end
	end
end
