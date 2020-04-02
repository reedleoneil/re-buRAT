require_relative 'bufilerw'

filerw = Bushido::BuFileReadWrite.new

filerw.on :open do |id|
  puts "open #{id}"
end

filerw.on :close do |id|
  puts "close #{id}"
end


filerw.open(456, 'test', :write, 100)
filerw.write(456, 'hi')
filerw.write(456, 'hellow')
puts filerw.files[0].bytesio

filerw.open(123, 'test', :read, 100)
filerw.read(123, 4)
filerw.read(123, 4)
puts filerw.files[0].bytesio

filerw.close(456)
filerw.close(123)
