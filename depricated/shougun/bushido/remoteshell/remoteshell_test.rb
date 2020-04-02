require_relative 'buremoteshell'

buremoteshell = Bushido::BuRemoteShell.new

buremoteshell.on :open do |id|
  puts "open #{id}"
end

buremoteshell.on :close do |id|
  puts "close #{id}"
end

buremoteshell.on :read do |id, data|
  puts "read #{id} #{data}"
end

buremoteshell.on :write do |id, data|
  puts "write #{id} #{data}"
end

buremoteshell.on :error do |id, error|
  puts "error #{id} #{error}"
end

buremoteshell.open('54321', 'bash')
buremoteshell.open('12345', 'bash')
buremoteshell.write('54321', 'whoami')
buremoteshell.write('12345', 'whoami')
buremoteshell.remoteshells.each do |remoteshell|
  puts remoteshell.id + " " + remoteshell.shell
end
sleep 1
buremoteshell.close('12345')
