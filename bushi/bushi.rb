require 'securerandom'
require 'os'
require 'open-uri'
require 'paho-mqtt'

require_relative 'bushido/remoteshell/buremoteshell'

class Bushi
  attr_reader :id, :host, :os, :ip
  attr_accessor :status, :bushido
  def initialize()
    @id = SecureRandom.hex(2)
    @host = (OS.windows? ? `ver` : `uname -sr`).strip
    @os = OS.windows? ? `whoami`.strip : `uname -n`.strip + '\\' + `whoami`.strip
    @ip = open('http://whatismyip.akamai.com').read
    @status = :offline
    @bushido = {
      :mqtt         => PahoMqtt::Client.new,
      :remoteshell  => Bushido::BuRemoteShell.new
    }
  end
end
