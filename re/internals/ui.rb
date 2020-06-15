require 'pastel'
require 'tty-cursor'
require 'tty-font'
require 'tty-progressbar'
require "tty-prompt"
require 'tty-reader'
require 'tty-table'

module Internals
  class UI
    def initialize()
      @on_render_termux = lambda { |prompt| puts prompt }
    end

    def render_table_bushi(bushi)
      data = []
      bushi.each_value do |value|
        data.push(value.fetch_values(:id, :host, :os, :ip, :status))
      end

      pastel = Pastel.new
      clear_screen()
      header = ['ID', 'HOST', 'OS', 'IP', 'STATUS'].map! do |header|
        pastel.bold(header)
      end
      rows = data
      table = TTY::Table.new header, rows
      puts table.render :unicode, resize: true
    end

    def render_banner(banner)
      font = TTY::Font.new(['3d', 'block', 'doom', 'standard', 'starwars', 'straight'].sample)
      puts font.write(banner)
    end

    def progressbar_filerw(total)
      TTY::ProgressBar.new(
        "ETA :eta [:bar] :percent :current_byte/:total_byte :byte_rate/s :elapsed",
        total: total,
        width: 100,
        frequency: 60,
        interval: 1
      )
    end

    def render_profile(bushi, remoteshell, filerw)
      clear_screen()
      pastel = Pastel.new

      string = 're: buRAT'
      (TTY::Screen.width - string.length).times {
        string << " "
      }
      puts pastel.inverse.bold(string)
      table = TTY::Table.new do |t|
        t << ['id', bushi[:id]]
        t << ['host', bushi[:host]]
        t << ['os', bushi[:os]]
        t << ['ip', bushi[:ip]]
        t << ['status', bushi[:status]]
      end
      puts table.render :basic, alignments: [:right, :left], resize: true


      string = 'REMOTESHELLS'
      (TTY::Screen.width - string.length).times {
        string << " "
      }
      puts pastel.inverse.bold(string)
      table = TTY::Table.new
      remoteshell.each do |r|
        table << [r[:id], r[:shell]]
      end
      puts table.render :basic

      pastel = Pastel.new
      string = 'FILERW'
      (TTY::Screen.width - string.length).times {
        string << " "
      }
      puts pastel.inverse.bold(string)
      table = TTY::Table.new
      filerw.each do |f|
        table << [f[:id], f[:path]]
      end
      puts table.render :basic, resize: true
    end

    private
    def clear_screen()
      cursor = TTY::Cursor
      print cursor.move_to(0, 0)
      print cursor.clear_screen
    end
  end
end
