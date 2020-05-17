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

    def on(event, &handler)
      case event
      when :render_termux
        @on_render_termux = handler
      end
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

    def render_termux_ui()
      clear_screen()
      pastel = Pastel.new
      puts pastel.inverse.bold("TM 4g📶 Smart H+📶 🎧 📡 🔋38%")

      prompt = TTY::Prompt.new
      menu = [
        { :name => "📞 Call #{pastel.underline.bold('L')}og", :value => 'l' },
        { :name => "✉️  #{pastel.underline.bold('S')}MS", :value => 's'},
        { :name => "📱 #{pastel.underline.bold('C')}ontacts", :value => 'c'},
        { :name => "📷 Ca#{pastel.underline.bold('m')}era", :value => 'm'}
      ]
      prompt = prompt.select('Select Menu:', menu, filter: true, per_page: 4, help: '')
      @on_render_termux.call(prompt)
    end

    def render_call_log(call_log)
      pastel = Pastel.new
      prompt = TTY::Prompt.new
      menu = []
      call_log.each do |log|
      menu << { 
        :name => "#{pastel.bold(log['name']).ljust(22)} #{log['date']}\n  #{log['phone_number'].ljust(28)} #{log['duration']}",
        :value => log['phone_number']
      }
      end
      prompt.select(' ', menu, filter: true, per_page: 4, help: '')
    end

    def render_sms_list(sms_list)
      pastel = Pastel.new
      threads = sms_list.uniq{ |sms| sms['threadid'] }
      prompt = TTY::Prompt.new
      menu = []
      threads.each do |thread|
      menu << {
         :name => "#{pastel.bold(thread['sender'] ? thread['sender'] : thread['number']).ljust(22)} #{thread['received']}\n  #{thread['body'][0..30].gsub("\n", ' ')}",
         :value => thread['threadid']
      }
      end
      prompt.select(' ', menu, filter: true, per_page: 4, help: '')
    end

    def render_contacts(contacts)
      pastel = Pastel.new
      prompt = TTY::Prompt.new
      menu = []
      contacts.each do |contact|
        menu << { 
        :name => "#{pastel.bold(contact['name'])}\n  #{contact['number']}", :value => contact['number'] }
      end
      prompt.select(' ', menu, filter: true, per_page: 4, help: '')
    end

    private
    def clear_screen()
      cursor = TTY::Cursor
      print cursor.move_to(0, 0)
      print cursor.clear_screen
    end
  end
end
