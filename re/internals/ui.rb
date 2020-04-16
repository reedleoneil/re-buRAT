require 'tty-cursor'
require 'tty-font'
require 'tty-progressbar'
require 'tty-table'

module Internals
  class UI
    def render_table_bushi(bushi)
      data = []
      bushi.each_value do |value|
        data.push(value.fetch_values(:id, :host, :os, :ip, :status))
      end

      cursor = TTY::Cursor
      print cursor.move_to(0, 0)
      print cursor.clear_screen
      header = ['ID', 'HOST', 'OS', 'IP', 'STATUS']
      rows = data
      table = TTY::Table.new header, rows
      puts table.render :unicode, resize: true
    end

    def render_banner(banner)
      font = TTY::Font.new(['3d', 'block', 'doom', 'standard', 'starwars', 'straight'].sample)
      puts font.write(banner)
    end

    def progressbar(total)
      TTY::ProgressBar.new(
        "ETA :eta [:bar] :percent :current_byte/:total_byte :byte_rate/s :elapsed",
        total: total,
        width: 100,
        frequency: 60,
        interval: 1
      )
    end
  end
end
