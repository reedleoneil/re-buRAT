require 'tty-table'
require 'tty-cursor'

module Internals
  class UI
    def render_bushi_table(data)
      cursor = TTY::Cursor
      print cursor.move_to(0, 0)
      print cursor.clear_screen
      header = ['ID', 'HOST', 'OS', 'IP', 'STATUS']
      rows = data
      table = TTY::Table.new header, rows
      puts table.render :unicode, resize: true
    end
  end
end
