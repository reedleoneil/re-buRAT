require 'tty-table'

header1 = ['ID', 'HOST', 'OS', 'IP', 'STATUS']
rows1 = [['asdf','sample','windowws','123.123.123.123', 'online']]
table1 = TTY::Table.new header1, rows1
test1 = table1.render(:unicode)

header2 = ['ID', 'HOST', 'OS', 'IP', 'STATUS']
rows2 = [['asdf','sample','windowws','123.123.123.123', "123"]]
table2 = TTY::Table.new header2, rows2
test2 = table2.render :unicode

header3 = ['ID', 'HOST']
rows3 = [['test1',test2]]
table3 = TTY::Table.new header3, rows3
test3 = table3.render :unicode, resize: true, multiline: true

puts test3
