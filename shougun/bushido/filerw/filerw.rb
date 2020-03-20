class File
  attr_reader :id, :path, :mode, :size, :bytesio

  def initialize(params)
    @id = params[:id]
    @path = params[:path]
    @mode = params[:mode]
    @size = params[:size]
    @bytesio = 0
  end

  def read(length)
    data = File.binread(@path, length, @bytesio)
    @bytesio += length
    return data
  end

  def write(data)
    length = File.binwrite(@path, data, @bytesio)
    @bytesio += length
    return length
  end
end
