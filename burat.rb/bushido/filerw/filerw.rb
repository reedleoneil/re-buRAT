class File
  attr_reader :id, :path

  def initialize(params)
    @id = params[:id]
    @path = params[:path]
  end

  def read(length, offset)
    data = File.binread(@path, length, offset)
    return data
  end

  def write(data, offset)
    length = File.binwrite(@path, data, offset)
    return length
  end
end
