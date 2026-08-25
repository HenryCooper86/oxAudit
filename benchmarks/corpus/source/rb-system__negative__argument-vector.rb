class Archiver
  def run(params)
    # An argument vector never reaches a shell, so metacharacters are inert.
    system("tar", "-czf", "out.tgz", params[:dir])
  end
end
