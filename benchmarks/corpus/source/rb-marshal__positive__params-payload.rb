class SessionStore
  def restore(params)
    Marshal.load(params[:state])
  end
end
