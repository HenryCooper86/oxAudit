require "json"

class SessionStore
  def restore(params)
    # JSON.parse builds plain data; it cannot instantiate arbitrary classes.
    JSON.parse(params[:state])
  end
end
