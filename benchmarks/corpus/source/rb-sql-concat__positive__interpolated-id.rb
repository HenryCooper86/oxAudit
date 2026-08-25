class UserRepo
  def find(connection, params)
    connection.execute("SELECT * FROM users WHERE id = #{params[:id]}")
  end
end
