class UserRepo
  def find(connection, params)
    # The id is bound by the driver and never becomes SQL text.
    connection.exec_params("SELECT * FROM users WHERE id = $1", [params[:id]])
  end
end
