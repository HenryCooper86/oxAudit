using System.Data.SqlClient;

class UserRepo {
    public SqlCommand Find(SqlConnection db, string id) {
        var command = new SqlCommand("SELECT * FROM Users WHERE Id = @id", db);
        command.Parameters.AddWithValue("@id", id);
        return command;
    }
}
