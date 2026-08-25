using System.Data.SqlClient;

class UserRepo {
    public SqlCommand Find(string id) {
        return new SqlCommand("SELECT * FROM Users WHERE Id = " + id);
    }
}
