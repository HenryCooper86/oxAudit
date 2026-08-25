class UserRepo {
    void find(java.sql.Connection db, String id) throws Exception {
        // Same shape, constant query text: the id is bound by the driver.
        String sql = "SELECT * FROM users WHERE id = ?";
        java.sql.PreparedStatement statement = db.prepareStatement(sql);
        statement.setString(1, id);
        statement.executeQuery();
    }
}
