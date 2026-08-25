class UserRepo {
    void find(java.sql.Statement statement) throws Exception {
        // The query is constant; RETURN_GENERATED_KEYS is a flags constant
        // sitting beside it. One unresolved argument used to make the whole
        // call unresolved, so this reported and the same line without the
        // second argument did not.
        String sql = "SELECT * FROM users WHERE id = 1";
        statement.execute(sql, java.sql.Statement.RETURN_GENERATED_KEYS);
    }
}
