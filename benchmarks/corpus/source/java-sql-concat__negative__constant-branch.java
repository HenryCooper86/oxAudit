class LocalQuery {
    void run(java.sql.Statement statement, String input) throws Exception {
        int limit = 13;
        String sql;
        if ((5 * 9) - limit > 30) sql = "SELECT 1";
        else sql = input;
        statement.execute(sql);
    }
}
