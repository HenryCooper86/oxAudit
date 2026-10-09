class OverflowQuery {
    void run(java.sql.Statement statement, String input) throws Exception {
        int count = 2147483647;
        String sql = count + 1 < 0 ? input : "SELECT 1";
        statement.execute(sql);
    }
}
