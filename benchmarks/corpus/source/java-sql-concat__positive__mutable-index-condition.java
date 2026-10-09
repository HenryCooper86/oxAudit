class IndexQuery {
    void run(java.sql.Statement statement, String input) throws Exception {
        int count = 0;
        String[] slots = {"unused"};
        slots[count++] = input;
        String sql = count == 0 ? "SELECT 1" : input;
        statement.execute(sql);
    }
}
