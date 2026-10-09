class InterpolatedQuery {
    void run(java.sql.Statement statement, String input) throws Exception {
        String sql = STR."SELECT * FROM people WHERE name = '\{input}'";
        statement.execute(sql);
    }
}
