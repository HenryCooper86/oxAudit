import javax.servlet.http.HttpServletRequest;

class UserRepo {
    void find(java.sql.Statement statement, Params params) throws Exception {
        // `params.get("id")` takes a constant key and returns whatever the
        // caller's request held. Treating an unmodelled callee as a function
        // of its arguments would call this constant and hide the injection —
        // measured at 11 hidden vulnerabilities on the OWASP Benchmark, so
        // the analysis deliberately keeps Unknown here.
        String sql = "SELECT * FROM users WHERE id = " + params.get("id");
        statement.execute(sql);
    }
}
