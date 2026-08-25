import javax.servlet.http.HttpServletRequest;

class UserRepo {
    void find(java.sql.Connection db, HttpServletRequest request) throws Exception {
        // The commonest real shape: build the query into a variable, then run
        // it. The rule originally required the concatenation to appear inside
        // the execute call and missed every case written this way.
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = " + id;
        db.prepareStatement(sql).executeQuery();
    }
}
