import javax.servlet.http.HttpServletRequest;

class CustomerRepository {
    void find(java.sql.Statement statement, HttpServletRequest request) throws Exception {
        String customerId = request.getParameter("customerId");
        String query = "SELECT * FROM customers WHERE id = " + customerId;
        statement.executeQuery(query);
    }
}
