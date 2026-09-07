class CustomerRepository {
    void find(java.sql.Connection connection, String customerId) throws Exception {
        java.sql.PreparedStatement query = connection.prepareStatement(
            "SELECT * FROM customers WHERE id = ?"
        );
        query.setString(1, customerId);
        query.executeQuery();
    }
}
