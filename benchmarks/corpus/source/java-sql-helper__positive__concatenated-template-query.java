import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;

class Users {
    Long lookup(JdbcTemplate jdbcTemplate, HttpServletRequest request) {
        String sql = "SELECT id FROM users WHERE name = '" + request.getParameter("name") + "'";
        return jdbcTemplate.queryForObject(sql, Long.class);
    }
}
