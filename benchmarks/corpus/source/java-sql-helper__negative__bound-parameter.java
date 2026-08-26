import javax.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;

class Users {
    // Deliberately NOT reported: the statement is constant and the value is
    // bound. The bound value being attacker-controlled is the point of
    // binding it, so reading it would mean reporting this rule's own
    // remediation.
    Long lookup(JdbcTemplate jdbcTemplate, HttpServletRequest request) {
        return jdbcTemplate.queryForObject(
                "SELECT id FROM users WHERE name = ?", Long.class, request.getParameter("name"));
    }
}
