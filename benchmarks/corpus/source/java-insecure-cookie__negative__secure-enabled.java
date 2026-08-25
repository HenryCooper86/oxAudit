import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

class Session {
    void issue(HttpServletResponse response) {
        Cookie cookie = new Cookie("sid", "abc123");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);
    }
}
