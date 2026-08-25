import javax.servlet.http.HttpServletRequest;

class Profile {
    void store(HttpServletRequest request) {
        // The attacker picks which session entry to write, so they can
        // overwrite one the application later reads back as its own.
        request.getSession().setAttribute(request.getParameter("key"), "10340");
    }
}
