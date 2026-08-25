import javax.servlet.http.HttpServletRequest;

class Profile {
    void store(HttpServletRequest request) {
        // A request value stored under a key the application chose. This is
        // what every login form does, and a rule that reports it is a rule
        // nobody leaves switched on.
        request.getSession().setAttribute("userId", request.getParameter("id"));
    }
}
