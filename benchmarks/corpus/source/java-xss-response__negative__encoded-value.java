import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class Search {
    void render(HttpServletRequest request, HttpServletResponse response) throws Exception {
        // Escapes markup, which is the weakness this sink carries.
        String safe = org.owasp.esapi.ESAPI.encoder().encodeForHTML(request.getParameter("q"));
        response.getWriter().println(safe);
    }
}
