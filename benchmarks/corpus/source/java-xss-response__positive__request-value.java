import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

class Search {
    void render(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.getWriter().println(request.getParameter("q"));
    }
}
