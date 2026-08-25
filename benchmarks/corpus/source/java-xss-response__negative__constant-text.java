import javax.servlet.http.HttpServletResponse;

class Search {
    void render(HttpServletResponse response) throws Exception {
        response.getWriter().println("No results found.");
    }
}
