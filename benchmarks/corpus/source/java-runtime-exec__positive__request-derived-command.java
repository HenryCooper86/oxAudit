import javax.servlet.http.HttpServletRequest;

class AdminDiagnostics {
    void run(HttpServletRequest request) throws Exception {
        String command = request.getParameter("command");
        Runtime.getRuntime().exec(command);
    }
}
