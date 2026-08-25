import javax.servlet.http.HttpServletRequest;

class Archiver {
    void run(HttpServletRequest request) throws Exception {
        // Ordinary Java: take the Runtime once, use it later. The rule
        // required the whole `Runtime.getRuntime().exec(` chain in one
        // expression and missed every command injection written this way —
        // 93 of the OWASP Benchmark's 126 labelled cases.
        Runtime runtime = Runtime.getRuntime();
        runtime.exec(request.getParameter("cmd"));
    }
}
