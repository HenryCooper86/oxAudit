import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

class Downloads {
    // The path reaches the sink through a loop binding, an accessor on the
    // loop variable, a decoder, and a concatenation — none of which un-choose
    // a value the caller of the request chose.
    void read(HttpServletRequest request) throws Exception {
        String name = "";
        for (Cookie cookie : request.getCookies()) {
            if (cookie.getName().equals("file")) {
                name = java.net.URLDecoder.decode(cookie.getValue(), "UTF-8");
            }
        }
        String path = "/var/data/" + name;
        java.io.FileInputStream stream = new java.io.FileInputStream(new java.io.File(path));
        stream.close();
    }
}
