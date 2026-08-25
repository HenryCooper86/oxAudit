import java.io.File;
import javax.servlet.http.HttpServletRequest;

class Downloads {
    File resolve(HttpServletRequest request) {
        return new File("/var/data/" + request.getParameter("name"));
    }
}
