import javax.servlet.http.HttpServletRequest;

class Downloads {
    // The safe half is the inner constructor. Reporting only the innermost
    // match would name the constant root and miss the attacker's segment.
    java.io.File resolve(HttpServletRequest request) {
        String child = request.getParameter("name");
        return new java.io.File(new java.io.File("/var/data"), child);
    }
}
