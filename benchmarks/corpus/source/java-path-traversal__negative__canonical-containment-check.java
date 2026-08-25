import javax.servlet.http.HttpServletRequest;

class Downloads {
    // Deliberately NOT reported: canonicalising and then checking containment
    // is what this rule's own remediation asks for.
    java.io.File resolve(HttpServletRequest request) throws Exception {
        java.io.File candidate = new java.io.File("/var/data", request.getParameter("name"));
        if (!candidate.getCanonicalPath().startsWith("/var/data/")) {
            throw new IllegalArgumentException("outside the data directory");
        }
        return candidate;
    }
}
