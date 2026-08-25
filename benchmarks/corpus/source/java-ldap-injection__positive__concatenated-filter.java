import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

class Directory {
    void lookup(DirContext ctx, HttpServletRequest request) throws Exception {
        String filter = "(&(objectclass=person)(uid=" + request.getParameter("uid") + "))";
        ctx.search("dc=example,dc=com", filter, new SearchControls());
    }
}
