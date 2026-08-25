import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;

class Directory {
    void lookup(DirContext ctx, HttpServletRequest request) throws Exception {
        // The remediation this rule recommends: {0} placeholders with the
        // values passed separately. The bound value is attacker-controlled
        // exactly as it should be, so judging the call by every argument
        // reported the fix as the defect.
        String filter = "(&(objectclass=person)(uid={0}))";
        Object[] filterArgs = {request.getParameter("uid")};
        ctx.search("dc=example,dc=com", filter, filterArgs, new SearchControls());
    }
}
