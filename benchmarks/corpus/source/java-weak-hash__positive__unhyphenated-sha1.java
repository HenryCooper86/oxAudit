import java.security.MessageDigest;

class Digest {
    MessageDigest of() throws Exception {
        // "SHA1" and "SHA-1" name the same broken hash; the rule matched only
        // the hyphenated spelling and missed 85 cases of this one.
        return MessageDigest.getInstance("SHA1");
    }
}
