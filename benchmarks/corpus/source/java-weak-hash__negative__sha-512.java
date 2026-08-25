import java.security.MessageDigest;

class Digest {
    MessageDigest of() throws Exception {
        // Must not match the optional-hyphen SHA-1 pattern.
        return MessageDigest.getInstance("SHA-512");
    }
}
