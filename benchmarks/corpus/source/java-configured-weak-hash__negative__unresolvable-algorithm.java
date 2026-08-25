import java.security.MessageDigest;

class Digest {
    // Deliberately NOT reported: the algorithm arrives from the caller, so
    // nothing here says whether it is broken. Asserting that it is would be
    // making the finding up.
    byte[] hash(String algorithm, byte[] data) throws Exception {
        return MessageDigest.getInstance(algorithm).digest(data);
    }
}
