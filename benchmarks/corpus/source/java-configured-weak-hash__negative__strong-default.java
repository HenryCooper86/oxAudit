import java.security.MessageDigest;
import java.util.Properties;

class Digest {
    // Deliberately NOT reported: no properties file in this fixture defines
    // the key, so the literal default is what the call returns.
    byte[] hash(Properties props, byte[] data) throws Exception {
        String algorithm = props.getProperty("digest", "SHA-256");
        return MessageDigest.getInstance(algorithm).digest(data);
    }
}
