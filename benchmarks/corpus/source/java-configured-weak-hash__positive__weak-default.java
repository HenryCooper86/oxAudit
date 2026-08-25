import java.security.MessageDigest;
import java.util.Properties;

class Digest {
    byte[] hash(Properties props, byte[] data) throws Exception {
        String algorithm = props.getProperty("digest", "MD5");
        return MessageDigest.getInstance(algorithm).digest(data);
    }
}
