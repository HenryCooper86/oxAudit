import java.security.SecureRandom;

class Keys {
    String apiKey() {
        SecureRandom random = new SecureRandom();
        return Long.toHexString(random.nextLong());
    }
}
