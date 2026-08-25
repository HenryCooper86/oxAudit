import java.util.Random;

class Keys {
    String apiKey() {
        Random random = new Random();
        return Long.toHexString(random.nextLong());
    }
}
