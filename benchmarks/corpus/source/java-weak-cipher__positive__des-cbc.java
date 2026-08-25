import javax.crypto.Cipher;

class Encryptor {
    Cipher build() throws Exception {
        // The mode is fine and the padding is fine. DES is broken, so the
        // whole construction is: a 56-bit key is brute-forceable regardless
        // of how it is chained.
        return Cipher.getInstance("DES/CBC/PKCS5Padding");
    }
}
