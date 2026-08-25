import javax.crypto.Cipher;

class Encryptor {
    Cipher build() throws Exception {
        return Cipher.getInstance("AES/GCM/NOPADDING");
    }
}
