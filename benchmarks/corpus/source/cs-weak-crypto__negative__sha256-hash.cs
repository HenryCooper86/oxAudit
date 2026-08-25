using System.Security.Cryptography;

class Digest {
    public byte[] Of(byte[] data) {
        using var hasher = SHA256.Create();
        return hasher.ComputeHash(data);
    }
}
