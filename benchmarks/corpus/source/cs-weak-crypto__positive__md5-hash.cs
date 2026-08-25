using System.Security.Cryptography;

class Digest {
    public byte[] Of(byte[] data) {
        using var hasher = MD5.Create();
        return hasher.ComputeHash(data);
    }
}
