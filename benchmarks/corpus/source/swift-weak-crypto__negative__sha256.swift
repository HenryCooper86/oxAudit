import CryptoKit

struct Digest {
    func of(_ data: Data) -> String {
        return SHA256.hash(data: data).description
    }
}
