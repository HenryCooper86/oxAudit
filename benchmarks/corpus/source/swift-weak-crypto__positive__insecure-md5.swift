import CryptoKit

struct Digest {
    func of(_ data: Data) -> String {
        return Insecure.MD5.hash(data: data).description
    }
}
