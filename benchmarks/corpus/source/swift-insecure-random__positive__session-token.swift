import Foundation

struct Sessions {
    func newSessionToken() -> String {
        let token = arc4random_uniform(UInt32.max)
        return String(token, radix: 16)
    }
}
