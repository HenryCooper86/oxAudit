import Foundation

struct Shimmer {
    // Visual jitter on a loading placeholder; predicting it gains nothing.
    func frameOffset() -> Int {
        return Int.random(in: 0..<16)
    }
}
