import Foundation

final class Client: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        // Deferring to the system runs the ordinary chain evaluation.
        completionHandler(.performDefaultHandling, nil)
    }
}
