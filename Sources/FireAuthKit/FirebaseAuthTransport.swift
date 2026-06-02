import Foundation

public struct FirebaseAuthTransportResponse: Sendable, Hashable {
    public let data: Data
    public let statusCode: Int
    public let headers: [String: String]

    public init(
        data: Data,
        statusCode: Int,
        headers: [String: String] = [:]
    ) {
        self.data = data
        self.statusCode = statusCode
        self.headers = headers
    }
}

public protocol FirebaseAuthTransport: Sendable {
    func data(for request: URLRequest) async throws -> FirebaseAuthTransportResponse
}

public struct URLSessionFirebaseAuthTransport: FirebaseAuthTransport {
    private let session: URLSession

    public init(session: URLSession = .shared) {
        self.session = session
    }

    public func data(for request: URLRequest) async throws -> FirebaseAuthTransportResponse {
        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw FirebaseAuthError.networkError
        }
        return FirebaseAuthTransportResponse(
            data: data,
            statusCode: httpResponse.statusCode,
            headers: httpResponse.allHeaderFields.reduce(into: [:]) { result, pair in
                guard let key = pair.key as? String else {
                    return
                }
                result[key] = "\(pair.value)"
            }
        )
    }
}
