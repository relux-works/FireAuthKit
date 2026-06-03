import FireAuthKit
import FireAuthProvider
import FireAuthProviderImpl
import Foundation
import Testing

@Suite
@MainActor
struct FireAuthProviderImplTests {
    @Test
    func configuredProviderStartsSignedOut() {
        let provider = FireAuthProvider.Module.Impl(
            configuration: .init(status: .configured(.init(firebaseAPIKey: "key"))),
            transport: QueueTransport([])
        )

        #expect(provider.authState() == .signedOut)
    }

    @Test
    func anonymousSignInUpdatesAuthState() async throws {
        let provider = FireAuthProvider.Module.Impl(
            configuration: .init(status: .configured(.init(firebaseAPIKey: "key"))),
            transport: QueueTransport([
                """
                {
                  "idToken": "id",
                  "refreshToken": "refresh",
                  "expiresIn": "3600",
                  "localId": "anonymous-user"
                }
                """,
            ])
        )

        let session = try await provider.signInAnonymously()

        #expect(session.user.id == "anonymous-user")
        #expect(provider.authState() == .signedIn(.init(id: "anonymous-user", displayName: "anonymous-user")))
    }

    @Test
    func refreshUsesStoredRefreshToken() async throws {
        let transport = QueueTransport([
            """
            {
              "idToken": "id",
              "refreshToken": "refresh",
              "expiresIn": "3600",
              "localId": "user"
            }
            """,
            """
            {
              "access_token": "access-2",
              "expires_in": "3600",
              "token_type": "Bearer",
              "refresh_token": "refresh-2",
              "id_token": "id-2",
              "user_id": "user"
            }
            """,
        ])
        let provider = FireAuthProvider.Module.Impl(
            configuration: .init(status: .configured(.init(firebaseAPIKey: "key"))),
            transport: transport
        )

        _ = try await provider.signInAnonymously()
        let refreshed = try await provider.refresh()
        let requests = await transport.requests

        #expect(refreshed.idToken == "id-2")
        #expect(requests.last?.url?.host == "securetoken.googleapis.com")
    }

    @Test
    func linkEmailPasswordDoesNotFallbackWhenEmailAlreadyExists() async throws {
        let transport = QueueTransport([
            """
            {
              "idToken": "anonymous-id-token",
              "refreshToken": "refresh",
              "expiresIn": "3600",
              "localId": "anonymous-user"
            }
            """,
            .init(
                statusCode: 400,
                response: """
                {
                  "error": {
                    "code": 400,
                    "message": "EMAIL_EXISTS"
                  }
                }
                """
            ),
            """
            {
              "idToken": "should-not-be-used",
              "refreshToken": "refresh-2",
              "expiresIn": "3600",
              "localId": "existing-user"
            }
            """,
        ])
        let provider = FireAuthProvider.Module.Impl(
            configuration: .init(status: .configured(.init(firebaseAPIKey: "key"))),
            transport: transport
        )

        _ = try await provider.signInAnonymously()

        do {
            _ = try await provider.linkEmailPassword(email: "used@example.com", password: "Password1!")
            Issue.record("Expected strict link to throw EMAIL_EXISTS")
        } catch FirebaseAuthError.emailAlreadyInUse {}

        let requests = await transport.requests
        #expect(requests.count == 2)
        #expect(requests[1].url?.path == "/v1/accounts:signUp")
        let body = try jsonBody(from: requests[1])
        #expect(body["idToken"] as? String == "anonymous-id-token")
    }

    @Test
    func linkCurrentUserWithCredentialDoesNotFallbackWhenProviderAlreadyLinked() async throws {
        let transport = QueueTransport([
            """
            {
              "idToken": "anonymous-id-token",
              "refreshToken": "refresh",
              "expiresIn": "3600",
              "localId": "anonymous-user"
            }
            """,
            .init(
                statusCode: 400,
                response: """
                {
                  "error": {
                    "code": 400,
                    "message": "FEDERATED_USER_ID_ALREADY_LINKED"
                  }
                }
                """
            ),
            """
            {
              "idToken": "should-not-be-used",
              "refreshToken": "refresh-2",
              "expiresIn": "3600",
              "localId": "existing-user"
            }
            """,
        ])
        let provider = FireAuthProvider.Module.Impl(
            configuration: .init(status: .configured(.init(firebaseAPIKey: "key"))),
            transport: transport
        )

        _ = try await provider.signInAnonymously()

        do {
            _ = try await provider.linkCurrentUser(with: .google(accessToken: "google-token"))
            Issue.record("Expected strict link to throw FEDERATED_USER_ID_ALREADY_LINKED")
        } catch FirebaseAuthError.federatedUserIdAlreadyLinked {}

        let requests = await transport.requests
        #expect(requests.count == 2)
        #expect(requests[1].url?.path == "/v1/accounts:signInWithIdp")
        let body = try jsonBody(from: requests[1])
        #expect(body["idToken"] as? String == "anonymous-id-token")
    }
}

private struct TransportStub: ExpressibleByStringLiteral, Sendable {
    let statusCode: Int
    let response: String

    init(statusCode: Int = 200, response: String) {
        self.statusCode = statusCode
        self.response = response
    }

    init(stringLiteral value: String) {
        self.init(response: value)
    }
}

private actor QueueTransport: FirebaseAuthTransport {
    private(set) var requests: [URLRequest] = []
    private var responses: [TransportStub]

    init(_ responses: [TransportStub]) {
        self.responses = responses
    }

    func data(for request: URLRequest) async throws -> FirebaseAuthTransportResponse {
        requests.append(request)
        let response = responses.isEmpty ? .init(response: "{}") : responses.removeFirst()
        return FirebaseAuthTransportResponse(
            data: Data(response.response.utf8),
            statusCode: response.statusCode
        )
    }
}

private func jsonBody(from request: URLRequest) throws -> [String: Any] {
    let body = try #require(request.httpBody)
    return try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
}
