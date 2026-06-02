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
}

private actor QueueTransport: FirebaseAuthTransport {
    private(set) var requests: [URLRequest] = []
    private var responses: [String]

    init(_ responses: [String]) {
        self.responses = responses
    }

    func data(for request: URLRequest) async throws -> FirebaseAuthTransportResponse {
        requests.append(request)
        let response = responses.isEmpty ? "{}" : responses.removeFirst()
        return FirebaseAuthTransportResponse(data: Data(response.utf8), statusCode: 200)
    }
}
