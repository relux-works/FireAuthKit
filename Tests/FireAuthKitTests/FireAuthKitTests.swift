import Foundation
import Testing
@testable import FireAuthKit

@Suite
struct FireAuthKitTests {
    @Test
    func anonymousSignInBuildsSignUpRequest() async throws {
        let transport = MockTransport(
            response: """
            {
              "idToken": "id",
              "refreshToken": "refresh",
              "expiresIn": "3600",
              "localId": "user"
            }
            """
        )
        let client = FirebaseAuthClient(apiKey: "test-key", transport: transport)

        let response = try await client.signInAnonymously()
        let request = await transport.firstRequest()

        #expect(response.idToken == "id")
        #expect(request?.url?.host == "identitytoolkit.googleapis.com")
        #expect(request?.url?.path == "/v1/accounts:signUp")
        #expect(request?.url?.query == "key=test-key")
    }

    @Test
    func emailExistsMapsToTypedError() async throws {
        let transport = MockTransport(
            statusCode: 400,
            response: """
            {
              "error": {
                "code": 400,
                "message": "EMAIL_EXISTS"
              }
            }
            """
        )
        let client = FirebaseAuthClient(apiKey: "test-key", transport: transport)

        do {
            _ = try await client.createUserWithEmailPassword(email: "a@b.com", password: "password")
            Issue.record("Expected emailAlreadyInUse")
        } catch let error as FirebaseAuthError {
            #expect(error == .emailAlreadyInUse)
        }
    }

    @Test
    func idpPostBodyIsFormEncodedInsideJSON() async throws {
        let transport = MockTransport(
            response: """
            {
              "idToken": "id",
              "refreshToken": "refresh",
              "expiresIn": "3600",
              "localId": "user"
            }
            """
        )
        let client = FirebaseAuthClient(apiKey: "test-key", transport: transport)

        _ = try await client.getFirebaseToken(googleAccessToken: "token value")

        let request = await transport.firstRequest()
        let body = try #require(request?.httpBody)
        let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(json["postBody"] as? String == "access_token=token%20value&providerId=google.com")
        #expect(json["requestUri"] as? String == "http://localhost")
    }

    @Test
    func customRequestURIIsUsedForIdpRequests() async throws {
        let transport = MockTransport(
            response: """
            {
              "idToken": "id",
              "refreshToken": "refresh",
              "expiresIn": "3600",
              "localId": "user"
            }
            """
        )
        let config = FirebaseAuthConfig(apiKey: "test-key", requestURI: "com.example.app:/oauth")
        let client = FirebaseAuthClient(config: config, transport: transport)

        _ = try await client.signInWithIdp(postBody: "access_token=value&providerId=google.com")

        let request = await transport.firstRequest()
        let body = try #require(request?.httpBody)
        let json = try #require(JSONSerialization.jsonObject(with: body) as? [String: Any])
        #expect(json["requestUri"] as? String == "com.example.app:/oauth")
    }

    @Test
    func refreshTokenUsesSecureTokenEndpoint() async throws {
        let transport = MockTransport(
            response: """
            {
              "access_token": "access",
              "expires_in": "3600",
              "token_type": "Bearer",
              "refresh_token": "refresh-2",
              "id_token": "id-2",
              "user_id": "user"
            }
            """
        )
        let client = FirebaseAuthClient(apiKey: "test-key", transport: transport)

        let response = try await client.refreshIdToken(refreshToken: "refresh-1")
        let request = await transport.firstRequest()

        #expect(response.idToken == "id-2")
        #expect(request?.url?.host == "securetoken.googleapis.com")
        #expect(request?.url?.path == "/v1/token")
    }

    @Test
    func anonymousIdpUpgradeFallsBackWhenFederatedLinkErrorIsHTTP400() async throws {
        let transport = QueueTransport([
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
            .init(
                response: """
                {
                  "idToken": "id",
                  "refreshToken": "refresh",
                  "expiresIn": "3600",
                  "localId": "linked-user"
                }
                """
            ),
        ])
        let client = FirebaseAuthClient(apiKey: "test-key", transport: transport)

        let response = try await client.signInWithIdpFromAnonymous(
            anonymousIdToken: "anonymous-id-token",
            credential: .google(accessToken: "google-token")
        )
        let requests = await transport.requests

        #expect(response.localId == "linked-user")
        #expect(requests.count == 2)

        let firstBody = try jsonBody(from: try #require(requests.first))
        let secondBody = try jsonBody(from: try #require(requests.last))
        #expect(firstBody["idToken"] as? String == "anonymous-id-token")
        #expect(secondBody["idToken"] == nil)
    }

    @Test
    func sendEmailVerificationBuildsSendOobCodeRequest() async throws {
        let transport = MockTransport(response: "{}")
        let client = FirebaseAuthClient(apiKey: "test-key", transport: transport)

        try await client.sendEmailVerification(idToken: "id-token", email: "a@b.com")

        let request = try #require(await transport.firstRequest())
        let body = try jsonBody(from: request)
        #expect(request.url?.path == "/v1/accounts:sendOobCode")
        #expect(body["requestType"] as? String == "VERIFY_EMAIL")
        #expect(body["idToken"] as? String == "id-token")
        #expect(body["email"] as? String == "a@b.com")
    }

    @Test
    func checkEmailVerificationStatusBuildsLookupRequest() async throws {
        let transport = MockTransport(
            response: """
            {
              "users": [
                {
                  "emailVerified": true
                }
              ]
            }
            """
        )
        let client = FirebaseAuthClient(apiKey: "test-key", transport: transport)

        let verified = try await client.checkEmailVerificationStatus(idToken: "id-token")

        let request = try #require(await transport.firstRequest())
        let body = try jsonBody(from: request)
        #expect(verified)
        #expect(request.url?.path == "/v1/accounts:lookup")
        #expect(body["idToken"] as? String == "id-token")
    }

    @Test
    func confirmEmailVerificationBuildsUpdateRequest() async throws {
        let transport = MockTransport(
            response: """
            {
              "idToken": "id",
              "refreshToken": "refresh",
              "expiresIn": "3600",
              "localId": "user"
            }
            """
        )
        let client = FirebaseAuthClient(apiKey: "test-key", transport: transport)

        let response = try await client.confirmEmailVerification(oobCode: "oob-code")

        let request = try #require(await transport.firstRequest())
        let body = try jsonBody(from: request)
        #expect(response.localId == "user")
        #expect(request.url?.path == "/v1/accounts:update")
        #expect(body["oobCode"] as? String == "oob-code")
    }

    @Test
    func jwtTTLReadsExpirationClaim() throws {
        let expiry = 1_900_000_000
        let jwt = makeUnsignedJWT(payload: ["exp": expiry])

        let date = try #require(try extractTTL(from: jwt))

        #expect(Int(date.timeIntervalSince1970) == expiry)
    }
}

private struct TransportStubResponse: Sendable {
    let statusCode: Int
    let response: String

    init(statusCode: Int = 200, response: String) {
        self.statusCode = statusCode
        self.response = response
    }
}

private actor MockTransport: FirebaseAuthTransport {
    private(set) var requests: [URLRequest] = []
    private let statusCode: Int
    private let response: String

    init(statusCode: Int = 200, response: String) {
        self.statusCode = statusCode
        self.response = response
    }

    func data(for request: URLRequest) async throws -> FirebaseAuthTransportResponse {
        requests.append(request)
        return FirebaseAuthTransportResponse(
            data: Data(response.utf8),
            statusCode: statusCode
        )
    }

    func firstRequest() -> URLRequest? {
        requests.first
    }
}

private actor QueueTransport: FirebaseAuthTransport {
    private(set) var requests: [URLRequest] = []
    private var responses: [TransportStubResponse]

    init(_ responses: [TransportStubResponse]) {
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

private func makeUnsignedJWT(payload: [String: Any]) -> String {
    let header = ["alg": "none"]
    let headerData = try! JSONSerialization.data(withJSONObject: header)
    let payloadData = try! JSONSerialization.data(withJSONObject: payload)
    return [
        headerData.base64URLEncodedString(),
        payloadData.base64URLEncodedString(),
        "",
    ].joined(separator: ".")
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
