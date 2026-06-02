import AuthenticationServices
import CryptoKit
import FireAuthKit
import Foundation
import Security

#if canImport(UIKit)
    import UIKit
#elseif canImport(AppKit)
    import AppKit
#endif

public enum FireAuthKitSocial {}

public enum FireAuthSocialError: Error, LocalizedError, Sendable {
    case missingConfiguration(String)
    case invalidAuthorizationURL
    case callbackMissing
    case callbackStateMismatch
    case authorizationCodeMissing
    case accessTokenMissing
    case tokenExchangeFailed(Int)
    case appleIdentityTokenMissing
    case randomGenerationFailed(OSStatus)
    case webAuthenticationFailed(String)

    public var errorDescription: String? {
        switch self {
        case let .missingConfiguration(field):
            return "Missing social auth configuration: \(field)."
        case .invalidAuthorizationURL:
            return "Social auth authorization URL is invalid."
        case .callbackMissing:
            return "Social auth callback URL is missing."
        case .callbackStateMismatch:
            return "Social auth state verification failed."
        case .authorizationCodeMissing:
            return "Social auth authorization code is missing."
        case .accessTokenMissing:
            return "Social auth access token is missing."
        case let .tokenExchangeFailed(statusCode):
            return "Social auth token exchange failed with status \(statusCode)."
        case .appleIdentityTokenMissing:
            return "Apple identity token is missing."
        case let .randomGenerationFailed(status):
            return "Secure random generation failed with OSStatus \(status)."
        case let .webAuthenticationFailed(message):
            return message
        }
    }
}

public extension FireAuthKitSocial {
    struct GoogleConfiguration: Sendable, Hashable {
        public let clientID: String
        public let redirectURI: URL
        public let scopes: [String]
        public let authorizationEndpoint: URL
        public let tokenEndpoint: URL

        public init(
            clientID: String,
            redirectURI: URL,
            scopes: [String] = ["openid", "email", "profile"],
            authorizationEndpoint: URL = URL(string: "https://accounts.google.com/o/oauth2/v2/auth")!,
            tokenEndpoint: URL = URL(string: "https://oauth2.googleapis.com/token")!
        ) {
            self.clientID = clientID
            self.redirectURI = redirectURI
            self.scopes = scopes
            self.authorizationEndpoint = authorizationEndpoint
            self.tokenEndpoint = tokenEndpoint
        }
    }

    struct FacebookConfiguration: Sendable, Hashable {
        public let appID: String
        public let scopes: [String]
        public let authorizationEndpoint: URL

        public init(
            appID: String,
            scopes: [String] = ["public_profile", "email"],
            authorizationEndpoint: URL = URL(string: "https://www.facebook.com/v7.0/dialog/oauth")!
        ) {
            self.appID = appID
            self.scopes = scopes
            self.authorizationEndpoint = authorizationEndpoint
        }

        public var callbackScheme: String {
            "fb\(appID)"
        }

        public var redirectURI: URL {
            URL(string: "\(callbackScheme)://authorize")!
        }
    }

    struct TwitterConfiguration: Sendable, Hashable {
        public let clientID: String
        public let redirectURI: URL
        public let scopes: [String]
        public let authorizationEndpoint: URL
        public let tokenEndpoint: URL

        public init(
            clientID: String,
            redirectURI: URL,
            scopes: [String] = ["tweet.read", "users.read", "offline.access"],
            authorizationEndpoint: URL = URL(string: "https://twitter.com/i/oauth2/authorize")!,
            tokenEndpoint: URL = URL(string: "https://api.twitter.com/2/oauth2/token")!
        ) {
            self.clientID = clientID
            self.redirectURI = redirectURI
            self.scopes = scopes
            self.authorizationEndpoint = authorizationEndpoint
            self.tokenEndpoint = tokenEndpoint
        }
    }
}

@MainActor
public final class FireAuthWebAuthenticationClient: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var currentSession: ASWebAuthenticationSession?

    public func authenticate(
        authorizationURL: URL,
        callbackURLScheme: String,
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: authorizationURL,
                callbackURLScheme: callbackURLScheme
            ) { callbackURL, error in
                Task { @MainActor in
                    self.currentSession = nil

                    if let error {
                        continuation.resume(
                            throwing: FireAuthSocialError.webAuthenticationFailed(error.localizedDescription)
                        )
                        return
                    }

                    guard let callbackURL else {
                        continuation.resume(throwing: FireAuthSocialError.callbackMissing)
                        return
                    }

                    continuation.resume(returning: callbackURL)
                }
            }

            session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
            session.presentationContextProvider = self
            currentSession = session

            guard session.start() else {
                currentSession = nil
                continuation.resume(
                    throwing: FireAuthSocialError.webAuthenticationFailed("ASWebAuthenticationSession failed to start.")
                )
                return
            }
        }
    }

    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if canImport(UIKit)
            let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
            let keyWindow = scenes
                .flatMap(\.windows)
                .first { $0.isKeyWindow }
            return keyWindow ?? UIWindow(frame: UIScreen.main.bounds)
        #elseif canImport(AppKit)
            return NSApplication.shared.keyWindow
                ?? NSApplication.shared.mainWindow
                ?? NSApplication.shared.windows.first
                ?? NSWindow()
        #else
            fatalError("ASWebAuthenticationSession presentation anchor is unsupported on this platform.")
        #endif
    }
}

@MainActor
public final class AppleOAuthClient: NSObject {
    private var currentNonce: String?
    private var continuation: CheckedContinuation<FirebaseIDPCredential, any Error>?

    public override init() {
        super.init()
    }

    public func signIn() async throws -> FirebaseIDPCredential {
        try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation

            do {
                let nonce = try FireAuthPKCE.randomString()
                currentNonce = nonce

                let request = ASAuthorizationAppleIDProvider().createRequest()
                request.requestedScopes = [.fullName, .email]
                request.nonce = FireAuthPKCE.sha256(nonce)

                let controller = ASAuthorizationController(authorizationRequests: [request])
                controller.delegate = self
                controller.performRequests()
            } catch {
                self.continuation = nil
                continuation.resume(throwing: error)
            }
        }
    }
}

extension AppleOAuthClient: ASAuthorizationControllerDelegate {
    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard
            let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
            let tokenData = credential.identityToken,
            let idToken = String(data: tokenData, encoding: .utf8),
            !idToken.isEmpty,
            let nonce = currentNonce
        else {
            continuation?.resume(throwing: FireAuthSocialError.appleIdentityTokenMissing)
            continuation = nil
            currentNonce = nil
            return
        }

        continuation?.resume(returning: .apple(idToken: idToken, nonce: nonce))
        continuation = nil
        currentNonce = nil
    }

    public func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: any Error
    ) {
        continuation?.resume(throwing: error)
        continuation = nil
        currentNonce = nil
    }
}

@MainActor
public final class GoogleOAuthClient {
    private let configuration: FireAuthKitSocial.GoogleConfiguration
    private let webAuthenticationClient: FireAuthWebAuthenticationClient
    private let urlSession: URLSession

    public init(
        configuration: FireAuthKitSocial.GoogleConfiguration,
        webAuthenticationClient: FireAuthWebAuthenticationClient = FireAuthWebAuthenticationClient(),
        urlSession: URLSession = .shared
    ) {
        self.configuration = configuration
        self.webAuthenticationClient = webAuthenticationClient
        self.urlSession = urlSession
    }

    public func signIn() async throws -> FirebaseIDPCredential {
        let verifier = try FireAuthPKCE.randomString()
        let state = UUID().uuidString
        let authorizationURL = try authorizationURL(
            state: state,
            codeChallenge: FireAuthPKCE.codeChallenge(for: verifier)
        )
        let callbackURL = try await webAuthenticationClient.authenticate(
            authorizationURL: authorizationURL,
            callbackURLScheme: try callbackScheme(from: configuration.redirectURI)
        )
        let code = try authorizationCode(from: callbackURL, expectedState: state)
        let tokenResponse: OAuthTokenResponse = try await exchangeAuthorizationCode(
            code,
            codeVerifier: verifier,
            clientID: configuration.clientID,
            redirectURI: configuration.redirectURI,
            tokenEndpoint: configuration.tokenEndpoint
        )

        return .google(accessToken: tokenResponse.accessToken)
    }

    private func authorizationURL(state: String, codeChallenge: String) throws -> URL {
        var components = URLComponents(
            url: configuration.authorizationEndpoint,
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: configuration.clientID),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: configuration.scopes.joined(separator: " ")),
            URLQueryItem(name: "include_granted_scopes", value: "true"),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]

        guard let url = components?.url else {
            throw FireAuthSocialError.invalidAuthorizationURL
        }
        return url
    }

    private func authorizationCode(from callbackURL: URL, expectedState: String) throws -> String {
        guard
            let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
            let code = components.queryItems?.first(where: { $0.name == "code" })?.value
        else {
            throw FireAuthSocialError.authorizationCodeMissing
        }

        let state = components.queryItems?.first(where: { $0.name == "state" })?.value
        guard state == expectedState else {
            throw FireAuthSocialError.callbackStateMismatch
        }

        return code
    }

    private func callbackScheme(from redirectURI: URL) throws -> String {
        guard let scheme = redirectURI.scheme else {
            throw FireAuthSocialError.missingConfiguration("Google redirect URI scheme")
        }
        return scheme
    }
}

@MainActor
public final class FacebookOAuthClient {
    private let configuration: FireAuthKitSocial.FacebookConfiguration
    private let webAuthenticationClient: FireAuthWebAuthenticationClient

    public init(
        configuration: FireAuthKitSocial.FacebookConfiguration,
        webAuthenticationClient: FireAuthWebAuthenticationClient = FireAuthWebAuthenticationClient()
    ) {
        self.configuration = configuration
        self.webAuthenticationClient = webAuthenticationClient
    }

    public func signIn() async throws -> FirebaseIDPCredential {
        let state = UUID().uuidString
        let authorizationURL = try authorizationURL(state: state)
        let callbackURL = try await webAuthenticationClient.authenticate(
            authorizationURL: authorizationURL,
            callbackURLScheme: configuration.callbackScheme
        )
        let accessToken = try accessToken(from: callbackURL, expectedState: state)
        return .facebook(accessToken: accessToken)
    }

    private func authorizationURL(state: String) throws -> URL {
        var components = URLComponents(
            url: configuration.authorizationEndpoint,
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = [
            URLQueryItem(name: "client_id", value: configuration.appID),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: configuration.scopes.joined(separator: ",")),
            URLQueryItem(name: "response_type", value: "token granted_scopes"),
            URLQueryItem(name: "state", value: state),
        ]

        guard let url = components?.url else {
            throw FireAuthSocialError.invalidAuthorizationURL
        }
        return url
    }

    private func accessToken(from callbackURL: URL, expectedState: String) throws -> String {
        guard
            let fragment = callbackURL.fragment,
            var components = URLComponents(string: "https://callback.local")
        else {
            throw FireAuthSocialError.accessTokenMissing
        }

        components.percentEncodedQuery = fragment
        let queryItems = components.queryItems ?? []
        let state = queryItems.first(where: { $0.name == "state" })?.value
        guard state == expectedState else {
            throw FireAuthSocialError.callbackStateMismatch
        }

        guard let accessToken = queryItems.first(where: { $0.name == "access_token" })?.value else {
            throw FireAuthSocialError.accessTokenMissing
        }

        return accessToken
    }
}

@MainActor
public final class TwitterOAuthClient {
    private let configuration: FireAuthKitSocial.TwitterConfiguration
    private let webAuthenticationClient: FireAuthWebAuthenticationClient
    private let urlSession: URLSession

    public init(
        configuration: FireAuthKitSocial.TwitterConfiguration,
        webAuthenticationClient: FireAuthWebAuthenticationClient = FireAuthWebAuthenticationClient(),
        urlSession: URLSession = .shared
    ) {
        self.configuration = configuration
        self.webAuthenticationClient = webAuthenticationClient
        self.urlSession = urlSession
    }

    public func signIn() async throws -> FirebaseIDPCredential {
        let verifier = try FireAuthPKCE.randomString()
        let state = UUID().uuidString
        let authorizationURL = try authorizationURL(
            state: state,
            codeChallenge: FireAuthPKCE.codeChallenge(for: verifier)
        )
        let callbackURL = try await webAuthenticationClient.authenticate(
            authorizationURL: authorizationURL,
            callbackURLScheme: try callbackScheme(from: configuration.redirectURI)
        )
        let code = try authorizationCode(from: callbackURL, expectedState: state)
        let tokenResponse: OAuthTokenResponse = try await exchangeAuthorizationCode(
            code,
            codeVerifier: verifier,
            clientID: configuration.clientID,
            redirectURI: configuration.redirectURI,
            tokenEndpoint: configuration.tokenEndpoint
        )

        return .twitter(accessToken: tokenResponse.accessToken)
    }

    private func authorizationURL(state: String, codeChallenge: String) throws -> URL {
        var components = URLComponents(
            url: configuration.authorizationEndpoint,
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: configuration.clientID),
            URLQueryItem(name: "redirect_uri", value: configuration.redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: configuration.scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]

        guard let url = components?.url else {
            throw FireAuthSocialError.invalidAuthorizationURL
        }
        return url
    }

    private func authorizationCode(from callbackURL: URL, expectedState: String) throws -> String {
        guard
            let components = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
            let code = components.queryItems?.first(where: { $0.name == "code" })?.value
        else {
            throw FireAuthSocialError.authorizationCodeMissing
        }

        let state = components.queryItems?.first(where: { $0.name == "state" })?.value
        guard state == expectedState else {
            throw FireAuthSocialError.callbackStateMismatch
        }

        return code
    }

    private func callbackScheme(from redirectURI: URL) throws -> String {
        guard let scheme = redirectURI.scheme else {
            throw FireAuthSocialError.missingConfiguration("Twitter redirect URI scheme")
        }
        return scheme
    }
}

private struct OAuthTokenResponse: Decodable {
    let accessToken: String

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
    }
}

private func exchangeAuthorizationCode(
    _ code: String,
    codeVerifier: String,
    clientID: String,
    redirectURI: URL,
    tokenEndpoint: URL
) async throws -> OAuthTokenResponse {
    var request = URLRequest(url: tokenEndpoint)
    request.httpMethod = "POST"
    request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
    request.httpBody = OAuthFormEncoding.queryString([
        URLQueryItem(name: "code", value: code),
        URLQueryItem(name: "client_id", value: clientID),
        URLQueryItem(name: "code_verifier", value: codeVerifier),
        URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
        URLQueryItem(name: "grant_type", value: "authorization_code"),
    ]).data(using: .utf8)

    let (data, response) = try await URLSession.shared.data(for: request)
    guard let httpResponse = response as? HTTPURLResponse else {
        throw FireAuthSocialError.tokenExchangeFailed(0)
    }
    guard 200..<300 ~= httpResponse.statusCode else {
        throw FireAuthSocialError.tokenExchangeFailed(httpResponse.statusCode)
    }

    return try JSONDecoder().decode(OAuthTokenResponse.self, from: data)
}

private enum OAuthFormEncoding {
    static func queryString(_ items: [URLQueryItem]) -> String {
        var components = URLComponents()
        components.queryItems = items
        return components.percentEncodedQuery ?? ""
    }
}

private enum FireAuthPKCE {
    static func randomString(length: Int = 32) throws -> String {
        precondition(length > 0)

        var randomBytes = [UInt8](repeating: 0, count: length)
        let errorCode = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        guard errorCode == errSecSuccess else {
            throw FireAuthSocialError.randomGenerationFailed(errorCode)
        }

        let charset = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVXYZabcdefghijklmnopqrstuvwxyz-._")
        return String(randomBytes.map { charset[Int($0) % charset.count] })
    }

    static func codeChallenge(for verifier: String) -> String {
        Data(SHA256.hash(data: Data(verifier.utf8)))
            .base64URLEncodedString()
    }

    static func sha256(_ input: String) -> String {
        SHA256.hash(data: Data(input.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }
}

private extension Data {
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
