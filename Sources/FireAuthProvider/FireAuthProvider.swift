import Foundation
import SwiftUI

/// SDK-neutral namespace for Firebase REST authentication provider contracts.
public enum FireAuthProvider {
    /// Dependency-injection namespace for the auth provider module.
    public enum Module {}
}

public extension FireAuthProvider {
    enum AuthState: Equatable, Sendable {
        case unconfigured
        case signedOut
        case signedIn(User)
    }

    struct User: Equatable, Sendable {
        public let id: String
        public let email: String?
        public let displayName: String

        public init(id: String, email: String? = nil, displayName: String = "User") {
            self.id = id
            self.email = email
            self.displayName = displayName
        }
    }

    struct AuthSession: Equatable, Sendable {
        public let user: User
        public let idToken: String
        public let refreshToken: String
        public let expiresIn: String

        public init(
            user: User,
            idToken: String,
            refreshToken: String,
            expiresIn: String
        ) {
            self.user = user
            self.idToken = idToken
            self.refreshToken = refreshToken
            self.expiresIn = expiresIn
        }
    }

    struct OAuthCredential: Equatable, Sendable {
        public let providerID: String
        public let fields: [String: String]

        public init(providerID: String, fields: [String: String]) {
            self.providerID = providerID
            self.fields = fields
        }
    }
}

public extension FireAuthProvider {
    struct Configuration: Equatable, Sendable {
        public struct Social: Equatable, Sendable {
            public let googleClientID: String?
            public let googleRedirectURI: String?
            public let facebookAppID: String?
            public let twitterClientID: String?
            public let twitterRedirectURI: String?

            public init(
                googleClientID: String? = nil,
                googleRedirectURI: String? = nil,
                facebookAppID: String? = nil,
                twitterClientID: String? = nil,
                twitterRedirectURI: String? = nil
            ) {
                self.googleClientID = googleClientID
                self.googleRedirectURI = googleRedirectURI
                self.facebookAppID = facebookAppID
                self.twitterClientID = twitterClientID
                self.twitterRedirectURI = twitterRedirectURI
            }

            public var hasGoogle: Bool {
                googleClientID != nil && googleRedirectURI != nil
            }

            public var hasFacebook: Bool {
                facebookAppID != nil
            }

            public var hasTwitter: Bool {
                twitterClientID != nil && twitterRedirectURI != nil
            }
        }

        public struct Resolved: Equatable, Sendable {
            public let firebaseAPIKey: String
            public let firebaseProjectID: String?
            public let googleAppID: String?
            public let bundleID: String?
            public let social: Social

            public init(
                firebaseAPIKey: String,
                firebaseProjectID: String? = nil,
                googleAppID: String? = nil,
                bundleID: String? = nil,
                social: Social = Social()
            ) {
                self.firebaseAPIKey = firebaseAPIKey
                self.firebaseProjectID = firebaseProjectID
                self.googleAppID = googleAppID
                self.bundleID = bundleID
                self.social = social
            }
        }

        public enum MissingField: String, CaseIterable, Hashable, Sendable {
            case firebaseAPIKey = "FireAuthFirebaseAPIKey"

            public var instruction: String {
                switch self {
                case .firebaseAPIKey:
                    return "Bundle GoogleService-Info.plist or set FireAuthFirebaseAPIKey in the app Info.plist."
                }
            }
        }

        public enum InfoKey {
            public static let firebaseAPIKey = "FireAuthFirebaseAPIKey"
            public static let firebaseProjectID = "FireAuthFirebaseProjectID"
            public static let googleClientID = "FireAuthGoogleClientID"
            public static let googleRedirectURI = "FireAuthGoogleRedirectURI"
            public static let facebookAppID = "FireAuthFacebookAppID"
            public static let twitterClientID = "FireAuthTwitterClientID"
            public static let twitterRedirectURI = "FireAuthTwitterRedirectURI"
        }

        public enum Status: Equatable, Sendable {
            case configured(Resolved)
            case missing([MissingField])
        }

        public static let placeholder = "replace-me"

        public let status: Status

        public init(status: Status) {
            self.status = status
        }

        public static func load(
            bundle: Bundle = .main,
            googleServiceInfoResource: String = "GoogleService-Info"
        ) -> Configuration {
            let googleServiceInfo = googleServiceInfoDictionary(
                bundle: bundle,
                resource: googleServiceInfoResource
            )

            return load(
                { key in bundle.object(forInfoDictionaryKey: key) },
                googleServiceInfo: googleServiceInfo
            )
        }

        public static func load(
            _ infoValue: (String) -> Any?,
            googleServiceInfo: [String: Any]? = nil
        ) -> Configuration {
            let firebaseAPIKey = sanitizedString(infoValue(InfoKey.firebaseAPIKey))
                ?? sanitizedString(googleServiceInfo?["API_KEY"])
            let projectID = sanitizedString(infoValue(InfoKey.firebaseProjectID))
                ?? sanitizedString(googleServiceInfo?["PROJECT_ID"])
            let googleAppID = sanitizedString(googleServiceInfo?["GOOGLE_APP_ID"])
            let bundleID = sanitizedString(googleServiceInfo?["BUNDLE_ID"])

            let social = Social(
                googleClientID: sanitizedString(infoValue(InfoKey.googleClientID)),
                googleRedirectURI: sanitizedString(infoValue(InfoKey.googleRedirectURI)),
                facebookAppID: sanitizedString(infoValue(InfoKey.facebookAppID)),
                twitterClientID: sanitizedString(infoValue(InfoKey.twitterClientID)),
                twitterRedirectURI: sanitizedString(infoValue(InfoKey.twitterRedirectURI))
            )

            guard let firebaseAPIKey else {
                return Configuration(status: .missing([.firebaseAPIKey]))
            }

            return Configuration(
                status: .configured(
                    Resolved(
                        firebaseAPIKey: firebaseAPIKey,
                        firebaseProjectID: projectID,
                        googleAppID: googleAppID,
                        bundleID: bundleID,
                        social: social
                    )
                )
            )
        }

        private static func googleServiceInfoDictionary(
            bundle: Bundle,
            resource: String
        ) -> [String: Any]? {
            guard let url = bundle.url(forResource: resource, withExtension: "plist") else {
                return nil
            }

            guard
                let data = try? Data(contentsOf: url),
                let plist = try? PropertyListSerialization.propertyList(
                    from: data,
                    options: [],
                    format: nil
                ) as? [String: Any]
            else {
                return nil
            }

            return plist
        }

        private static func sanitizedString(_ rawValue: Any?) -> String? {
            guard let string = rawValue as? String else {
                return nil
            }

            let trimmed = string.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmed.isEmpty, trimmed != placeholder else {
                return nil
            }

            return trimmed
        }
    }
}

public extension FireAuthProvider.Module {
    @MainActor
    protocol Interface: Sendable {
        var configuration: FireAuthProvider.Configuration { get }

        func configure()
        func authState() -> FireAuthProvider.AuthState
        func bearerToken() async throws -> String?
        func resetLocalAuthState() async

        @discardableResult
        func signInAnonymously() async throws -> FireAuthProvider.AuthSession

        @discardableResult
        func createUser(email: String, password: String) async throws -> FireAuthProvider.AuthSession

        @discardableResult
        func signIn(email: String, password: String) async throws -> FireAuthProvider.AuthSession

        @discardableResult
        func linkEmailPassword(email: String, password: String) async throws -> FireAuthProvider.AuthSession

        @discardableResult
        func refresh() async throws -> FireAuthProvider.AuthSession

        func sendEmailVerification(email: String) async throws
        func checkEmailVerificationStatus() async throws -> Bool

        @available(*, deprecated, message: "Firebase accounts:update oobCode confirmation is kept for API parity.")
        @discardableResult
        func confirmEmailVerification(oobCode: String) async throws -> FireAuthProvider.AuthSession

        func makeAuthGateView(
            authenticated: @escaping @MainActor () -> AnyView,
            missingConfiguration: @escaping @MainActor (FireAuthProvider.Configuration) -> AnyView,
            signedOut: @escaping @MainActor () -> AnyView
        ) -> AnyView

        func makeAccountManagementView(onSignedOut: @escaping @MainActor () -> Void) -> AnyView
    }
}
