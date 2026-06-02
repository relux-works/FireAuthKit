import FireAuthKit
import FireAuthKitSocial
import FireAuthProvider
import SwiftUI

public extension FireAuthProvider.Module {
    @MainActor
    final class Impl: FireAuthProvider.Module.Interface {
        public let configuration: FireAuthProvider.Configuration

        private let transport: any FirebaseAuthTransport
        private var client: FirebaseAuthClient?
        private var session: FireAuthProvider.AuthSession?
        private var state: FireAuthProvider.AuthState = .unconfigured

        public init(
            configuration: FireAuthProvider.Configuration,
            transport: any FirebaseAuthTransport = URLSessionFirebaseAuthTransport()
        ) {
            self.configuration = configuration
            self.transport = transport
            configure()
        }

        public func configure() {
            guard case let .configured(resolved) = configuration.status else {
                client = nil
                session = nil
                state = .unconfigured
                return
            }

            client = FirebaseAuthClient(
                config: FirebaseAuthConfig(apiKey: resolved.firebaseAPIKey),
                transport: transport
            )
            state = session.map { .signedIn($0.user) } ?? .signedOut
        }

        public func authState() -> FireAuthProvider.AuthState {
            state
        }

        public func bearerToken() async throws -> String? {
            session?.idToken
        }

        public func resetLocalAuthState() async {
            session = nil
            state = configuration.isConfigured ? .signedOut : .unconfigured
        }

        public func signInAnonymously() async throws -> FireAuthProvider.AuthSession {
            let response = try await requireClient().signInAnonymously()
            return store(response)
        }

        public func createUser(email: String, password: String) async throws -> FireAuthProvider.AuthSession {
            let response = try await requireClient().createUserWithEmailPassword(
                email: email,
                password: password
            )
            return store(response)
        }

        public func signIn(email: String, password: String) async throws -> FireAuthProvider.AuthSession {
            let response = try await requireClient().signInWithEmailPassword(
                email: email,
                password: password
            )
            return store(response)
        }

        public func linkEmailPassword(
            email: String,
            password: String
        ) async throws -> FireAuthProvider.AuthSession {
            guard let session else {
                throw FirebaseAuthError.invalidIdToken
            }

            let response = try await requireClient().signInWithEmailFromAnonymous(
                anonymousIdToken: session.idToken,
                email: email,
                password: password
            )
            return store(response)
        }

        public func signIn(with credential: FirebaseIDPCredential) async throws -> FireAuthProvider.AuthSession {
            let response = try await requireClient().signInWithIdp(credential)
            return store(response)
        }

        public func linkCurrentUser(with credential: FirebaseIDPCredential) async throws -> FireAuthProvider.AuthSession {
            guard let session else {
                throw FirebaseAuthError.invalidIdToken
            }

            let response = try await requireClient().signInWithIdpFromAnonymous(
                anonymousIdToken: session.idToken,
                credential: credential
            )
            return store(response)
        }

        public func refresh() async throws -> FireAuthProvider.AuthSession {
            guard let session else {
                throw FirebaseAuthError.invalidRefreshToken
            }

            let response = try await requireClient().refreshIdToken(refreshToken: session.refreshToken)
            return store(response)
        }

        public func sendEmailVerification(email: String) async throws {
            guard let session else {
                throw FirebaseAuthError.invalidIdToken
            }

            try await requireClient().sendEmailVerification(idToken: session.idToken, email: email)
        }

        public func checkEmailVerificationStatus() async throws -> Bool {
            guard let session else {
                throw FirebaseAuthError.invalidIdToken
            }

            return try await requireClient().checkEmailVerificationStatus(idToken: session.idToken)
        }

        @available(*, deprecated, message: "Firebase accounts:update oobCode confirmation is kept for API parity.")
        public func confirmEmailVerification(oobCode: String) async throws -> FireAuthProvider.AuthSession {
            let response = try await requireClient().confirmEmailVerification(oobCode: oobCode)
            return store(response)
        }

        public func makeAuthGateView(
            authenticated: @escaping @MainActor () -> AnyView,
            missingConfiguration: @escaping @MainActor (FireAuthProvider.Configuration) -> AnyView,
            signedOut: @escaping @MainActor () -> AnyView
        ) -> AnyView {
            switch authState() {
            case .signedIn:
                authenticated()
            case .signedOut:
                signedOut()
            case .unconfigured:
                missingConfiguration(configuration)
            }
        }

        public func makeAccountManagementView(onSignedOut: @escaping @MainActor () -> Void) -> AnyView {
            AnyView(
                Form {
                    Section("Account") {
                        switch authState() {
                        case let .signedIn(user):
                            LabeledContent("User ID", value: user.id)
                            if let email = user.email {
                                LabeledContent("Email", value: email)
                            }
                        case .signedOut:
                            Text("Signed out")
                        case .unconfigured:
                            Text("Missing configuration")
                        }

                        Button("Sign out") {
                            Task {
                                await self.resetLocalAuthState()
                                onSignedOut()
                            }
                        }
                    }
                }
            )
        }

        private func requireClient() throws -> FirebaseAuthClient {
            guard let client else {
                throw FirebaseAuthError.missingConfig
            }
            return client
        }

        private func store(_ response: FirebaseTokenResponse) -> FireAuthProvider.AuthSession {
            let user = FireAuthProvider.User(
                id: response.localId,
                email: response.email,
                displayName: preferredDisplayName(response)
            )
            let session = FireAuthProvider.AuthSession(
                user: user,
                idToken: response.idToken,
                refreshToken: response.refreshToken,
                expiresIn: response.expiresIn
            )

            self.session = session
            state = .signedIn(user)
            return session
        }

        private func preferredDisplayName(_ response: FirebaseTokenResponse) -> String {
            let displayName = response.displayName?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !displayName.isEmpty {
                return displayName
            }

            let email = response.email?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if !email.isEmpty {
                return email
            }

            return response.localId
        }
    }
}

private extension FireAuthProvider.Configuration {
    var isConfigured: Bool {
        if case .configured = status {
            return true
        }
        return false
    }
}
