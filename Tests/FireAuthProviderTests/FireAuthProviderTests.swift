import Testing
@testable import FireAuthProvider

@Suite
struct FireAuthProviderTests {
    @Test
    func configurationLoadsFirebaseAPIKeyFromGoogleServiceInfo() {
        let configuration = FireAuthProvider.Configuration.load(
            { _ in nil },
            googleServiceInfo: [
                "API_KEY": "firebase-key",
                "PROJECT_ID": "project-id",
                "GOOGLE_APP_ID": "google-app-id",
                "BUNDLE_ID": "com.example.app",
            ]
        )

        guard case let .configured(resolved) = configuration.status else {
            Issue.record("Expected configured status")
            return
        }

        #expect(resolved.firebaseAPIKey == "firebase-key")
        #expect(resolved.firebaseProjectID == "project-id")
        #expect(resolved.bundleID == "com.example.app")
    }

    @Test
    func configurationReportsMissingAPIKey() {
        let configuration = FireAuthProvider.Configuration.load { _ in nil }

        #expect(configuration.status == .missing([.firebaseAPIKey]))
    }

    @Test
    func socialConfigurationIsOptional() {
        let configuration = FireAuthProvider.Configuration.load(
            { key in
                switch key {
                case FireAuthProvider.Configuration.InfoKey.firebaseAPIKey:
                    return "firebase-key"
                case FireAuthProvider.Configuration.InfoKey.googleClientID:
                    return "google-client"
                case FireAuthProvider.Configuration.InfoKey.googleRedirectURI:
                    return "com.example:/oauth"
                default:
                    return nil
                }
            }
        )

        guard case let .configured(resolved) = configuration.status else {
            Issue.record("Expected configured status")
            return
        }

        #expect(resolved.social.hasGoogle)
        #expect(!resolved.social.hasFacebook)
        #expect(!resolved.social.hasTwitter)
    }
}
