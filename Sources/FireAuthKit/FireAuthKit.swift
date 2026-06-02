import Foundation

public struct FirebaseAuthConfig: Sendable, Hashable {
    public let apiKey: String
    public let requestURI: String

    public init(apiKey: String, requestURI: String = "http://localhost") {
        self.apiKey = apiKey
        self.requestURI = requestURI
    }
}

public struct GoogleServiceInfo: Sendable, Hashable {
    public let apiKey: String
    public let bundleId: String
    public let googleAppId: String
    public let projectId: String
    public let gcmSenderId: String?
    public let storageBucket: String?

    public init(
        apiKey: String,
        bundleId: String,
        googleAppId: String,
        projectId: String,
        gcmSenderId: String? = nil,
        storageBucket: String? = nil
    ) {
        self.apiKey = apiKey
        self.bundleId = bundleId
        self.googleAppId = googleAppId
        self.projectId = projectId
        self.gcmSenderId = gcmSenderId
        self.storageBucket = storageBucket
    }

    public init(contentsOf url: URL) throws {
        let data = try Data(contentsOf: url)
        guard
            let plist = try PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: nil
            ) as? [String: Any],
            let apiKey = plist["API_KEY"] as? String,
            let bundleId = plist["BUNDLE_ID"] as? String,
            let googleAppId = plist["GOOGLE_APP_ID"] as? String,
            let projectId = plist["PROJECT_ID"] as? String
        else {
            throw FirebaseAuthError.invalidGoogleServiceInfo
        }

        self.init(
            apiKey: apiKey,
            bundleId: bundleId,
            googleAppId: googleAppId,
            projectId: projectId,
            gcmSenderId: plist["GCM_SENDER_ID"] as? String,
            storageBucket: plist["STORAGE_BUCKET"] as? String
        )
    }

    public var authConfig: FirebaseAuthConfig {
        FirebaseAuthConfig(apiKey: apiKey)
    }
}

public extension GoogleServiceInfo {
    static func load(
        from bundle: Bundle = .main,
        resource: String = "GoogleService-Info"
    ) throws -> GoogleServiceInfo {
        guard let url = bundle.url(forResource: resource, withExtension: "plist") else {
            throw FirebaseAuthError.googleServiceInfoNotFound
        }
        return try GoogleServiceInfo(contentsOf: url)
    }
}

public struct FirebasePhoneVerificationSession: Sendable, Hashable, Codable {
    public let sessionInfo: String

    public init(sessionInfo: String) {
        self.sessionInfo = sessionInfo
    }
}

public struct FirebaseTokenResponse: Sendable, Hashable, Codable {
    public let idToken: String
    public let refreshToken: String
    public let expiresIn: String
    public let localId: String
    public let email: String?
    public let displayName: String?
    public let photoUrl: String?
    public let registered: Bool?
    public let isNewUser: Bool?

    public init(
        idToken: String,
        refreshToken: String,
        expiresIn: String,
        localId: String,
        email: String? = nil,
        displayName: String? = nil,
        photoUrl: String? = nil,
        registered: Bool? = nil,
        isNewUser: Bool? = nil
    ) {
        self.idToken = idToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
        self.localId = localId
        self.email = email
        self.displayName = displayName
        self.photoUrl = photoUrl
        self.registered = registered
        self.isNewUser = isNewUser
    }
}

public struct FirebasePhoneAuthSendVerificationCodeResponse: Sendable, Hashable, Codable {
    public let sessionInfo: String

    public init(sessionInfo: String) {
        self.sessionInfo = sessionInfo
    }
}

public struct FirebaseRefreshTokenResponse: Sendable, Hashable, Codable {
    public let accessToken: String
    public let expiresIn: String
    public let tokenType: String
    public let refreshToken: String
    public let idToken: String
    public let userId: String
    public let projectId: String?

    public init(
        accessToken: String,
        expiresIn: String,
        tokenType: String,
        refreshToken: String,
        idToken: String,
        userId: String,
        projectId: String? = nil
    ) {
        self.accessToken = accessToken
        self.expiresIn = expiresIn
        self.tokenType = tokenType
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.userId = userId
        self.projectId = projectId
    }

    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case expiresIn = "expires_in"
        case tokenType = "token_type"
        case refreshToken = "refresh_token"
        case idToken = "id_token"
        case userId = "user_id"
        case projectId = "project_id"
    }
}

public struct FirebaseErrorResponse: Sendable, Hashable, Codable {
    public let error: Details

    public init(error: Details) {
        self.error = error
    }

    public struct Details: Sendable, Hashable, Codable {
        public let code: Int
        public let message: String
        public let errors: [Info]?

        public init(code: Int, message: String, errors: [Info]? = nil) {
            self.code = code
            self.message = message
            self.errors = errors
        }
    }

    public struct Info: Sendable, Hashable, Codable {
        public let message: String
        public let domain: String
        public let reason: String

        public init(message: String, domain: String, reason: String) {
            self.message = message
            self.domain = domain
            self.reason = reason
        }
    }
}

public struct SocialLinkErrorResponse: Sendable, Hashable, Codable {
    public let federatedId: String
    public let providerId: String
    public let email: String
    public let emailVerified: Bool
    public let firstName: String?
    public let fullName: String?
    public let photoUrl: String?
    public let displayName: String?
    public let oauthAccessToken: String
    public let oauthExpireIn: Int
    public let rawUserInfo: String
    public let errorMessage: String
    public let kind: String

    public init(
        federatedId: String,
        providerId: String,
        email: String,
        emailVerified: Bool,
        firstName: String? = nil,
        fullName: String? = nil,
        photoUrl: String? = nil,
        displayName: String? = nil,
        oauthAccessToken: String,
        oauthExpireIn: Int,
        rawUserInfo: String,
        errorMessage: String,
        kind: String
    ) {
        self.federatedId = federatedId
        self.providerId = providerId
        self.email = email
        self.emailVerified = emailVerified
        self.firstName = firstName
        self.fullName = fullName
        self.photoUrl = photoUrl
        self.displayName = displayName
        self.oauthAccessToken = oauthAccessToken
        self.oauthExpireIn = oauthExpireIn
        self.rawUserInfo = rawUserInfo
        self.errorMessage = errorMessage
        self.kind = kind
    }
}

public struct LinkWithIdpResponse: Sendable, Hashable, Codable {
    public let idToken: String?
    public let refreshToken: String?
    public let expiresIn: String?
    public let localId: String?
    public let federatedId: String?
    public let providerId: String?
    public let email: String?
    public let emailVerified: Bool?
    public let firstName: String?
    public let fullName: String?
    public let displayName: String?
    public let photoUrl: String?
    public let errorMessage: String?
    public let rawUserInfo: String?
    public let oauthAccessToken: String?
    public let oauthExpireIn: Int?
}

public struct FirebaseIDPCredential: Sendable, Hashable {
    public let providerId: String
    public let fields: [String: String]

    public init(providerId: String, fields: [String: String]) {
        self.providerId = providerId
        self.fields = fields
    }

    public static func google(accessToken: String) -> FirebaseIDPCredential {
        FirebaseIDPCredential(providerId: "google.com", fields: ["access_token": accessToken])
    }

    public static func facebook(accessToken: String) -> FirebaseIDPCredential {
        FirebaseIDPCredential(providerId: "facebook.com", fields: ["access_token": accessToken])
    }

    public static func apple(
        idToken: String,
        nonce: String,
        oauthClientId: String? = nil
    ) -> FirebaseIDPCredential {
        var fields = [
            "id_token": idToken,
            "nonce": nonce,
        ]
        if let oauthClientId {
            fields["oauth_client_id"] = oauthClientId
        }
        return FirebaseIDPCredential(providerId: "apple.com", fields: fields)
    }

    public static func twitter(
        accessToken: String,
        tokenSecret: String? = nil
    ) -> FirebaseIDPCredential {
        var fields = ["access_token": accessToken]
        if let tokenSecret {
            fields["oauth_token_secret"] = tokenSecret
        }
        return FirebaseIDPCredential(providerId: "twitter.com", fields: fields)
    }

    var postBody: String {
        var items = fields.map { URLQueryItem(name: $0.key, value: $0.value) }
        items.append(URLQueryItem(name: "providerId", value: providerId))
        return FormEncoding.queryString(items)
    }
}

public enum FirebaseAuthError: Error, Sendable, Hashable, LocalizedError {
    case missingConfig
    case invalidEndpoint
    case invalidRequest
    case invalidResponse
    case networkError
    case transportError(String)
    case decodingError(String)
    case googleServiceInfoNotFound
    case invalidGoogleServiceInfo
    case invalidPhoneNumber
    case invalidIdToken
    case invalidCredentialOrProviderId
    case tooManyAttempts
    case invalidVerificationCode
    case sessionExpired
    case credentialAlreadyInUse
    case invalidRefreshToken
    case verificationCodeExpired
    case emailAlreadyInUse
    case invalidEmail
    case weakPassword
    case missingPassword
    case missingEmail
    case userNotFound
    case wrongPassword
    case invalidGrant
    case invalidCredentials
    case operationNotAllowed
    case emailVerificationRequired
    case federatedUserIdAlreadyLinked(SocialLinkErrorResponse)
    case serverError(String)
    case unknown(String)

    public var errorDescription: String? {
        switch self {
        case .missingConfig:
            return "Firebase auth config is missing."
        case .invalidEndpoint:
            return "Firebase auth endpoint is invalid."
        case .invalidRequest:
            return "Firebase auth request is invalid."
        case .invalidResponse:
            return "Firebase auth response is invalid."
        case .networkError:
            return "Firebase auth network request failed."
        case let .transportError(message),
             let .decodingError(message),
             let .serverError(message),
             let .unknown(message):
            return message
        case .googleServiceInfoNotFound:
            return "GoogleService-Info.plist was not found."
        case .invalidGoogleServiceInfo:
            return "GoogleService-Info.plist is missing required Firebase keys."
        case .invalidPhoneNumber:
            return "Phone number is invalid."
        case .invalidIdToken:
            return "Firebase ID token is invalid."
        case .invalidCredentialOrProviderId:
            return "Firebase credential or provider ID is invalid."
        case .tooManyAttempts:
            return "Firebase auth rejected the request due to too many attempts."
        case .invalidVerificationCode:
            return "Verification code is invalid."
        case .sessionExpired:
            return "Verification session expired."
        case .credentialAlreadyInUse:
            return "Credential is already in use."
        case .invalidRefreshToken:
            return "Refresh token is invalid."
        case .verificationCodeExpired:
            return "Verification code expired."
        case .emailAlreadyInUse:
            return "Email is already in use."
        case .invalidEmail:
            return "Email is invalid."
        case .weakPassword:
            return "Password is too weak."
        case .missingPassword:
            return "Password is missing."
        case .missingEmail:
            return "Email is missing."
        case .userNotFound:
            return "Firebase user was not found."
        case .wrongPassword:
            return "Password is incorrect."
        case .invalidGrant:
            return "OAuth grant is invalid."
        case .invalidCredentials:
            return "Credentials are invalid."
        case .operationNotAllowed:
            return "Firebase auth operation is not allowed."
        case .emailVerificationRequired:
            return "Email verification is required."
        case .federatedUserIdAlreadyLinked:
            return "Federated user ID is already linked."
        }
    }
}

public protocol FirebaseAuthClientProtocol: Actor {
    func setAuthConfig(_ config: FirebaseAuthConfig)
    func sendVerificationCode(phoneNumber: String, recaptchaToken: String?) async throws -> String
    func signInWithCode(
        verificationCode: String,
        sessionInfo: FirebasePhoneVerificationSession
    ) async throws -> FirebaseTokenResponse
    func signInAnonymously() async throws -> FirebaseTokenResponse
    func createUserWithEmailPassword(email: String, password: String) async throws -> FirebaseTokenResponse
    func signInWithEmailPassword(email: String, password: String) async throws -> FirebaseTokenResponse
    func signInWithIdp(postBody: String, idToken: String?) async throws -> FirebaseTokenResponse
    func signInWithIdp(_ credential: FirebaseIDPCredential) async throws -> FirebaseTokenResponse
    func signInWithIdpFromAnonymous(
        anonymousIdToken: String,
        credential: FirebaseIDPCredential
    ) async throws -> FirebaseTokenResponse
    func linkWithIdp(idToken: String, credential: FirebaseIDPCredential) async throws -> FirebaseTokenResponse
    func linkWithGoogle(anonymousIdToken: String, googleAccessToken: String) async throws -> FirebaseTokenResponse
    func linkWithFacebook(anonymousIdToken: String, facebookAccessToken: String) async throws -> FirebaseTokenResponse
    func linkWithApple(
        anonymousIdToken: String,
        appleIdToken: String,
        nonce: String
    ) async throws -> FirebaseTokenResponse
    func linkWithTwitter(anonymousIdToken: String, twitterAccessToken: String) async throws -> FirebaseTokenResponse
    func linkWithEmailPassword(
        anonymousIdToken: String,
        email: String,
        password: String
    ) async throws -> FirebaseTokenResponse
    func signInWithGoogleFromAnonymous(
        anonymousIdToken: String,
        googleAccessToken: String
    ) async throws -> FirebaseTokenResponse
    func signInWithFacebookFromAnonymous(
        anonymousIdToken: String,
        facebookAccessToken: String
    ) async throws -> FirebaseTokenResponse
    func signInWithAppleFromAnonymous(
        anonymousIdToken: String,
        appleIdToken: String,
        nonce: String
    ) async throws -> FirebaseTokenResponse
    func signInWithTwitterFromAnonymous(
        anonymousIdToken: String,
        twitterAccessToken: String
    ) async throws -> FirebaseTokenResponse
    func signInWithEmailFromAnonymous(
        anonymousIdToken: String,
        email: String,
        password: String
    ) async throws -> FirebaseTokenResponse
    func refreshIdToken(refreshToken: String) async throws -> FirebaseTokenResponse
    func sendEmailVerification(idToken: String, email: String) async throws
    func checkEmailVerificationStatus(idToken: String) async throws -> Bool
    func confirmEmailVerification(oobCode: String) async throws -> FirebaseTokenResponse
}

public actor FirebaseAuthClient: FirebaseAuthClientProtocol {
    private var config: FirebaseAuthConfig?
    private let transport: any FirebaseAuthTransport
    private let identityToolkitBaseURL: URL
    private let secureTokenBaseURL: URL
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    public init(
        config: FirebaseAuthConfig? = nil,
        transport: any FirebaseAuthTransport = URLSessionFirebaseAuthTransport(),
        identityToolkitBaseURL: URL = URL(string: "https://identitytoolkit.googleapis.com/v1")!,
        secureTokenBaseURL: URL = URL(string: "https://securetoken.googleapis.com/v1")!
    ) {
        self.config = config
        self.transport = transport
        self.identityToolkitBaseURL = identityToolkitBaseURL
        self.secureTokenBaseURL = secureTokenBaseURL
        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()
    }

    public init(
        apiKey: String,
        transport: any FirebaseAuthTransport = URLSessionFirebaseAuthTransport()
    ) {
        self.config = FirebaseAuthConfig(apiKey: apiKey)
        self.transport = transport
        self.identityToolkitBaseURL = URL(string: "https://identitytoolkit.googleapis.com/v1")!
        self.secureTokenBaseURL = URL(string: "https://securetoken.googleapis.com/v1")!
        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()
    }

    public func setAuthConfig(_ config: FirebaseAuthConfig) {
        self.config = config
    }

    public func sendVerificationCode(
        phoneNumber: String,
        recaptchaToken: String? = nil
    ) async throws -> String {
        struct Body: Encodable {
            let phoneNumber: String
            let recaptchaToken: String?
        }

        let response: FirebasePhoneAuthSendVerificationCodeResponse = try await sendJSON(
            path: "accounts:sendVerificationCode",
            body: Body(phoneNumber: phoneNumber, recaptchaToken: recaptchaToken)
        )
        return response.sessionInfo
    }

    public func signInWithCode(
        verificationCode: String,
        sessionInfo: FirebasePhoneVerificationSession
    ) async throws -> FirebaseTokenResponse {
        struct Body: Encodable {
            let sessionInfo: String
            let code: String
        }

        return try await sendJSON(
            path: "accounts:signInWithPhoneNumber",
            body: Body(sessionInfo: sessionInfo.sessionInfo, code: verificationCode)
        )
    }

    public func signInAnonymously() async throws -> FirebaseTokenResponse {
        struct Body: Encodable {
            let returnSecureToken: Bool
        }

        return try await sendJSON(
            path: "accounts:signUp",
            body: Body(returnSecureToken: true)
        )
    }

    public func createUserWithEmailPassword(
        email: String,
        password: String
    ) async throws -> FirebaseTokenResponse {
        struct Body: Encodable {
            let email: String
            let password: String
            let returnSecureToken: Bool
        }

        return try await sendJSON(
            path: "accounts:signUp",
            body: Body(email: email, password: password, returnSecureToken: true)
        )
    }

    public func signInWithEmailPassword(
        email: String,
        password: String
    ) async throws -> FirebaseTokenResponse {
        struct Body: Encodable {
            let email: String
            let password: String
            let returnSecureToken: Bool
        }

        return try await sendJSON(
            path: "accounts:signInWithPassword",
            body: Body(email: email, password: password, returnSecureToken: true)
        )
    }

    public func signInWithIdp(_ credential: FirebaseIDPCredential) async throws -> FirebaseTokenResponse {
        try await signInWithIdpResponse(credential).tokenResponse()
    }

    public func signInWithIdp(
        postBody: String,
        idToken: String? = nil
    ) async throws -> FirebaseTokenResponse {
        try await signInWithIdpResponse(postBody: postBody, idToken: idToken).tokenResponse()
    }

    public func signInWithIdpFromAnonymous(
        anonymousIdToken: String,
        credential: FirebaseIDPCredential
    ) async throws -> FirebaseTokenResponse {
        do {
            return try await linkWithIdp(idToken: anonymousIdToken, credential: credential)
        } catch FirebaseAuthError.federatedUserIdAlreadyLinked {
            return try await signInWithIdp(credential)
        }
    }

    public func getFirebaseToken(googleAccessToken: String) async throws -> FirebaseTokenResponse {
        try await signInWithIdp(.google(accessToken: googleAccessToken))
    }

    public func getFirebaseTokenWithFacebook(facebookAccessToken: String) async throws -> FirebaseTokenResponse {
        try await signInWithIdp(.facebook(accessToken: facebookAccessToken))
    }

    public func getFirebaseTokenWithApple(
        appleIdToken: String,
        nonce: String,
        oauthClientId: String? = nil
    ) async throws -> FirebaseTokenResponse {
        try await signInWithIdp(.apple(idToken: appleIdToken, nonce: nonce, oauthClientId: oauthClientId))
    }

    public func getFirebaseTokenWithTwitter(
        twitterAccessToken: String,
        tokenSecret: String? = nil
    ) async throws -> FirebaseTokenResponse {
        try await signInWithIdp(.twitter(accessToken: twitterAccessToken, tokenSecret: tokenSecret))
    }

    public func linkWithIdp(
        idToken: String,
        credential: FirebaseIDPCredential
    ) async throws -> FirebaseTokenResponse {
        try await linkWithIdpResponse(idToken: idToken, credential: credential).tokenResponse()
    }

    public func linkWithGoogle(
        anonymousIdToken: String,
        googleAccessToken: String
    ) async throws -> FirebaseTokenResponse {
        try await linkWithIdp(idToken: anonymousIdToken, credential: .google(accessToken: googleAccessToken))
    }

    public func linkWithFacebook(
        anonymousIdToken: String,
        facebookAccessToken: String
    ) async throws -> FirebaseTokenResponse {
        try await linkWithIdp(idToken: anonymousIdToken, credential: .facebook(accessToken: facebookAccessToken))
    }

    public func linkWithApple(
        anonymousIdToken: String,
        appleIdToken: String,
        nonce: String
    ) async throws -> FirebaseTokenResponse {
        try await linkWithIdp(
            idToken: anonymousIdToken,
            credential: .apple(idToken: appleIdToken, nonce: nonce)
        )
    }

    public func linkWithTwitter(
        anonymousIdToken: String,
        twitterAccessToken: String
    ) async throws -> FirebaseTokenResponse {
        try await linkWithIdp(idToken: anonymousIdToken, credential: .twitter(accessToken: twitterAccessToken))
    }

    public func linkWithEmailPassword(
        anonymousIdToken: String,
        email: String,
        password: String
    ) async throws -> FirebaseTokenResponse {
        struct Body: Encodable {
            let idToken: String
            let email: String
            let password: String
            let returnSecureToken: Bool
        }

        return try await sendJSON(
            path: "accounts:signUp",
            body: Body(
                idToken: anonymousIdToken,
                email: email,
                password: password,
                returnSecureToken: true
            )
        )
    }

    public func signInWithGoogleFromAnonymous(
        anonymousIdToken: String,
        googleAccessToken: String
    ) async throws -> FirebaseTokenResponse {
        try await signInWithIdpFromAnonymous(
            anonymousIdToken: anonymousIdToken,
            credential: .google(accessToken: googleAccessToken)
        )
    }

    public func signInWithFacebookFromAnonymous(
        anonymousIdToken: String,
        facebookAccessToken: String
    ) async throws -> FirebaseTokenResponse {
        try await signInWithIdpFromAnonymous(
            anonymousIdToken: anonymousIdToken,
            credential: .facebook(accessToken: facebookAccessToken)
        )
    }

    public func signInWithAppleFromAnonymous(
        anonymousIdToken: String,
        appleIdToken: String,
        nonce: String
    ) async throws -> FirebaseTokenResponse {
        try await signInWithIdpFromAnonymous(
            anonymousIdToken: anonymousIdToken,
            credential: .apple(idToken: appleIdToken, nonce: nonce)
        )
    }

    public func signInWithTwitterFromAnonymous(
        anonymousIdToken: String,
        twitterAccessToken: String
    ) async throws -> FirebaseTokenResponse {
        try await signInWithIdpFromAnonymous(
            anonymousIdToken: anonymousIdToken,
            credential: .twitter(accessToken: twitterAccessToken)
        )
    }

    public func signInWithEmailFromAnonymous(
        anonymousIdToken: String,
        email: String,
        password: String
    ) async throws -> FirebaseTokenResponse {
        do {
            return try await linkWithEmailPassword(
                anonymousIdToken: anonymousIdToken,
                email: email,
                password: password
            )
        } catch FirebaseAuthError.emailAlreadyInUse {
            return try await signInWithEmailPassword(email: email, password: password)
        }
    }

    public func refreshIdToken(refreshToken: String) async throws -> FirebaseTokenResponse {
        let response: FirebaseRefreshTokenResponse = try await sendForm(
            path: "token",
            baseURL: secureTokenBaseURL,
            body: [
                URLQueryItem(name: "grant_type", value: "refresh_token"),
                URLQueryItem(name: "refresh_token", value: refreshToken),
            ]
        )

        return FirebaseTokenResponse(
            idToken: response.idToken,
            refreshToken: response.refreshToken,
            expiresIn: response.expiresIn,
            localId: response.userId
        )
    }

    public func sendEmailVerification(idToken: String, email: String) async throws {
        struct Body: Encodable {
            let requestType: String
            let idToken: String
            let email: String
        }

        let _: EmptyFirebaseResponse = try await sendJSON(
            path: "accounts:sendOobCode",
            body: Body(requestType: "VERIFY_EMAIL", idToken: idToken, email: email)
        )
    }

    public func checkEmailVerificationStatus(idToken: String) async throws -> Bool {
        struct Body: Encodable {
            let idToken: String
        }

        let response: AccountLookupResponse = try await sendJSON(
            path: "accounts:lookup",
            body: Body(idToken: idToken)
        )

        guard let user = response.users.first else {
            throw FirebaseAuthError.invalidResponse
        }
        return user.emailVerified
    }

    public func confirmEmailVerification(oobCode: String) async throws -> FirebaseTokenResponse {
        struct Body: Encodable {
            let oobCode: String
        }

        return try await sendJSON(
            path: "accounts:update",
            body: Body(oobCode: oobCode)
        )
    }
}

private extension FirebaseAuthClient {
    func signInWithIdpResponse(
        postBody: String,
        idToken: String?
    ) async throws -> LinkWithIdpResponse {
        if let idToken {
            return try await linkWithIdpResponse(idToken: idToken, postBody: postBody)
        }
        return try await signInWithIdpResponse(postBody: postBody)
    }

    func signInWithIdpResponse(_ credential: FirebaseIDPCredential) async throws -> LinkWithIdpResponse {
        try await signInWithIdpResponse(postBody: credential.postBody)
    }

    func signInWithIdpResponse(postBody: String) async throws -> LinkWithIdpResponse {
        struct Body: Encodable {
            let postBody: String
            let requestUri: String
            let returnSecureToken: Bool
            let returnIdpCredential: Bool
        }

        return try await sendJSON(
            path: "accounts:signInWithIdp",
            body: Body(
                postBody: postBody,
                requestUri: try requestURI(),
                returnSecureToken: true,
                returnIdpCredential: true
            )
        )
    }

    func linkWithIdpResponse(
        idToken: String,
        credential: FirebaseIDPCredential
    ) async throws -> LinkWithIdpResponse {
        try await linkWithIdpResponse(idToken: idToken, postBody: credential.postBody)
    }

    func linkWithIdpResponse(
        idToken: String,
        postBody: String
    ) async throws -> LinkWithIdpResponse {
        struct Body: Encodable {
            let idToken: String
            let postBody: String
            let requestUri: String
            let returnSecureToken: Bool
            let returnIdpCredential: Bool
        }

        return try await sendJSON(
            path: "accounts:signInWithIdp",
            body: Body(
                idToken: idToken,
                postBody: postBody,
                requestUri: try requestURI(),
                returnSecureToken: true,
                returnIdpCredential: true
            )
        )
    }

    func requestURI() throws -> String {
        guard let config else {
            throw FirebaseAuthError.missingConfig
        }
        return config.requestURI
    }

    func sendJSON<Response: Decodable>(
        path: String,
        body: some Encodable,
        baseURL: URL? = nil
    ) async throws -> Response {
        var request = try request(path: path, baseURL: baseURL ?? identityToolkitBaseURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try encoder.encode(AnyEncodable(body))
        return try await execute(request)
    }

    func sendForm<Response: Decodable>(
        path: String,
        baseURL: URL,
        body: [URLQueryItem]
    ) async throws -> Response {
        var request = try request(path: path, baseURL: baseURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = FormEncoding.queryString(body).data(using: .utf8)
        return try await execute(request)
    }

    func request(path: String, baseURL: URL) throws -> URLRequest {
        guard let config else {
            throw FirebaseAuthError.missingConfig
        }

        let url = baseURL.appendingPathComponent(path)
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            throw FirebaseAuthError.invalidEndpoint
        }
        components.queryItems = [URLQueryItem(name: "key", value: config.apiKey)]

        guard let resolvedURL = components.url else {
            throw FirebaseAuthError.invalidEndpoint
        }
        return URLRequest(url: resolvedURL)
    }

    func execute<Response: Decodable>(_ request: URLRequest) async throws -> Response {
        let payload: FirebaseAuthTransportResponse
        do {
            payload = try await transport.data(for: request)
        } catch let error as FirebaseAuthError {
            throw error
        } catch {
            throw FirebaseAuthError.transportError(error.localizedDescription)
        }

        switch payload.statusCode {
        case 200:
            if Response.self == EmptyFirebaseResponse.self, payload.data.isEmpty {
                return EmptyFirebaseResponse() as! Response
            }
            do {
                return try decoder.decode(Response.self, from: payload.data)
            } catch {
                throw FirebaseAuthError.decodingError(error.localizedDescription)
            }
        case 400, 401, 403:
            throw decodeFirebaseError(from: payload.data, fallbackStatusCode: payload.statusCode)
        default:
            if let errorResponse = try? decoder.decode(FirebaseErrorResponse.self, from: payload.data) {
                throw FirebaseAuthError.serverError(errorResponse.error.message)
            }
            throw FirebaseAuthError.serverError("Unexpected status code: \(payload.statusCode)")
        }
    }

    func decodeFirebaseError(from data: Data, fallbackStatusCode: Int) -> FirebaseAuthError {
        guard let response = try? decoder.decode(FirebaseErrorResponse.self, from: data) else {
            return fallbackStatusCode == 401 ? .invalidGrant : .invalidCredentials
        }
        return FirebaseAuthError(firebaseMessage: response.error.message)
    }
}

private extension LinkWithIdpResponse {
    func tokenResponse() throws -> FirebaseTokenResponse {
        if let errorMessage, !errorMessage.isEmpty {
            if errorMessage == "FEDERATED_USER_ID_ALREADY_LINKED" || errorMessage == "EMAIL_EXISTS" {
                throw FirebaseAuthError.federatedUserIdAlreadyLinked(
                    SocialLinkErrorResponse(
                        federatedId: federatedId ?? "",
                        providerId: providerId ?? "",
                        email: email ?? "",
                        emailVerified: emailVerified ?? false,
                        firstName: firstName,
                        fullName: fullName,
                        photoUrl: photoUrl,
                        displayName: displayName,
                        oauthAccessToken: oauthAccessToken ?? "",
                        oauthExpireIn: oauthExpireIn ?? 0,
                        rawUserInfo: rawUserInfo ?? "",
                        errorMessage: errorMessage,
                        kind: "identitytoolkit#VerifyAssertionResponse"
                    )
                )
            }
            throw FirebaseAuthError.serverError(errorMessage)
        }

        guard
            let idToken,
            let refreshToken,
            let expiresIn,
            let localId
        else {
            throw FirebaseAuthError.invalidResponse
        }

        return FirebaseTokenResponse(
            idToken: idToken,
            refreshToken: refreshToken,
            expiresIn: expiresIn,
            localId: localId,
            email: email,
            displayName: displayName,
            photoUrl: photoUrl
        )
    }
}

private extension FirebaseAuthError {
    init(firebaseMessage message: String) {
        switch message {
        case "INVALID_PHONE_NUMBER":
            self = .invalidPhoneNumber
        case "TOO_MANY_ATTEMPTS":
            self = .tooManyAttempts
        case "INVALID_CODE", "INVALID_OOB_CODE":
            self = .invalidVerificationCode
        case "SESSION_EXPIRED":
            self = .sessionExpired
        case "INVALID_REFRESH_TOKEN", "TOKEN_EXPIRED":
            self = .invalidRefreshToken
        case "EMAIL_EXISTS":
            self = .emailAlreadyInUse
        case "EMAIL_NOT_FOUND":
            self = .userNotFound
        case "INVALID_PASSWORD":
            self = .wrongPassword
        case "INVALID_EMAIL":
            self = .invalidEmail
        case "WEAK_PASSWORD":
            self = .weakPassword
        case "MISSING_PASSWORD":
            self = .missingPassword
        case "MISSING_EMAIL":
            self = .missingEmail
        case "OPERATION_NOT_ALLOWED":
            self = .operationNotAllowed
        case "INVALID_ID_TOKEN":
            self = .invalidIdToken
        case "INVALID_CREDENTIAL_OR_PROVIDER_ID":
            self = .invalidCredentialOrProviderId
        case "EXPIRED_OOB_CODE":
            self = .verificationCodeExpired
        case "CREDENTIAL_ALREADY_IN_USE":
            self = .credentialAlreadyInUse
        case "FEDERATED_USER_ID_ALREADY_LINKED":
            self = .federatedUserIdAlreadyLinked(
                SocialLinkErrorResponse(
                    federatedId: "",
                    providerId: "",
                    email: "",
                    emailVerified: false,
                    oauthAccessToken: "",
                    oauthExpireIn: 0,
                    rawUserInfo: "",
                    errorMessage: message,
                    kind: "identitytoolkit#VerifyAssertionResponse"
                )
            )
        default:
            self = .serverError(message)
        }
    }
}

private struct EmptyFirebaseResponse: Decodable {
    init() {}
}

private struct AccountLookupResponse: Decodable {
    let users: [AccountLookupUser]
}

private struct AccountLookupUser: Decodable {
    let emailVerified: Bool
}

private struct AnyEncodable: Encodable {
    private let encode: (any Encoder) throws -> Void

    init(_ wrapped: some Encodable) {
        self.encode = wrapped.encode
    }

    func encode(to encoder: any Encoder) throws {
        try encode(encoder)
    }
}

enum FormEncoding {
    static func queryString(_ items: [URLQueryItem]) -> String {
        var components = URLComponents()
        components.queryItems = items
        return components.percentEncodedQuery ?? ""
    }
}
