import Foundation

public protocol JWT {
    var header: [String: Any] { get }
    var body: [String: Any] { get }
    var signature: String? { get }
    var string: String { get }
    var expiresAt: Date? { get }
    var issuer: String? { get }
    var subject: String? { get }
    var audience: [String]? { get }
    var issuedAt: Date? { get }
    var notBefore: Date? { get }
    var identifier: String? { get }
    var expired: Bool { get }
    func claim(name: String) -> JWTClaim
}

public extension JWT {
    func claim(name: String) -> JWTClaim {
        JWTClaim(value: body[name])
    }

    subscript(claim: String) -> JWTClaim {
        self.claim(name: claim)
    }
}

public enum JWTDecodeError: LocalizedError, CustomDebugStringConvertible {
    case invalidBase64URL(String)
    case invalidJSON(String)
    case invalidPartCount(String, Int)

    public var errorDescription: String? {
        switch self {
        case let .invalidBase64URL(value):
            return "JWT part is not valid Base64URL: \(value)"
        case let .invalidJSON(value):
            return "JWT part is not valid JSON: \(value)"
        case let .invalidPartCount(_, count):
            return "JWT has \(count) parts instead of 3."
        }
    }

    public var debugDescription: String {
        errorDescription ?? "JWT decode error"
    }
}

public func decodeJwt(_ jwt: String) throws -> any JWT {
    try DecodedJWT(jwt: jwt)
}

public func extractTTL(from jwt: String) throws -> Date? {
    try decodeJwt(jwt).expiresAt
}

struct DecodedJWT: JWT {
    let header: [String: Any]
    let body: [String: Any]
    let signature: String?
    let string: String

    init(jwt: String) throws {
        let parts = jwt.components(separatedBy: ".")
        guard parts.count == 3 else {
            throw JWTDecodeError.invalidPartCount(jwt, parts.count)
        }

        self.header = try decodeJWTPart(parts[0])
        self.body = try decodeJWTPart(parts[1])
        self.signature = parts[2]
        self.string = jwt
    }

    var expiresAt: Date? { claim(name: "exp").date }
    var issuer: String? { claim(name: "iss").string }
    var subject: String? { claim(name: "sub").string }
    var audience: [String]? { claim(name: "aud").array }
    var issuedAt: Date? { claim(name: "iat").date }
    var notBefore: Date? { claim(name: "nbf").date }
    var identifier: String? { claim(name: "jti").string }

    var expired: Bool {
        guard let expiresAt else {
            return false
        }
        return expiresAt <= Date()
    }
}

public struct JWTClaim {
    let value: Any?

    public var rawValue: Any? {
        value
    }

    public var string: String? {
        value as? String
    }

    public var boolean: Bool? {
        if let value = value as CFTypeRef?, CFGetTypeID(value) == CFBooleanGetTypeID() {
            return self.value as? Bool
        }
        return nil
    }

    public var double: Double? {
        if let string {
            return Double(string)
        }
        if boolean == nil {
            return value as? Double
        }
        return nil
    }

    public var integer: Int? {
        if let string {
            return Int(string)
        }
        if let double {
            return Int(double)
        }
        if boolean == nil {
            return value as? Int
        }
        return nil
    }

    public var date: Date? {
        guard let timestamp = double else {
            return nil
        }
        return Date(timeIntervalSince1970: timestamp)
    }

    public var array: [String]? {
        if let array = value as? [String] {
            return array
        }
        if let string {
            return [string]
        }
        return nil
    }
}

private func base64UrlDecode(_ value: String) -> Data? {
    var base64 = value
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")

    let length = Double(base64.lengthOfBytes(using: .utf8))
    let requiredLength = 4 * ceil(length / 4.0)
    let paddingLength = requiredLength - length
    if paddingLength > 0 {
        base64 += String(repeating: "=", count: Int(paddingLength))
    }
    return Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
}

private func decodeJWTPart(_ value: String) throws -> [String: Any] {
    guard let bodyData = base64UrlDecode(value) else {
        throw JWTDecodeError.invalidBase64URL(value)
    }

    guard
        let json = try? JSONSerialization.jsonObject(with: bodyData),
        let payload = json as? [String: Any]
    else {
        throw JWTDecodeError.invalidJSON(value)
    }

    return payload
}
