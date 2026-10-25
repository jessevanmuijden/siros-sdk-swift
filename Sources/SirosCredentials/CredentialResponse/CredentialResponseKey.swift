// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A wallet-held ephemeral key for ONE Credential Response: the issuer's response is encrypted to
/// its public half, so an engine that relays the response cannot read it (engine-blind issuance).
///
/// A new key per `generate_proof` request, so each c_nonce retry gets its own. It exists only in
/// memory: there is deliberately no way to serialize it.
public final class CredentialResponseKey: @unchecked Sendable {

    public let params: CredentialResponseEncryptionParams
    private let privateKey: P256.KeyAgreement.PrivateKey

    /// A fresh key for `params`, or nil when this build cannot open that `alg`/`enc`.
    public init?(params: CredentialResponseEncryptionParams) {
        guard params.isSupported else { return nil }
        self.params = params
        self.privateKey = P256.KeyAgreement.PrivateKey()
    }

    /// Test seam: a key the test holds, to encrypt a known response to.
    init(params: CredentialResponseEncryptionParams, privateKey: P256.KeyAgreement.PrivateKey) {
        self.params = params
        self.privateKey = privateKey
    }

    /// The public JWK for the credential request's `credential_response_encryption.jwk`:
    /// `{kty:EC, crv:P-256, x, y, use:enc, alg}` (no private member, no `kid`).
    public var publicJwk: [String: String] {
        let point = privateKey.publicKey.x963Representation
        return [
            "kty": "EC",
            "crv": "P-256",
            "x": CredentialResponseJwe.encode(point.subdata(in: 1..<33)),
            "y": CredentialResponseJwe.encode(point.subdata(in: 33..<65)),
            "use": "enc",
            "alg": params.alg,
        ]
    }

    /// Open a Credential Response JWE; the header must carry exactly the negotiated `alg` and `enc`.
    public func decrypt(_ compact: String) throws -> Data {
        try CredentialResponseJwe.decrypt(compact, recipient: privateKey, expected: params)
    }
}

/// A decrypted OpenID4VCI Credential Response, reduced to what the wallet acts on.
public struct DecryptedCredentialResponse: Sendable, Equatable {

    public enum ParseError: Error, Sendable, Equatable {
        case notAnObject
        case malformed(String)
    }

    /// Each credential as the string the wallet stores (an object-valued credential is stored as its JSON).
    public let credentials: [String]
    /// The Credential Response's `notification_id`, when it has one.
    public let notificationId: String?
    /// `transaction_id` and `interval`: the deferred-issuance control fields.
    public let transactionId: String?
    public let interval: Int?
    /// The response-level `credential_metadata`, exactly as received: absent, or any JSON value (a
    /// consumer such as `DeliveredSecretReceipt` decides what a non-object means).
    public let credentialMetadata: JSONValue?
    /// A digest of the JWE this response was opened from, set by the owner that retains it: the same encrypted response
    /// delivered again (a retried child) is recognised and not retained twice.
    public var sourceDigest: String?

    public init(
        credentials: [String], notificationId: String? = nil, transactionId: String? = nil,
        interval: Int? = nil, credentialMetadata: JSONValue? = nil
    ) {
        self.credentials = credentials
        self.notificationId = notificationId
        self.transactionId = transactionId
        self.interval = interval
        self.credentialMetadata = credentialMetadata
    }

    /// Parse the plaintext of a Credential Response (immediate or deferred). The JSON is parsed
    /// strictly (no duplicate members, bounded nesting). A response with neither credentials nor a
    /// `transaction_id` is malformed.
    public static func parse(_ plaintext: Data) throws -> DecryptedCredentialResponse {
        guard let value = try? StrictJSON.parse(plaintext), case .object(let object) = value else {
            throw ParseError.notAnObject
        }
        var credentials: [String] = []
        if let list = object["credentials"] {
            guard case .array(let entries) = list else { throw ParseError.malformed("credentials is not an array") }
            for entry in entries {
                guard case .object(let member) = entry, let credential = member["credential"] else {
                    throw ParseError.malformed("a credentials entry has no credential")
                }
                credentials.append(try stored(credential))
            }
        } else if let single = object["credential"] {
            credentials.append(try stored(single))
        }
        let transactionId = object["transaction_id"]?.stringValue
        if object["transaction_id"] != nil && transactionId == nil { throw ParseError.malformed("transaction_id is not a string") }
        guard !credentials.isEmpty || transactionId != nil else { throw ParseError.malformed("no credentials and no transaction_id") }
        var interval: Int?
        if let raw = object["interval"] {
            guard case .int(let seconds) = raw, seconds >= 0, seconds <= Int64(Int32.max) else { throw ParseError.malformed("interval") }
            interval = Int(seconds)
        }
        let notificationId = object["notification_id"]?.stringValue
        if object["notification_id"] != nil && notificationId == nil { throw ParseError.malformed("notification_id is not a string") }
        let metadata = object["credential_metadata"]
        if let metadata { try checkLimits(metadata) }
        return DecryptedCredentialResponse(
            credentials: credentials, notificationId: notificationId, transactionId: transactionId,
            interval: interval, credentialMetadata: metadata
        )
    }

    /// The `notification_id` of a response, read leniently, so a response rejected for any other reason
    /// can still be reported to the issuer as `credential_failure`. nil when the plaintext has none.
    public static func notificationId(in plaintext: Data) -> String? {
        // Lenient on purpose (a duplicate member is exactly what may have got the response rejected): this
        // reads one string and nothing else from the document.
        guard let object = (try? JSONSerialization.jsonObject(with: plaintext)) as? [String: Any],
              let id = object["notification_id"] as? String, !id.isEmpty else { return nil }
        return id
    }

    // The limits the engine used to enforce on `credential_metadata` before it stopped seeing it. The JSON
    // is parsed strictly, so a duplicate member never gets this far.
    public static let maxMetadataBytes = 1_048_576
    public static let maxMetadataDepth = 16
    public static let maxMetadataMembers = 256
    public static let maxMemberNameBytes = 256

    private static func checkLimits(_ metadata: JSONValue) throws {
        func walk(_ value: JSONValue, depth: Int) throws {
            guard depth <= maxMetadataDepth else { throw ParseError.malformed("credential_metadata is nested too deeply") }
            switch value {
            case .array(let items): for item in items { try walk(item, depth: depth + 1) }
            case .object(let members):
                guard members.count <= maxMetadataMembers else { throw ParseError.malformed("credential_metadata has too many members") }
                for (name, member) in members {
                    guard name.utf8.count <= maxMemberNameBytes else { throw ParseError.malformed("a member name is too long") }
                    try walk(member, depth: depth + 1)
                }
            default: break
            }
        }
        try walk(metadata, depth: 1)
        guard try json(metadata).utf8.count <= maxMetadataBytes else { throw ParseError.malformed("credential_metadata is too large") }
    }

    private static func stored(_ value: JSONValue) throws -> String {
        switch value {
        case .string(let text):
            guard !text.isEmpty else { throw ParseError.malformed("an empty credential") }
            return text
        case .object:
            return try json(value)
        default:
            throw ParseError.malformed("a credential is neither a string nor an object")
        }
    }

    /// Compact JSON with sorted members, for an object-valued credential. Numbers are written as the
    /// token the strict parser validated, so no value is rounded or re-typed on the way through.
    private static func json(_ value: JSONValue) throws -> String {
        switch value {
        case .null: return "null"
        case .bool(let flag): return flag ? "true" : "false"
        case .int(let number): return String(number)
        case .decimal(let token): return token
        case .double(let number):
            guard number.isFinite else { throw ParseError.malformed("a number is not finite") }
            return "\(number)"
        case .string(let text): return try quoted(text)
        case .array(let items): return "[" + (try items.map(json).joined(separator: ",")) + "]"
        case .object(let members):
            let pairs = try members.keys.sorted().map { key in try quoted(key) + ":" + json(members[key] ?? .null) }
            return "{" + pairs.joined(separator: ",") + "}"
        }
    }

    private static func quoted(_ text: String) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return String(decoding: try encoder.encode(text), as: UTF8.self)
    }
}
