// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The response-level `credential_metadata` object of an OpenID4VCI 1.1 Credential
/// Response, as the wallet engine (or a WMP issuer) relays it with the issued
/// credentials (privatedata-spec section 5A).
///
/// It is the SAME object as the display-oriented `credential_metadata` of the public
/// issuer metadata and may carry a delivered secret (`org.siros.secret_seed`), so this
/// type is deliberately inert:
///
/// - **The members are kept verbatim**, including every member this SDK does not
///   understand, so what is stored is what the issuer sent.
/// - **Decoding never throws.** A value that is not a JSON object becomes the
///   ``isMalformed`` placeholder instead of an error: the frame it arrived in must still
///   decode (notably the credentials' `notification_id`) so the wallet can refuse the
///   issuance explicitly and tell the issuer, instead of dropping the frame and hanging.
/// - **It never prints, logs or re-encodes its content.** `description`,
///   `debugDescription` and the reflection mirror are redacted, and encoding writes JSON
///   `null`: a message holding this value cannot leak the seed through a logger, a dump
///   or an encoder. Read ``members`` only where the value is used.
public struct CredentialResponseMetadata: Sendable, Equatable, Codable,
    CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {

    /// The member name this specification defines for a delivered secret seed.
    public static let secretSeedMember = "org.siros.secret_seed"

    /// The object's members exactly as received (empty for a malformed placeholder).
    public let members: [String: AnyCodable]

    /// True when the wire value was not a JSON object. Such a placeholder carries no
    /// data: a consumer MUST refuse the issuance rather than store or interpret it.
    public let isMalformed: Bool

    public init(members: [String: AnyCodable]) {
        self.members = members
        self.isMalformed = false
    }

    /// The placeholder for a `credential_metadata` that is not a JSON object.
    public static let malformed = CredentialResponseMetadata(members: [:], isMalformed: true)

    private init(members: [String: AnyCodable], isMalformed: Bool) {
        self.members = members
        self.isMalformed = isMalformed
    }

    public init(from decoder: Decoder) throws {
        guard let container = try? decoder.singleValueContainer(),
              let value = try? container.decode(AnyCodable.self),
              case .object_(let object) = value else {
            self = .malformed
            return
        }
        self.init(members: object)
    }

    /// The metadata member of a frame: nil only when the key is ABSENT. An explicit `null` (or any other
    /// non-object) is the ``malformed`` placeholder, so a consumer can tell "the issuer sent no metadata"
    /// from "the issuer sent something that is not an object" and refuse the latter.
    public static func decode<Key: CodingKey>(from container: KeyedDecodingContainer<Key>, forKey key: Key) -> CredentialResponseMetadata? {
        guard container.contains(key) else { return nil }
        return (try? container.decode(CredentialResponseMetadata.self, forKey: key)) ?? .malformed
    }

    /// Always encodes JSON `null`: the content is never written out by this type.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encodeNil()
    }

    public var description: String { "CredentialResponseMetadata(<redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// A boolean flag from a relayed frame that never fails the frame: anything that is not a
/// JSON boolean is `false`. (The engine sets `credential_metadata_encrypted_response` only
/// when the issuer's response was a JWE; a malformed value must not be read as "encrypted".)
public struct LenientFlag: Sendable, Equatable, Codable, ExpressibleByBooleanLiteral {
    public let value: Bool

    public init(_ value: Bool) { self.value = value }
    public init(booleanLiteral value: Bool) { self.value = value }

    public init(from decoder: Decoder) throws {
        value = (try? decoder.singleValueContainer().decode(Bool.self)) ?? false
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}

/// The members a REPLAYED `wmp.flow.complete` result had removed before it was replayed
/// (`redacted_members`, WMP spec): exactly the members that were present and withheld,
/// drawn from `credential_metadata`, `credential_metadata_encrypted_response`,
/// `refresh_token`, `dpop_jwk`, `dpop_key_id`. A listed member is NOT RECOVERABLE: it is
/// never invented, reused or substituted, a seed that is required but withheld means the
/// issuance fails or is re-issued, and renewal of that issuance is unavailable. The live
/// completion on the connected SSE stream carries no marker. Decoding never throws:
/// anything that is not an array of strings is read as no marker, because the members
/// themselves are then simply absent.
public struct RedactedMembers: Sendable, Equatable, Codable {
    public let names: Set<String>

    public init(_ names: Set<String>) { self.names = names }

    public init(from decoder: Decoder) throws {
        let array = (try? decoder.singleValueContainer().decode([AnyCodable].self)) ?? []
        names = Set(array.compactMap { $0.stringValue })
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(names.sorted())
    }

    public static let credentialMetadata = "credential_metadata"
    public static let refreshToken = "refresh_token"
    public static let dpopJwk = "dpop_jwk"
    public static let dpopKeyId = "dpop_key_id"

    public func contains(_ member: String) -> Bool { names.contains(member) }
}
