// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// The wallet's side of delivered secrets (privatedata-spec SPEC section 5A): what the OpenID4VCI client
// MUST check on a Credential Response that carries `org.siros.secret_seed`, the strip-before-merge rule for
// display metadata, and the advertisement check on issuer metadata. Pure: no storage, no network, no logging.
// The seed is never part of an error value or a description.

/// The `credential_metadata` member of a Credential Response as the receipt sees it. Members are in the
/// order received.
public enum DeliveredSecretMetadataInput: Sendable, Equatable {
    /// The response has no `credential_metadata`.
    case absent
    /// `credential_metadata` is present but not a JSON object (an array, a string, `null`): malformed.
    case notObject
    case members([DeliveredSecretMember])
}

public struct DeliveredSecretMember: Sendable, Equatable {
    public let name: String
    public let value: JSONValue

    public init(name: String, value: JSONValue) {
        self.name = name
        self.value = value
    }
}

/// The credential's commitment to a delivered secret: for `nym_auth`, `SHA256(secret_seed) == ssc`, where
/// the seed is the one of the namespace the credential type designates.
public struct DeliveredSecretCommitment: Sendable, Equatable {
    public let namespace: String
    public let ssc: [UInt8]

    public init(namespace: String, ssc: [UInt8]) {
        self.namespace = namespace
        self.ssc = ssc
    }
}

/// Why a response is refused: the issuance fails and nothing from the response is stored. Carries no value.
public enum DeliveredSecretRefusal: Error, Sendable, Equatable {
    /// `credential_metadata` is not a JSON object.
    case metadataNotObject
    /// A response carrying a seed was not JWE-encrypted.
    case plainResponse
    /// A Deferred Credential Response carrying a seed (not supported in this version).
    case deferredResponse
    /// A response carrying a seed has no `notification_id`.
    case missingNotificationId
    /// The `org.siros.secret_seed` member is malformed (limits, hex form, advertisement form).
    case malformedSeedMember
    /// The designated namespace is not in the object.
    case commitmentNamespaceAbsent
    /// `SHA256(secret_seed)` is not the credential's `ssc`.
    case commitmentMismatch
}

/// What an accepted response yields.
public struct DeliveredSecretReceived: Sendable, Equatable {
    /// The `metadata` entries to store in EACH credential entry of the response (`type` is the member
    /// name, `value` is the member's value exactly as received), in the order received. Includes the seed
    /// entry when one was delivered.
    public let storedMetadata: [DeliveredSecretMember]
    /// `credential_metadata` without `org.siros.secret_seed`: the only part that may be merged into display
    /// metadata, rendered, cached or logged.
    public let displayMembers: [DeliveredSecretMember]
    /// The delivered seeds by namespace (16 bytes each), for the secret store only; empty when none.
    /// Never print or log.
    public let seeds: [String: [UInt8]]
}

extension DeliveredSecretReceived: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "DeliveredSecretReceived(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }
}

/// What issuer metadata says about a delivered seed.
public enum DeliveredSecretAdvertisement: Sendable, Equatable {
    /// No `org.siros.secret_seed` member.
    case none
    /// A valid advertisement of namespace names: the wallet MUST request `credential_response_encryption`
    /// and MUST refuse a plain response.
    case advertised(namespaces: [String])
    /// Malformed (a seed value in issuer metadata, bad limits): the configuration is treated as not offered.
    case malformed
}

public enum DeliveredSecretReceipt {
    /// The member name this specification defines.
    public static let memberName = "org.siros.secret_seed"
    /// The reserved key of the advertisement form.
    public static let reservedNamespace = "namespaces"
    // Limits of this version of the specification; named, not buried, so a later version can raise them.
    public static let minNamespaces = 1
    public static let maxNamespaces = 8
    public static let maxNamespaceBytes = 64
    public static let seedHexCharacters = 32

    /// Applies section 5A.2 to a response. `jweEncrypted` is whether the response was JWE-decrypted,
    /// `deferred` whether it is a Deferred Credential Response. Throws ``DeliveredSecretRefusal``.
    public static func receive(
        metadata: DeliveredSecretMetadataInput, jweEncrypted: Bool, deferred: Bool, hasNotificationId: Bool,
        commitment: DeliveredSecretCommitment?
    ) throws -> DeliveredSecretReceived {
        let members: [DeliveredSecretMember]
        switch metadata {
        case .absent: return DeliveredSecretReceived(storedMetadata: [], displayMembers: [], seeds: [:])
        case .notObject: throw DeliveredSecretRefusal.metadataNotObject
        case .members(let all): members = all
        }
        let display = members.filter { $0.name != memberName }
        guard let seedMember = members.first(where: { $0.name == memberName }) else {
            return DeliveredSecretReceived(storedMetadata: members, displayMembers: display, seeds: [:])
        }
        // A response that carries a seed must be encrypted, not deferred and carry a notification id.
        guard !deferred else { throw DeliveredSecretRefusal.deferredResponse }
        guard jweEncrypted else { throw DeliveredSecretRefusal.plainResponse }
        guard hasNotificationId else { throw DeliveredSecretRefusal.missingNotificationId }
        var seeds = try parseSeeds(seedMember.value)
        defer { for key in seeds.keys { wipe(&seeds[key]) } }
        if let commitment {
            guard var seed = seeds[commitment.namespace] else { throw DeliveredSecretRefusal.commitmentNamespaceAbsent }
            defer { wipe(&seed) }
            var digest = Array(SHA256.hash(data: seed))
            defer { wipe(&digest) }
            guard commitment.ssc.count == digest.count, constantTimeEqual(digest, commitment.ssc) else {
                throw DeliveredSecretRefusal.commitmentMismatch
            }
        }
        return DeliveredSecretReceived(storedMetadata: members, displayMembers: display, seeds: seeds)
    }

    /// Strip before merge: `response` without `org.siros.secret_seed`, merged over `issuer` (the issuer
    /// metadata's `credential_metadata`): members of the response overwrite members of the same name, and the
    /// issuer's public advertisement stays. The seed is absent from the result.
    public static func mergedDisplayMetadata(issuer: [String: JSONValue]?, response: [DeliveredSecretMember]) -> [String: JSONValue] {
        var merged = issuer ?? [:]
        for member in response where member.name != memberName { merged[member.name] = member.value }
        return merged
    }

    /// Section 5A.4: issuer metadata advertises namespace NAMES, never values.
    public static func advertisement(issuerCredentialMetadata: [String: JSONValue]?) -> DeliveredSecretAdvertisement {
        guard let value = issuerCredentialMetadata?[memberName] else { return .none }
        guard case .object(let object) = value, object.count == 1, case .array(let list)? = object[reservedNamespace] else { return .malformed }
        let names = list.compactMap(\.stringValue)
        guard names.count == list.count, (minNamespaces...maxNamespaces).contains(names.count), Set(names).count == names.count,
              names.allSatisfy({ validNamespace($0) && !isSeedHex($0) }) else { return .malformed }
        return .advertised(namespaces: names)
    }

    // MARK: -

    private static func validNamespace(_ name: String) -> Bool {
        let bytes = name.utf8.count
        return bytes >= 1 && bytes <= maxNamespaceBytes && name != reservedNamespace
    }

    private static func isSeedHex(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        return bytes.count == seedHexCharacters && bytes.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    /// The seeds of an `org.siros.secret_seed` value: 1 to 8 namespaces, each a seed of 32 lowercase hex characters.
    private static func parseSeeds(_ value: JSONValue) throws -> [String: [UInt8]] {
        guard case .object(let object) = value, (minNamespaces...maxNamespaces).contains(object.count) else {
            throw DeliveredSecretRefusal.malformedSeedMember
        }
        var seeds: [String: [UInt8]] = [:]
        for (namespace, seedValue) in object {
            guard validNamespace(namespace), let text = seedValue.stringValue, isSeedHex(text) else {
                for key in seeds.keys { wipe(&seeds[key]) }
                throw DeliveredSecretRefusal.malformedSeedMember
            }
            let utf8 = Array(text.utf8)
            func nibble(_ c: UInt8) -> UInt8 { c <= 0x39 ? c - 0x30 : c - 0x61 + 10 }
            seeds[namespace] = stride(from: 0, to: utf8.count, by: 2).map { (nibble(utf8[$0]) << 4) | nibble(utf8[$0 + 1]) }
        }
        return seeds
    }

    private static func wipe(_ bytes: inout [UInt8]?) {
        guard var value = bytes else { return }
        wipe(&value)
        bytes = value
    }

    private static func wipe(_ bytes: inout [UInt8]) {
        for index in bytes.indices { bytes[index] = 0 }
    }

    private static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for index in a.indices { difference |= a[index] ^ b[index] }
        return difference == 0
    }
}
