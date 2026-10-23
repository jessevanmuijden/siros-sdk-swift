// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A wallet root secret that can derive labelled secrets without ever handing out the key itself.
///
/// Internal on purpose: a public generic derivation primitive would let any SDK consumer call it
/// with the seed label and read the seed. Keystores keep their root key behind it and expose only
/// purpose-bound views; tests supply a fixed root.
protocol RootSecret {
    /// `HKDF-SHA256(root, salt = empty, info)[:length]`; `info` is the full HKDF info input, label
    /// included, and `length` at most 32.
    func deriveSecret(info: [UInt8], length: Int) throws -> [UInt8]
}

/// A root secret from a key the caller supplies (tests, demos): the same derivation a keystore
/// applies to its container `mainKey`. It holds no wallet secret.
struct FixedRootSecret: RootSecret {
    private let key: [UInt8]

    init(key: [UInt8]) { self.key = key }

    func deriveSecret(info: [UInt8], length: Int) throws -> [UInt8] {
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: key), salt: Data(), info: Data(info), outputByteCount: 32)
        return derived.withUnsafeBytes { Array($0.prefix(length)) }
    }
}

/// Why a private seed was not derived. The message names no value.
enum PrivateSeedError: Error, Equatable {
    /// An empty credential type or issuer.
    case emptyField
    /// A credential type or issuer whose UTF-8 encoding is longer than 65535 bytes.
    case fieldTooLong
}

/// The holder's `private_seed` for a credential type at an issuer, and its commitment.
///
/// `private_seed = HKDF-SHA256(mainKey, salt = empty, info = "org.siros.private_seed/v2" ||
/// lp(credentialType) || lp(issuer))[:16]`, `psc = SHA256(private_seed)` (privatedata-spec SPEC
/// 2.7, section 5.4.1), `lp(x)` = 2-byte big-endian length || UTF-8 bytes, which makes the
/// encoding injective. The seed is stable per (credential type, issuer): it does not depend on a
/// credential id, a batch or an issuance, so every batch, issuance and renewal of one type at
/// one issuer commits to the same `psc`, and two issuers cannot link the holder by it.
/// `credentialType` is an opaque caller-supplied string (a doctype, a vct) and `issuer` the
/// Credential Issuer Identifier exactly as the credential carries it
/// (`S.credentials[].credentialIssuerIdentifier`): both are UTF-8 encoded and compared as exact
/// strings, with no normalisation. An empty field, or one over 65535 bytes, is refused.
///
/// The root is the container `mainKey`, not a PRF output: `mainKey` is the same on every
/// passkey and device of an account, while PRF outputs differ per passkey. `mainKey` MUST NEVER
/// be rotated or re-keyed: doing so changes every seed and so every `psc`.
///
/// The seed never leaves this module except as a witness handed to the configured prover: it is
/// not returned by any public API, logged, stored or cached, and appears in no error message.
/// Every call derives it afresh, so a locked keystore yields nothing.
struct PrivateSeed {
    /// The derivation label, including its version.
    static let label = "org.siros.private_seed/v2"
    /// The rulebook's `private_seed` length.
    static let seedBytes = 16
    /// The longest field `lp` can length-prefix.
    static let maxFieldBytes = 65535

    private let root: any RootSecret

    init(root: any RootSecret) { self.root = root }

    /// `label || lp(credentialType) || lp(issuer)`.
    static func info(credentialType: String, issuer: String) throws -> [UInt8] {
        Array(label.utf8) + (try lp(credentialType)) + (try lp(issuer))
    }

    private static func lp(_ field: String) throws -> [UInt8] {
        let bytes = Array(field.utf8)
        guard !bytes.isEmpty else { throw PrivateSeedError.emptyField }
        guard bytes.count <= maxFieldBytes else { throw PrivateSeedError.fieldTooLong }
        return [UInt8(bytes.count >> 8), UInt8(bytes.count & 0xFF)] + bytes
    }

    /// `SHA256(private_seed)`: the value the issuer receives in the credential request.
    func psc(credentialType: String, issuer: String) throws -> [UInt8] {
        var seed = try derive(credentialType: credentialType, issuer: issuer)
        defer { SecretBytes.wipe(&seed) }
        return NymPseudonym.sha256(seed)
    }

    /// Whether `psc` is the commitment this wallet derives for the type at the issuer. Fail-closed:
    /// anything but an exact 32-byte match is false, and a wallet that gets false must not use the seed.
    func matchesCommitment(credentialType: String, issuer: String, psc candidate: [UInt8]) throws -> Bool {
        SecretBytes.constantTimeEqual(try psc(credentialType: credentialType, issuer: issuer), candidate)
    }

    /// The 16-byte seed. Internal on purpose: callers get `psc` and the check, never the seed.
    func derive(credentialType: String, issuer: String) throws -> [UInt8] {
        try root.deriveSecret(info: try Self.info(credentialType: credentialType, issuer: issuer), length: Self.seedBytes)
    }
}

/// Helpers for secret byte strings.
enum SecretBytes {
    /// Best-effort zeroing of a secret held in an array.
    static func wipe(_ bytes: inout [UInt8]) {
        for index in bytes.indices { bytes[index] = 0 }
    }

    /// Equality that does not stop at the first differing byte; false for different lengths.
    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for index in a.indices { difference |= a[index] ^ b[index] }
        return difference == 0
    }
}
