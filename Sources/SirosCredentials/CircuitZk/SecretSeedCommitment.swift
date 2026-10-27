// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@preconcurrency import SwiftCBOR
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The `nym_auth` commitment `ssc = SHA256(secret_seed)` and how to read it from an
/// issuer-signed credential (privatedata-spec section 5A).
///
/// Every read is strict and fails closed: a value that is absent, duplicated, of the wrong type
/// or of the wrong length is nil, never a best guess. Nothing here logs or returns a seed.
public enum SecretSeedCommitment {
    /// `secret_seed` length in bytes (rulebook).
    public static let seedBytes = 16
    /// `ssc` length in bytes: a SHA-256 digest.
    public static let commitmentBytes = 32

    /// Whether `SHA256(seed) == ssc`, compared in constant time. False for any wrong length.
    public static func opens(seed: [UInt8], ssc: [UInt8]) -> Bool {
        guard seed.count == seedBytes, ssc.count == commitmentBytes else { return false }
        var digest = NymPseudonym.sha256(seed)
        defer { SecretBytes.wipe(&digest) }
        return SecretBytes.constantTimeEqual(digest, ssc)
    }

    /// The 32-byte `ssc` of an mdoc `document`: its value in the credential's OWN doctype
    /// namespace, or nil when the namespace or element is absent, occurs more than once there,
    /// is not a byte string, or is not 32 bytes. The same element in another namespace is never consulted.
    public static func ssc(of document: DocumentMdoc) -> [UInt8]? {
        let matches = (document.issuerSigned.nameSpaces[document.docType] ?? []).filter { $0.item.elementIdentifier == "ssc" }
        guard matches.count == 1, case .byteString(let value) = matches[0].item.elementValue,
              value.count == commitmentBytes else { return nil }
        return value
    }

    /// The `ssc` of a stored mdoc credential (the stored raw form), or nil when unreadable.
    public static func sscOfMdoc(raw: String) -> [UInt8]? {
        CredentialUtils.parseMdocDocument(raw).flatMap { ssc(of: $0) }
    }

    /// The `ssc` of a compact SD-JWT VC: its one top-level `ssc` disclosure, as 64 lowercase hex
    /// characters. Nil when there is no such disclosure, more than one, the claim is also present
    /// in the clear, the disclosure is not referenced from the signed payload's top-level `_sd`
    /// (a same-named claim in a nested object is ignored), `_sd_alg` is present and not `sha-256`,
    /// or the value is not 64 lowercase hex characters.
    public static func sscOfSdJwt(_ credential: String) -> [UInt8]? {
        let parts = credential.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        guard let jwt = parts.first else { return nil }
        let jwtParts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard jwtParts.count > 1, let payloadData = base64UrlDecode(String(jwtParts[1])),
              // StrictJSON, not JSONSerialization: a payload with a repeated member (two `_sd`, two `_sd_alg`) is
              // ambiguous and a lenient parser would silently keep one of them, making the binding parser-dependent.
              let payload = (try? StrictJSON.parse(payloadData))?.objectValue,
              payload["ssc"] == nil else { return nil }
        // Disclosure digests are SHA-256 here: a payload declaring any other `_sd_alg` is not bound under that
        // hash, so it fails closed (an absent `_sd_alg` is the SHA-256 default).
        if let algorithm = payload["_sd_alg"] {
            guard algorithm.stringValue == "sha-256" else { return nil }
        }
        let digests = Set(payload["_sd"]?.arrayValue?.compactMap { $0.stringValue } ?? [])
        var found: [(segment: String, value: String)] = []
        for segment in parts.dropFirst() where !segment.isEmpty {
            guard let data = base64UrlDecode(segment),
                  let array = (try? JSONSerialization.jsonObject(with: data)) as? [Any], array.count == 3,
                  let name = array[1] as? String, name == "ssc",
                  // Only a disclosure the signed payload's TOP-LEVEL `_sd` references is the top-level claim; a same-named
                  // claim inside a nested object's `_sd` is a different claim and is ignored.
                  digests.contains(disclosureDigest(segment)) else { continue }
            guard let value = array[2] as? String else { return nil }
            found.append((segment, value))
        }
        guard found.count == 1, let only = found.first else { return nil }
        guard isLowerHex(only.value, count: 2 * commitmentBytes) else { return nil }
        return bytes(fromLowerHex: only.value)
    }

    // MARK: -

    /// The SD-JWT disclosure digest: base64url (no padding) of SHA-256 over the ASCII disclosure segment.
    static func disclosureDigest(_ segment: String) -> String {
        base64UrlEncode(Data(SHA256.hash(data: Data(segment.utf8))))
    }

    private static func isLowerHex(_ text: String, count: Int) -> Bool {
        let utf8 = Array(text.utf8)
        return utf8.count == count && utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }

    private static func bytes(fromLowerHex hex: String) -> [UInt8] {
        let utf8 = Array(hex.utf8)
        func nibble(_ c: UInt8) -> UInt8 { c <= 0x39 ? c - 0x30 : c - 0x61 + 10 }
        return stride(from: 0, to: utf8.count, by: 2).map { (nibble(utf8[$0]) << 4) | nibble(utf8[$0 + 1]) }
    }

    private static func base64UrlDecode(_ text: String) -> Data? {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard !text.contains("=") else { return nil }
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)
    }

    private static func base64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
