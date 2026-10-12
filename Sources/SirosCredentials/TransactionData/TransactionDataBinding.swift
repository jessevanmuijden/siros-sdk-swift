// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One authentication factor applied for an operation, in TS12 vocabulary
/// (TS12 v1.0.1 section 3.6).
public struct AuthenticationFactor: Sendable, Equatable {
    public enum Category: String, Sendable, CaseIterable {
        case knowledge, possession, inherence
    }

    /// The method values TS12 defines per category (section 3.6).
    public static let methods: [Category: Set<String>] = [
        .knowledge: ["pin_less_than_6_digits", "pin_6_or_more_digits", "passphrase_less_than_8_chars",
                     "passphrase_8_to_11_chars", "passphrase_12_or_more_chars", "pattern", "other"],
        .possession: ["key_in_remote_wscd", "key_in_local_external_wscd", "key_in_local_internal_wscd",
                      "key_in_local_native_wscd", "other"],
        .inherence: ["fingerprint_device", "fingerprint_external", "face_device", "face_external", "other"],
    ]

    public let category: Category
    public let method: String

    public init(_ category: Category, _ method: String) {
        self.category = category
        self.method = method
    }

    /// Whether `method` is a value TS12 defines for this category.
    public var isDefined: Bool { Self.methods[category]?.contains(method) ?? false }
}

/// Everything the keystore needs to add the EC TS12 claims to one SD-JWT VC
/// KB-JWT (TS12 v1.0.1 section 3.6). Built from a validated request; the
/// keystore never sees, parses or re-serialises the transaction itself.
public struct TransactionDataBinding: Sendable, Equatable {
    /// The `transaction_data` strings exactly as the verifier sent them,
    /// verifier order, restricted to this credential's entries.
    public let rawEntries: [String]
    /// The chosen hash algorithm (`sha-256`, `sha-384` or `sha-512`).
    public let hashAlgorithm: String
    /// The OID4VP `response_mode` of the request.
    public let responseMode: String
    /// Factors applied for THIS operation.
    public let factors: [AuthenticationFactor]

    /// `package` access on purpose: a binding signs its `factors` into the `amr` claim, so only the SDK's own pipeline (which takes them from a verified provider) may build one; an application cannot mint an SCA claim by constructing it.
    package init(rawEntries: [String], hashAlgorithm: String, responseMode: String, factors: [AuthenticationFactor]) {
        self.rawEntries = rawEntries
        self.hashAlgorithm = hashAlgorithm
        self.responseMode = responseMode
        self.factors = factors
    }

    /// The KB-JWT claims TS12 adds. Throws rather than produce a claim set a
    /// verifier would have to reject: unsupported algorithm, no entries,
    /// fewer than two distinct factor categories, or a factor method TS12
    /// does not define.
    ///
    /// - Parameter jti: a fresh, cryptographically random value; defaults to a
    ///   new random UUID. A parameter only so tests can pin it.
    public func kbJwtClaims(jti: String = UUID().uuidString.lowercased()) throws -> [String: Any] {
        guard !rawEntries.isEmpty else { throw TransactionDataError(.invalidEntry, detail: "no transaction_data entries to bind") }
        var hashes: [String] = []
        for raw in rawEntries {
            guard let h = TransactionDataHashing.hash(raw: raw, algorithm: hashAlgorithm) else {
                throw TransactionDataError(.unsupportedHashAlgorithm, detail: hashAlgorithm)
            }
            hashes.append(h)
        }
        guard factors.allSatisfy(\.isDefined) else {
            throw TransactionDataError(.insufficientAuthenticationFactors, detail: "factor method outside the TS12 vocabulary")
        }
        guard Set(factors.map(\.category)).count >= 2 else {
            throw TransactionDataError(.insufficientAuthenticationFactors, detail: "fewer than two distinct factor categories")
        }
        return [
            "transaction_data_hashes": hashes,
            // A string: the one algorithm used, not the verifier's array.
            "transaction_data_hashes_alg": hashAlgorithm,
            "jti": jti,
            "response_mode": responseMode,
            "amr": factors.map { [$0.category.rawValue: $0.method] },
        ]
    }
}
