// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Why ``NymPseudonym/derive(config:seed:proverInput:verifierId:verifierContext:)`` refused
/// its arguments. These are API-misuse errors of the derivation itself, NOT the
/// rulebook's "unsatisfiable request" verdicts (a `verifier_context` over 64 bytes, an
/// unobtainable `verifier_id`, ...): those belong to the wallet, and the derivation
/// accepts any length of any input it is given.
public enum NymPseudonymError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The config id is not in the config table.
    case unknownConfig(String)
    /// The config needs an input the caller did not supply.
    case missingInput(config: String, input: String)
    /// The config does not use an input the caller supplied.
    case unusedInput(config: String, input: String)
    /// The seed is not the length the config's seed kind requires.
    case wrongSeedLength(config: String, expected: Int, actual: Int)

    /// The message never contains seed material.
    public var description: String {
        switch self {
        case .unknownConfig(let config): return "Unknown nym_auth config '\(config)'"
        case .missingInput(let config, let input): return "Config '\(config)' needs \(input)"
        case .unusedInput(let config, let input): return "Config '\(config)' does not use \(input)"
        case .wrongSeedLength(let config, let expected, let actual):
            return "Config '\(config)' needs a \(expected)-byte seed, got \(actual) bytes"
        }
    }
}

/// Which of the `nym_auth` attestation's two seeds a config derives from. Both are held by
/// the wallet: the `private_seed` is derived on the device, the `secret_seed` is delivered
/// by the issuer (it is shared with the issuer by design) and checked against `ssc` before
/// every use.
public enum NymSeedKind: Sendable, Equatable {
    /// `secret_seed`, opened from `ssc`; shared with the issuer, delivered to the wallet.
    case secret
    /// `private_seed`, opened from `psc`; derived on the device, never leaves it.
    case `private`

    /// The rulebook's length for both seeds: 16 bytes.
    public var bytes: Int { 16 }
}

/// What a pseudonym config needs from the caller.
public struct NymConfigInfo: Sendable, Equatable {
    public let seedKind: NymSeedKind
    /// The config takes a user-supplied value as `prover_input`.
    public let userValue: Bool
    /// The config uses a `verifier_id`.
    public let verifierId: Bool
    /// The config also uses a `verifier_context`.
    public let verifierContext: Bool
}

/// The rulebook's pseudonym function `pseudonym` (v0.4; `ver` 1, `prf` `sha-256`):
/// `SHA256(DST || seed || prover_input || verifier_input)`, with
/// `DST = "nym_auth/v1/<config>"` (UTF-8) and no separators.
///
/// Pure and stateless: no seed is logged, returned or cached, and nothing here knows about
/// wallet state, trust, matching or storage. `verifier_id` is an opaque, caller-supplied
/// UTF-8 string: it is hashed byte-for-byte, never built, inspected or normalised here.
public enum NymPseudonym {
    enum ProverInput { case none, sha256OfUserValue }
    enum VerifierInput { case none, sha256OfId, sha256OfIdAndContext }

    struct Config {
        let id: String
        let seed: NymSeedKind
        let proverInput: ProverInput
        let verifierInput: VerifierInput
    }

    private static let dstPrefix = "nym_auth/v1/"
    private static let inputBytes = 32

    /// The config table (rulebook v0.3 and v0.4). A new configuration is a new entry; nothing else changes.
    static let configs: [String: Config] = Dictionary(uniqueKeysWithValues: [
        Config(id: "known-offender-matching-ssc", seed: .secret, proverInput: .none, verifierInput: .sha256OfId),
        Config(id: "known-offender-matching-psc", seed: .private, proverInput: .none, verifierInput: .sha256OfId),
        Config(id: "account-recovery-ssc", seed: .secret, proverInput: .none, verifierInput: .sha256OfIdAndContext),
        Config(id: "user-managed-pseudonym-xsite-ssc", seed: .secret, proverInput: .sha256OfUserValue, verifierInput: .none),
    ].map { ($0.id, $0) })

    /// The ids of every known config.
    public static var configIds: Set<String> { Set(configs.keys) }

    /// What `config` needs from the caller, or nil for an unknown config.
    public static func describe(config: String) -> NymConfigInfo? {
        configs[config].map {
            NymConfigInfo(
                seedKind: $0.seed, userValue: $0.proverInput != .none,
                verifierId: $0.verifierInput != .none, verifierContext: $0.verifierInput == .sha256OfIdAndContext)
        }
    }

    /// Derives the 32-byte pseudonym.
    ///
    /// - Parameters:
    ///   - config: A config id from the table, e.g. `known-offender-matching-ssc`.
    ///   - seed: The `secret_seed` or `private_seed` the config uses, at that seed's exact length.
    ///   - proverInput: The user-supplied value, for configs that hash one; otherwise must be nil.
    ///   - verifierId: The opaque `verifier_id`, for configs that use one; otherwise must be nil.
    ///   - verifierContext: The `verifier_context`, for configs that use one; otherwise must be nil.
    ///     Any length is accepted; the rulebook's 1-64 byte limit is the wallet's satisfiability check.
    /// - Throws: ``NymPseudonymError`` on an unknown config, a missing or unused input, or a wrong seed length.
    public static func derive(
        config: String,
        seed: [UInt8],
        proverInput: [UInt8]? = nil,
        verifierId: String? = nil,
        verifierContext: String? = nil
    ) throws -> [UInt8] {
        guard let entry = configs[config] else { throw NymPseudonymError.unknownConfig(config) }
        guard seed.count == entry.seed.bytes else {
            throw NymPseudonymError.wrongSeedLength(config: config, expected: entry.seed.bytes, actual: seed.count)
        }
        try check(config, "prover_input", used: entry.proverInput != .none, supplied: proverInput != nil)
        try check(config, "verifier_id", used: entry.verifierInput != .none, supplied: verifierId != nil)
        try check(config, "verifier_context", used: entry.verifierInput == .sha256OfIdAndContext, supplied: verifierContext != nil)

        let proverBytes: [UInt8]
        switch entry.proverInput {
        case .none: proverBytes = [UInt8](repeating: 0, count: inputBytes)
        case .sha256OfUserValue: proverBytes = sha256(proverInput ?? [])
        }
        let verifierBytes: [UInt8]
        switch entry.verifierInput {
        case .none: verifierBytes = [UInt8](repeating: 0, count: inputBytes)
        case .sha256OfId: verifierBytes = sha256(Array((verifierId ?? "").utf8))
        case .sha256OfIdAndContext:
            verifierBytes = sha256(sha256(Array((verifierId ?? "").utf8)), sha256(Array((verifierContext ?? "").utf8)))
        }
        return sha256(Array((dstPrefix + entry.id).utf8), seed, proverBytes, verifierBytes)
    }

    private static func check(_ config: String, _ name: String, used: Bool, supplied: Bool) throws {
        if used && !supplied { throw NymPseudonymError.missingInput(config: config, input: name) }
        if !used && supplied { throw NymPseudonymError.unusedInput(config: config, input: name) }
    }

    static func sha256(_ parts: [UInt8]...) -> [UInt8] {
        var hasher = SHA256()
        for part in parts { hasher.update(data: part) }
        return Array(hasher.finalize())
    }
}
