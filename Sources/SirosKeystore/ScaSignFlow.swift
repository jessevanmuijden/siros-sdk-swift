// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// What one WSCD sign reported about the authentication it applied
/// (the manager's `FfiSignOutcome`, without the FFI types).
struct ScaSignReport {
    var signature: Data
    var factors: [AuthenticationFactor]
    var satisfiesTwoCategories: Bool
    var shortfall: String?
}

/// The EC TS12 SCA sign sequence, independent of the FFI so it can be tested
/// without the native library.
///
/// The `amr` is inside the signed KB-JWT, but the factors are only known once
/// the user has authenticated. So the flow (1) takes the PIN from the user, (2)
/// derives the factors that sign WILL apply (possession from the plugin, the
/// knowledge class MEASURED from that PIN), (3) builds the payload with them,
/// (4) signs with the same PIN handed back to the plugin exactly once and a
/// fresh-authentication requirement, and (5) accepts the result only if the
/// sign itself reported exactly those factors. A mismatch discards the
/// signature: the claim in the token and the authentication that was applied
/// can never differ.
enum ScaSignFlow {
    /// The plugins whose fresh PIN authentication the manager honours for a
    /// flagged sign (R2PS OPAQUE, FIDO2 on a raw transport), with the
    /// possession method each one reports.
    static func possessionMethod(pluginId: String?) -> String? {
        switch pluginId {
        case "r2ps": return "key_in_remote_wscd"
        case "fido2": return "key_in_local_external_wscd"
        default: return nil
        }
    }

    /// The TS12 knowledge method for a typed secret, measured the way the
    /// manager measures it (`classify_secret`): all ASCII digits is a PIN,
    /// anything else a passphrase, classed by character count. `nil` for an
    /// empty or non-UTF-8 secret (the class is then unknown and not guessed).
    static func classifySecret(_ secret: Data) -> String? {
        // Foundation's decoder drops a leading U+FEFF, which the manager's (Rust) decoding keeps and
        // counts: validate with Foundation, then decode natively so both measure the same scalars.
        guard String(data: secret, encoding: .utf8) != nil else { return nil }
        let s = String(decoding: secret, as: UTF8.self)
        let n = s.unicodeScalars.count
        guard n > 0 else { return nil }
        if s.unicodeScalars.allSatisfy({ $0.value >= 0x30 && $0.value <= 0x39 }) {
            return n < 6 ? "pin_less_than_6_digits" : "pin_6_or_more_digits"
        }
        if n < 8 { return "passphrase_less_than_8_chars" }
        return n < 12 ? "passphrase_8_to_11_chars" : "passphrase_12_or_more_chars"
    }

    private static func refuse(_ detail: String) -> TransactionDataError {
        TransactionDataError(.insufficientAuthenticationFactors, detail: detail)
    }

    /// - Parameters:
    ///   - promptPin: asks the user for the PIN for THIS sign.
    ///   - payload: builds the bytes to sign from the factors that will apply.
    ///   - sign: signs `data` with a fresh user authentication, handing the
    ///     plugin `pin` the first time it asks for one; returns what the sign reported.
    static func run(
        pluginId: String?,
        capability: SignerFactorCapability,
        promptPin: () throws -> Data,
        payload: ([AuthenticationFactor]) throws -> Data,
        sign: (_ data: Data, _ pin: Data) throws -> ScaSignReport
    ) throws -> SignerScaOutcome {
        guard capability.canReachTwoCategories else {
            throw refuse(capability.reason ?? "the key cannot reach two authentication categories")
        }
        guard let possession = possessionMethod(pluginId: pluginId) else {
            throw refuse("the key's WSCD plugin does not support a fresh PIN authentication")
        }
        let pin = try promptPin()
        guard let knowledge = classifySecret(pin) else {
            throw refuse("the class of the secret entered for this sign could not be established")
        }
        let expected = [AuthenticationFactor(.possession, possession), AuthenticationFactor(.knowledge, knowledge)]
        let data = try payload(expected)
        let report = try sign(data, pin)
        // The sign's own report is authoritative, and must be exactly what the payload claims.
        guard report.satisfiesTwoCategories, Set(report.factors.map(\.category)).count >= 2 else {
            throw refuse(report.shortfall ?? "the sign did not apply two authentication categories")
        }
        guard report.factors.count == expected.count, report.factors.allSatisfy({ expected.contains($0) }) else {
            throw refuse("the authentication applied by the sign differs from the factors claimed in the payload")
        }
        return SignerScaOutcome(signature: report.signature, signedData: data, factors: report.factors)
    }
}
