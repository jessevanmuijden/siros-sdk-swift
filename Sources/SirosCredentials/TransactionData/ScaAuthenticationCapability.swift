// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Answers, BEFORE the user is shown a transaction, "could the key that will
/// sign establish two distinct authentication categories (TS12 section 3.6)?".
///
/// This is a probe, never a source of factors. The factors written into the
/// KB-JWT `amr` are the ones the signing operation itself reports
/// (siros-wscd-manager `signWithFactors`), so they can only describe the sign
/// that produced the signature. An implementation must not prompt the user and
/// must not cache an answer from an earlier operation as if it were this one's.
public protocol ScaAuthenticationCapability: Sendable {
    /// `false` when the key is unknown, cannot reach two categories, or the
    /// answer cannot be obtained (fail closed).
    func canEstablishTwoCategories(keyId: String?) async -> Bool
}

/// The default: a wallet whose keystore cannot report authentication factors
/// cannot satisfy SCA, so every transaction is refused up front.
public struct NoScaAuthentication: ScaAuthenticationCapability {
    public init() {}
    public func canEstablishTwoCategories(keyId: String?) async -> Bool { false }
}
