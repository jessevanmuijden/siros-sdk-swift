// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// What is known about the key that will sign, used to derive the TS12
/// authentication factors for ONE presentation.
public struct AuthenticationFactorContext: Sendable, Equatable {
    /// Key storage kinds as the WSCD reports them (`software`, `hardware`,
    /// `remote_hsm`, `trusted_execution`).
    public var keyStorage: [String]
    /// The WSCD plugin that holds the key (`softkey`, `r2ps`, `fido2`), when known.
    public var pluginId: String?
    public var keyId: String?

    public init(keyStorage: [String] = [], pluginId: String? = nil, keyId: String? = nil) {
        self.keyStorage = keyStorage
        self.pluginId = pluginId
        self.keyId = keyId
    }
}

/// Supplies the authentication factors applied for the presentation about to
/// be signed (TS12 section 3.6 `amr`).
///
/// Interim contract (step 3 of the rollout moves this into the WSCD manager,
/// siros-wscd-manager#101/#102): an implementation must report only factors
/// it can justify FOR THIS OPERATION. A cached authentication from an earlier
/// operation does not count.
public protocol AuthenticationFactorsProvider: Sendable {
    func factors(for context: AuthenticationFactorContext) async throws -> [AuthenticationFactor]

    /// A cheap, side-effect-free answer to "could two distinct categories be
    /// established for this key?", asked BEFORE the user is shown the
    /// transaction so a hopeless request is refused up front instead of after
    /// they confirmed. Must not prompt the user. The default asks `factors`;
    /// a provider that only produces factors by running a verification as part
    /// of the operation overrides it.
    func canEstablishTwoCategories(for context: AuthenticationFactorContext) async -> Bool
}

public extension AuthenticationFactorsProvider {
    func canEstablishTwoCategories(for context: AuthenticationFactorContext) async -> Bool {
        guard let factors = try? await factors(for: context) else { return false }
        return Set(factors.map(\.category)).count >= 2
    }
}

/// The default provider: conservative, and deliberately unable to satisfy SCA
/// on its own.
///
/// It derives only the possession factor, from where the key lives:
/// `remote_hsm` (or the `r2ps` plugin) is `key_in_remote_wscd`; the `fido2`
/// plugin is `key_in_local_external_wscd`; a software key yields none.
/// `hardware` / `trusted_execution` without a plugin id is ambiguous between a
/// platform keystore and an external token, so no possession claim is made.
///
/// Knowledge and inherence factors are never inferred. The WSCD reports the
/// authentication of the PREVIOUS operation only (`amr` is read before
/// signing), and the platform does not say what will gate this one, so with
/// this provider alone fewer than two categories are established and SCA
/// presentations are refused (`insufficientAuthenticationFactors`). A host app
/// that performs a verification for this very operation (or a later WSCD
/// manager that reports it) supplies `verifiedThisOperation` AND says, without
/// side effects, whether it can (`canVerifyAnotherCategory`): the pre-consent
/// probe uses only that, so the verification itself runs once, after consent.
public struct InterimAuthenticationFactorsProvider: AuthenticationFactorsProvider {
    public typealias Verified = @Sendable (AuthenticationFactorContext) async -> [AuthenticationFactor]

    public typealias Capability = @Sendable (AuthenticationFactorContext) async -> Bool

    private let verifiedThisOperation: Verified
    private let canVerifyAnotherCategory: Capability

    /// - Parameters:
    ///   - verifiedThisOperation: runs the host's verification for THIS operation
    ///     (it may prompt the user); called only after consent.
    ///   - canVerifyAnotherCategory: side-effect-free "can the host verify a
    ///     category beyond possession?" used by the pre-consent probe.
    public init(
        verifiedThisOperation: @escaping Verified = { _ in [] },
        canVerifyAnotherCategory: @escaping Capability = { _ in false }
    ) {
        self.verifiedThisOperation = verifiedThisOperation
        self.canVerifyAnotherCategory = canVerifyAnotherCategory
    }

    /// Possession from the key, plus whatever the host says it can verify; never runs the verification.
    public func canEstablishTwoCategories(for context: AuthenticationFactorContext) async -> Bool {
        guard Self.possession(for: context) != nil else { return false }
        return await canVerifyAnotherCategory(context)
    }

    public func factors(for context: AuthenticationFactorContext) async throws -> [AuthenticationFactor] {
        var result: [AuthenticationFactor] = []
        if let possession = Self.possession(for: context) { result.append(possession) }
        for factor in await verifiedThisOperation(context) where !result.contains(factor) {
            result.append(factor)
        }
        return result
    }

    static func possession(for context: AuthenticationFactorContext) -> AuthenticationFactor? {
        switch context.pluginId {
        case "r2ps": return AuthenticationFactor(.possession, "key_in_remote_wscd")
        case "fido2": return AuthenticationFactor(.possession, "key_in_local_external_wscd")
        case "softkey": return nil
        default: break
        }
        if context.keyStorage.contains("remote_hsm") { return AuthenticationFactor(.possession, "key_in_remote_wscd") }
        return nil
    }
}
