// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

// Credential eligibility (consumption policy, presentation history, live key
// availability). Moved out of `SirosWallet.swift` unchanged to keep that file
// under the lint file-length limit.
extension SirosWallet {
    /// Filters `instances` down to the ones this wallet's own
    /// `credentialConsumptionPolicy` and `presentationHistory` currently
    /// consider eligible (i.e. not yet consumed), AND whose bound signing
    /// key still actually exists in `keystore` - the same computation this
    /// class performs internally before every presentation, exposed as a
    /// convenience so consent/selection UI doesn't need to thread policy,
    /// history, and live key availability through
    /// `CredentialUtils.eligibleInstances` itself.
    ///
    /// The key-availability half of this check exists because a real,
    /// recurring bug (found via live proximity-presentation testing) let a
    /// credential whose signing key was silently lost (e.g. a sync that
    /// never folded a software key into the persisted container - see
    /// privatedata-spec#1/siros-wscd-manager#68 for the deeper architectural
    /// fix) keep reporting "available" under
    /// `CredentialConsumptionPolicy.neverConsume` forever, right up until a
    /// live presentation attempt failed deep inside key selection with no
    /// user-facing signal at all.
    ///
    /// - Parameter isZkPresentation: Per-candidate: will THIS presentation be
    ///   a ZK proof? Callers that know the matched query's format (the DC API
    ///   and engine paths) pass it so `CredentialConsumptionPolicy.consumeNonZkp`
    ///   can tell ZK from raw; the default falls back to the stored format,
    ///   which is never ZK - see `CredentialUtils.eligibleInstances`.
    public func eligibleInstances(
        from instances: [StoredCredential],
        isZkPresentation: ((StoredCredential) -> Bool)? = nil
    ) -> [StoredCredential] {
        let eligible = policyEligibleInstances(from: instances, isZkPresentation: isZkPresentation)
        // A container this build must not rewrite is read-only: a consumption would
        // be recorded in memory only, and reopening would make the used instance
        // eligible again (a one-time-use credential presented twice). So an
        // instance whose presentation would be consumed is not offered.
        guard keystore.unsupportedSchemaVersion != nil else { return eligible }
        switch credentialConsumptionPolicy {
        case .neverConsume: return eligible
        case .consumeAll: return []
        case .consumeNonZkp: return eligible.filter { isZkPresentation?($0) ?? false }
        }
    }

    private func policyEligibleInstances(
        from instances: [StoredCredential],
        isZkPresentation: ((StoredCredential) -> Bool)?
    ) -> [StoredCredential] {
        let keyIds = availableKeyIds
        if let isZkPresentation {
            return CredentialUtils.eligibleInstances(
                instances: instances,
                policy: credentialConsumptionPolicy,
                presentationHistory: presentationHistory,
                availableKeyIds: keyIds,
                isZkPresentation: isZkPresentation
            )
        }
        return CredentialUtils.eligibleInstances(
            instances: instances,
            policy: credentialConsumptionPolicy,
            presentationHistory: presentationHistory,
            availableKeyIds: keyIds
        )
    }

    /// The `kid`s this wallet's keystore can currently sign with - exposed so
    /// consent/selection UI (e.g. a consent screen's exhausted-query
    /// precheck) can compute eligibility ahead of time without a full
    /// `eligibleInstances(from:)` round trip per candidate list. Read live
    /// from `keystore.listKeys()` on every access, never cached: the whole
    /// point of the check is to notice a key that has gone missing.
    public var availableKeyIds: Set<String> {
        Set(keystore.listKeys().map(\.keyId))
    }
}
