// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport
import SirosKeystore
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

/// Credential re-issuance/renewal plan (Phase 2): OID4VCI `refresh_token`-based
/// silent renewal, plus the proactive near-expiry threshold check that
/// triggers it. Split out of `SirosWallet.swift` (already over SwiftLint's
/// file/type-length budget before this plan existed) into its own extension
/// file, matching `SirosWallet+Notifications.swift`'s precedent for
/// extracting a self-contained slice of functionality - `pendingRenewalSourceBatchId`/
/// `renewThresholds` themselves stay declared on `SirosWallet` proper, since
/// Swift extensions can't add stored properties to a type.
extension SirosWallet {
    /// Every credential batch's durable OID4VCI renewal candidate
    /// (`S.credentialRefreshTokens` - privatedata-spec §6.2), unlike
    /// `wscdCredentials` this applies regardless of which concrete
    /// `KeystoreManager` backs `keystore` - both the default `JweKeystore`
    /// and `WscdKeystoreAdapter` (which internally delegates to its own
    /// `JweKeystore` for credential/privatedata storage, separately from
    /// whatever WSCD backs key signing) expose it.
    func exportCredentialRefreshTokens() async -> [Int64: CredentialRefreshTokenEntry] {
        #if canImport(CryptoKit)
        if let jwe = keystore as? JweKeystore {
            return await jwe.exportCredentialRefreshTokens()
        }
        if let adapter = keystore as? WscdKeystoreAdapter {
            return await adapter.exportCredentialRefreshTokens()
        }
        #endif
        return [:]
    }

    func setCredentialRefreshToken(batchId: Int64, entry: CredentialRefreshTokenEntry) async {
        #if canImport(CryptoKit)
        if let jwe = keystore as? JweKeystore {
            await jwe.setCredentialRefreshToken(batchId: batchId, entry: entry)
        }
        if let adapter = keystore as? WscdKeystoreAdapter {
            await adapter.setCredentialRefreshToken(batchId: batchId, entry: entry)
        }
        #endif
    }

    func removeCredentialRefreshToken(batchId: Int64) async {
        #if canImport(CryptoKit)
        if let jwe = keystore as? JweKeystore {
            await jwe.removeCredentialRefreshToken(batchId: batchId)
        }
        if let adapter = keystore as? WscdKeystoreAdapter {
            await adapter.removeCredentialRefreshToken(batchId: batchId)
        }
        #endif
    }

    /// Per-credential-configuration-id override for
    /// `CredentialUtils.renewThreshold` - see `renewThresholds`' own doc
    /// comment on `SirosWallet` proper.
    private func renewThresholdFor(_ credentialConfigurationId: String?) -> Int {
        guard let credentialConfigurationId else { return CredentialUtils.renewThreshold }
        return renewThresholds[credentialConfigurationId] ?? CredentialUtils.renewThreshold
    }

    /// After `consumedCredentialIds` were just presented (see
    /// `recordPresentation`), check whether any of their batches dropped to
    /// or below its renew threshold and fire
    /// `WalletEventListener.onCredentialNearExpiry` if so - the
    /// proactive-renewal trigger (plan §4.3).
    // Not `private`: `SirosWallet.swift`'s `recordPresentation` (a separate
    // file, same module) calls this - same cross-file-extension-access
    // reason as `keystore` etc.
    func checkRenewThresholds(consumedCredentialIds: [Int64]) async {
        let allCredentials = await credentialStore.getAll()
        var affectedBatchIds: [Int64] = []
        for id in consumedCredentialIds {
            if let batchId = allCredentials.first(where: { $0.id == id })?.batchId, !affectedBatchIds.contains(batchId) {
                affectedBatchIds.append(batchId)
            }
        }
        for batchId in affectedBatchIds {
            let batchInstances = allCredentials.filter { $0.batchId == batchId }
            guard let representative = batchInstances.first(where: { $0.instanceId == 0 }) ?? batchInstances.first else { continue }
            let threshold = renewThresholdFor(representative.credentialConfigurationId)
            let eligible = eligibleInstances(from: batchInstances)
            if eligible.count <= threshold {
                lock.lock(); let listener = eventListener; lock.unlock()
                listener?.onCredentialNearExpiry(credential: representative, eligibleRemaining: eligible.count, threshold: threshold)
            }
        }
    }

    /// Renew a credential batch via OID4VCI's `refresh_token` grant
    /// (credential re-issuance/renewal plan, Phase 2), using the
    /// refresh_token/DPoP key durably captured for it in `privatedata`
    /// (`S.credentialRefreshTokens` - see `exportCredentialRefreshTokens`)
    /// at the time it (or its most recent prior renewal) was issued.
    ///
    /// Throws `SirosError.renewalUnavailable` if no renewal candidate is
    /// stored for `batchId` - either it was never captured (the issuer
    /// didn't return a refresh_token), or it's already been
    /// consumed/superseded. `reissuanceKid` is left unset for now - the
    /// server-side same-wallet-unit continuity mechanism (re-signing
    /// `generate_proof` with the original credential's key) is tracked
    /// separately and not yet wired into this call site.
    ///
    /// A renewal's `flow_complete` is handled by the exact same code path as
    /// a fresh issuance's, which reads display metadata (logo/issuer
    /// name/friendly credential name) off `activeOffer` - but a renewal
    /// never parses a fresh credential_offer, so `activeOffer` would
    /// otherwise be left nil/stale from whatever the *previous* flow reset
    /// it to. Re-fetch and rebuild it here from the stored issuer/config id
    /// so the renewed card displays correctly rather than falling back to
    /// raw wire values (e.g. the bare "mso_mdoc" format string instead of
    /// "mDL").
    public func renewCredential(batchId: Int64) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        // A renewal is issuance-shaped (it ends up at the same
        // `flow_complete` path and mutates the same `activeOffer`/
        // `pendingRenewalSourceBatchId` shared state) so it must
        // participate in the same overlap guard as
        // `startIssuance`/`startIssuanceByOffer`, or a concurrent renewal
        // + fresh issuance could corrupt each other's shared state.
        lock.lock()
        if issuanceInFlight {
            lock.unlock()
            throw SirosError.wallet(message: "Another issuance is already in progress")
        }
        issuanceInFlight = true
        let startEpoch = issuanceEpoch // see startIssuanceByOffer
        lock.unlock()
        do {
            let candidates = await exportCredentialRefreshTokens()
            guard let candidate = candidates[batchId] else {
                throw SirosError.renewalUnavailable(batchId: batchId)
            }
            #if canImport(os)
            logger.debug("Starting renewal for batch=\(batchId) issuer=\(candidate.credentialIssuerIdentifier)")
            #endif
            // Staged locally and published only inside the epoch-checked commit below: a
            // renewal cancelled while this fetch was suspended must not overwrite the
            // `activeOffer` of an issuance that started meanwhile.
            var stagedOffer: CredentialOffer?
            do {
                let metadata = try await fetchIssuerMetadata(issuerUrl: candidate.credentialIssuerIdentifier)
                stagedOffer = Self.buildCredentialOffer(
                    issuerUrl: candidate.credentialIssuerIdentifier,
                    configId: candidate.credentialConfigurationId,
                    metadata: metadata
                )
            } catch {
                #if canImport(os)
                logger.warning("Failed to refresh issuer metadata for renewal display; card will show raw format: \(error.localizedDescription)")
                #endif
            }
            // Ownership check, offer and source-batch publication and send are ONE critical section
            // (like `dispatchIssuanceStart`): a cancel plus a newer renewal cannot land
            // between them, so this one can neither overwrite the newer renewal's source
            // batch nor send its cancelled start.
            commitRenewalStart(epoch: startEpoch, batchId: batchId, offer: stagedOffer) {
                engine.startRenewal(
                    refreshToken: candidate.refreshToken,
                    credentialIssuer: candidate.credentialIssuerIdentifier,
                    selectedCredentialConfigurationId: candidate.credentialConfigurationId,
                    dpopJwk: candidate.dpopJwk,
                    dpopKeyId: candidate.dpopKeyId,
                    startTag: $0
                )
            }
        } catch {
            // Same rationale as `startIssuance`'s catch block: a synchronous
            // failure here (e.g. no refresh_token on file for this batch)
            // means no flow was ever registered server-side, so nothing
            // will clear the guard via the normal flow_complete/flow_error
            // path - without this, every future issuance/renewal attempt
            // would be permanently blocked.
            resetIssuanceGuards()
            throw error
        }
    }
}
