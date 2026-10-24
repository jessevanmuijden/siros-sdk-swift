// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport
import SirosKeystore
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

/// A randomly-generated uint32-range identifier, matching wallet-frontend's
/// `credentialId: number` (privatedata-spec §6) - not a UUID. Cross-client
/// interop (the same encrypted container read by either client) requires
/// this to be a genuine JSON number on the wire, not a string.
///
/// Uses `SystemRandomNumberGenerator` (a CSPRNG on every platform this
/// package targets) rather than `SecRandomCopyBytes`, which is Apple-only -
/// this file has no `#if canImport(CryptoKit)` gate of its own.
func randomUint32Id() -> Int64 {
    var rng = SystemRandomNumberGenerator()
    let value = Int64(UInt32.random(in: 0...UInt32.max, using: &rng))
    return value == 0 ? 1 : value
}

// OID4VCI §10 credential lifecycle notification handling for the wallet facade.
extension SirosWallet {
    /// Handle a `flow_complete` message: persist the issued credentials and,
    /// for each credential that carries a `notification_id`, ask the backend to
    /// forward a `credential_accepted` notification to the issuer.
    ///
    /// The notification send is a no-op if the engine session has been torn down
    /// concurrently (e.g. logout): `WalletEngineSession.sendCredentialNotification`
    /// drops the message when not connected, so a queued `flow_complete` cannot
    /// crash the app. The backend authenticates the notification using ephemeral
    /// issuance state and never stores credential data.
    func handleFlowComplete(msg: FlowCompleteMessage) async {
        // A flow that already failed or was cancelled is not revived by a late completion (its key is gone, so the plain
        // path below would otherwise accept it as a successful plain issuance).
        if flowAlreadyEnded(msg.flowId) { return }
        // Whether this wallet offered a response-encryption key for the flow, read before the flow's state is dropped.
        lock.lock(); let offeredKey = offeredResponseKeyFlows.contains(msg.flowId); lock.unlock()
        if offeredKey, msg.credentialResponseEncrypted != true {
            // The engine says the issuer answered in the clear although the wallet's key was offered: the engine holds
            // the credentials, which engine-blind issuance forbids. Nothing is stored; the issuer is told.
            await refusePlainCompletion(flowId: msg.flowId, notificationIds: (msg.credentials ?? []).compactMap(\.notificationId))
            return
        }
        // Taken before `cancelTransactionTasks`, which also drops the flow's response-encryption key.
        let decryptedResponses = takeDecryptedCredentialResponses(flowId: msg.flowId)
        cancelTransactionTasks(flowId: msg.flowId)
        lock.lock(); legacyFlowSnapshots.removeValue(forKey: msg.flowId); lock.unlock()
        lock.lock()
        let offer = activeOffer
        let vctm = activeVctm
        // The document too, not just the parse: the `vct#integrity` check needs
        // the exact bytes, and taking it here - with everything else this
        // completion is about - keeps that check on the flow that produced
        // these credentials rather than on whatever ambient issuance state
        // happens to be current by the time each credential is stored.
        let vctmDocument = activeVctmDocument
        let attestedKeyIds = activeAttestedKeyIds
        // THIS flow's epoch: the one in force when its flow_start was sent, carried by
        // the session until completion (`FlowCompleteMessage.startTag`), not the
        // current one: a flow cancelled before its first progress, with a newer flow
        // started meanwhile, must not adopt the newer flow's epoch.
        let epochAtStart = msg.startTag
        // A completed flow has no further sign_presentation coming - drop
        // its cached DCQL match results (if any; a no-op for an issuance
        // flow, which never populates this map) so it doesn't linger
        // forever, mirroring Kotlin's identical
        // `pendingMatchResultsByFlow.remove(msg.flowId)` here.
        pendingMatchResultsByFlow.removeValue(forKey: msg.flowId)
        lock.unlock()

        var credentialsToStore = msg.credentials
        if msg.credentialResponseEncrypted == true {
            // Engine-blind issuance: the engine never held the credentials. Entry i of the engine's
            // list is the i-th credential this wallet decrypted; a count mismatch is not guessed at.
            guard let entries = msg.credentials,
                  let paired = Self.pairEncryptedCredentials(entries: entries, decrypted: decryptedResponses) else {
                await rejectDecryptedCompletion(
                    flowId: msg.flowId, responses: decryptedResponses,
                    message: "The credentials the issuer sent do not match what the engine reported"
                )
                return
            }
            credentialsToStore = paired
        }
        // The issuer trust gate sees the credentials that will be stored: for a
        // wallet-encrypted completion the engine's entries carry no values, so
        // the gate runs on the decrypted ones (same shape as the Kotlin SDK's
        // `fillEncryptedCompletion` before `issuanceTrustRefusal`).
        var gateMsg = msg
        gateMsg.credentials = credentialsToStore

        // Fail closed on issuer trust before anything is stored or superseded.
        if await issuanceTrustGateHandled(gateMsg, offer: offer, epoch: epochAtStart) { return }

        // Shared across every copy in this response so the UI can group them
        // into one card (see StoredCredential.batchId) - ALWAYS assigned,
        // even for a single-credential issuance, matching wallet-frontend's
        // useOID4VCIFlow.ts (batchId = Date.now()) exactly: every issuance
        // response is its own batch of at least one, there is no "no batch"
        // sentinel on either client.
        let batchId = Int64(Date().timeIntervalSince1970 * 1000)

        // A plain (not wallet-encrypted) completion carries each credential's value. One that lacks it is unreadable
        // as a whole: refused before anything is stored or superseded, so a renewal never costs the user the
        // credential it was replacing (and the issuer's other entries are not half-applied).
        if msg.credentialResponseEncrypted != true,
           let entries = msg.credentials, entries.contains(where: { ($0.credential ?? "").isEmpty }) {
            await failIssuanceLocally(flowId: msg.flowId, message: "The issuer's credential did not arrive")
            return
        }

        let (oldBatchId, oldRenewedClaims) = await snapshotRenewalSourceBatch()
        let wasRenewal = oldBatchId != nil

        // Tracks whether any credential in this batch actually made it into
        // the store, so a flow that "completes" per the engine but whose
        // only credential(s) failed to parse doesn't get silently reported
        // as success - see storeFailureReason below.
        var storedCount = 0
        var storeFailureReason: String?
        if let credentials = credentialsToStore {
            for (index, cred) in credentials.enumerated() {
                let outcome = await storeIssuedCredential(
                    cred, index: index, flowId: msg.flowId, offer: offer, vctm: vctm,
                    vctmDocument: vctmDocument,
                    attestedKeyIds: attestedKeyIds, batchId: batchId
                )
                if outcome.stored { storedCount += 1 }
                if let reason = outcome.failureReason { storeFailureReason = reason }
            }
        }

        // Only now that the new batch is confirmed stored is it safe to
        // delete the one it supersedes - deleting it any earlier (e.g.
        // right after snapshotting, before knowing whether the renewal's
        // credential(s) actually parsed/validated) would destroy the user's
        // only copy on a failed renewal. See snapshotRenewalSourceBatch's
        // doc comment.
        if storedCount > 0, let oldBatchId {
            await deleteRenewalSourceBatch(oldBatchId)
        }

        // A refresh token belongs to a batch that exists: with nothing stored there is no batch to attach it to.
        if storedCount > 0 { await captureRefreshTokenIfPresent(msg: msg, offer: offer, batchId: batchId) }
        await notifyRenewalAttributeDiffIfNeeded(wasRenewal: wasRenewal, oldClaims: oldRenewedClaims, batchId: batchId)

        // Terminal path for this issuance - see `resetIssuanceGuards()`.
        // Also clears `pendingRenewalSourceBatchId` (see its own clearing in
        // `resetIssuanceGuards()`), whether this renewal attempt succeeded
        // or failed - either way the attempt is over.
        // Only for a completion that belongs to an issuance (it carries the start tag the
        // trust gate just validated). A presentation's completion is untagged and says
        // nothing about an issuance in flight beside it: resetting here would clear that
        // issuance's guards and invalidate its own tag.
        if msg.startTag != nil { resetIssuanceGuards() }

        await persistAndSyncKeystore()

        // The engine considers this flow successfully finished, but if it
        // delivered credentials and none of them survived parsing/validation,
        // reporting onFlowComplete here would silently strand the user - the
        // flow "succeeds" with nothing to show for it and no indication
        // anything went wrong. Surface it as a flow error instead so the
        // UI's error handling fires, matching how any other flow failure is
        // handled.
        let expectedCredentials = credentialsToStore?.count ?? 0
        lock.lock(); let listener = eventListener; lock.unlock()
        if expectedCredentials > 0 && storedCount == 0 {
            listener?.onFlowError(flowId: msg.flowId, errorMessage: storeFailureReason ?? "Credential could not be processed", redirectUri: nil)
        } else {
            listener?.onFlowComplete(flowId: msg.flowId, redirectUri: msg.redirectUri)
        }

        await restoreReadyState()
    }

    /// A completion that should have been wallet-encrypted but was not: refused, nothing stored, `credential_failure`
    /// for each notification id the entries carry, and the issuance ended locally.
    func refusePlainCompletion(flowId: String, notificationIds: [String]) async {
        // The notification awaits a transport send, during which this issuance may be cancelled and another begun: the
        // cleanup runs only if THIS flow still owns the state (checked under the wallet lock, where it also ends the flow).
        let generation = credentialResponseGeneration(flowId: flowId)
        for id in Set(notificationIds).sorted() where !id.isEmpty {
            await sendCredentialFailure(flowId: flowId, notificationId: id)
        }
        await failIssuanceLocally(flowId: flowId, message: "The issuer's response was not encrypted to this wallet", ifGeneration: generation)
    }

    /// Back to `.ready` (with the stored credentials) from an issuance that has ended.
    ///
    /// - Parameter ownedBy: the flow, its generation and the issuance attempt this restore belongs to. After the awaited
    ///   store read they are revalidated, and the state is replaced, under the SAME lock acquisition: a logout that
    ///   published `.disconnected`, a cancellation, or a replacement issuance that started meanwhile (without cancelling
    ///   this one) is never overwritten with the previous issuance's `.ready`.
    func restoreReadyState(ownedBy owner: (flowId: String, generation: [Int], attempt: Int)? = nil) async {
        lock.lock()
        let restorable: Bool
        switch _state {
        case .flowActive, .ready: restorable = true
        default: restorable = false
        }
        lock.unlock()
        guard restorable else { return }
        let creds = await credentialStore.getAll()
        lock.lock()
        if let owner,
           credentialResponseGenerationLocked(flowId: owner.flowId) != owner.generation || !issuanceStartEpoch.isCurrent(owner.attempt) {
            lock.unlock()
            return
        }
        let restored: WalletState
        switch _state {
        case .flowActive(let userId, let displayName, _, _, _, _), .ready(let userId, let displayName, _, _):
            restored = .ready(userId: userId, displayName: displayName, credentials: creds)
        default:
            lock.unlock()
            return
        }
        _state = restored
        let conts = Array(stateContinuations.values)
        lock.unlock()
        for c in conts { c.yield(restored) }
    }

    // Credential re-issuance/renewal plan (Phase 2): if this flow_complete is
    // a renewal's, peek at (but do NOT yet delete) the batch it's about to
    // supersede - just note its id and snapshot its claims (for the
    // attribute diff once the new batch is stored). Deleting it is
    // `deleteRenewalSourceBatch`'s job, and MUST only happen once the new
    // batch has actually been stored successfully (see handleFlowComplete):
    // deleting it here, unconditionally, would mean a renewal whose returned
    // credential(s) all fail to parse/validate destroys the user's only copy
    // of the credential instead of leaving it in place - a real data-loss
    // bug a Copilot review caught on this exact function.
    private func snapshotRenewalSourceBatch() async -> (oldBatchId: Int64?, oldClaims: [DisplayClaim]?) {
        lock.lock(); let renewalSourceBatchId = pendingRenewalSourceBatchId; lock.unlock()
        guard let oldBatchId = renewalSourceBatchId else { return (nil, nil) }
        let existing = await credentialStore.getAll()
        let oldRenewedClaims = existing
            .first(where: { $0.batchId == oldBatchId && $0.instanceId == 0 })
            .map { CredentialUtils.extractClaims($0) }
        return (oldBatchId, oldRenewedClaims)
    }

    // Delete `oldBatchId`'s credential entries AND its privatedata
    // refresh_token entry (per privatedata-spec §6.2 - a stale entry
    // pointing at a no-longer-existing batch must not linger) now that the
    // batch that supersedes it is confirmed stored - see
    // `snapshotRenewalSourceBatch`'s doc comment for why this must not run
    // any earlier.
    /// The credential type this flow was authorised to receive, or nil if the
    /// wallet never resolved one.
    ///
    /// This is the type whose metadata was fetched, whose WSCD requirement was
    /// applied, and which the issuer's registration was checked against. The
    /// credential configuration ID is deliberately NOT a fallback: it is an
    /// OID4VCI-internal identifier, not a credential type, so comparing a `vct`
    /// against it would fail every time and refuse legitimate issuance.
    func authorisedCredentialType(format: String) -> String? {
        if format == "mso_mdoc" {
            // The offer first: it is what the entitlement check in
            // resolveIssuerMetadata was run against, and unlike the resolved
            // schema it is present even when metadata resolution failed. Taking
            // only the schema would make this check a no-op in exactly the
            // situation where the wallet knows least about the credential.
            return activeOffer?.doctype ?? activeMddlSchema?.doctype
        }
        return activeOffer?.vct ?? activeVctm?.vct
    }

    /// Refuse a credential whose declared type is not the one this flow was
    /// authorised to receive.
    ///
    /// Every earlier decision in the issuance path — the issuer's entitlement
    /// under ARF section 6.6.2.3, which type metadata to apply, which WSCD to
    /// use — was made about the type the issuer *advertised*. None of them
    /// looked at what actually arrived. Without this, an issuer entitled to one
    /// attestation type could deliver another and have every one of those
    /// decisions stand, made about the wrong credential.
    ///
    /// Returns a failure reason, or nil when the credential is acceptable. A
    /// type that could not be determined on either side is not a mismatch: as
    /// everywhere else in this path, a check that could not run must not become
    /// a refusal.
    /// - Parameter declaredType: the type the caller has already read off the
    ///   credential, when it has one. Both storage paths parse the credential
    ///   before reaching here, so passing it avoids a second parse - and, more
    ///   to the point, compares the same parse that was validated rather than a
    ///   fresh one that might not agree with it.
    func verifyIssuedType(format: String, raw: String, declaredType: String? = nil) -> String? {
        guard let authorised = authorisedCredentialType(format: format),
              let declared = declaredType ?? CredentialUtils.declaredType(format: format, raw: raw),
              declared != authorised else {
            return nil
        }
        return "Issuer delivered a '\(declared)' credential, but this offer was for '\(authorised)'"
    }

    /// Refuse a credential whose issuer pinned its type metadata to something
    /// the wallet cannot find.
    ///
    /// SD-JWT VC Type Metadata lets the credential carry `vct#integrity`, a
    /// digest over the type metadata document. It exists so the *issuer*
    /// decides what a credential type means. Without checking it, whoever
    /// serves the registry decides how the credential is displayed and which
    /// claims it is understood to carry — independently of the issuer who
    /// vouched for it, and even for a type the issuer is legitimately
    /// registered to issue.
    ///
    /// The pin is an input to resolution, not a verdict on its output. When the
    /// document the wallet holds disagrees with it, that is ordinary rather
    /// than hostile: the document may have been cached before the issuer
    /// changed it, or come from a source serving a different copy. So resolve
    /// again, directed by the pin this time, and let the credential through if
    /// the issuer's own document can still be found anywhere. Only a wallet
    /// that cannot find it at all refuses — the security property is unchanged,
    /// because a document that does not hash to the pin is never accepted.
    ///
    /// Only checked when the credential asks for it: a credential with no
    /// `vct#integrity` is making no claim about its metadata, so there is
    /// nothing to disagree with.
    ///
    /// - Returns: the refusal reason, or nil to accept; and the document a
    ///   re-resolution settled on, when one happened. The refreshed document is
    ///   handed back rather than written into `activeVctm`/`activeVctmDocument`
    ///   on the way past: this function awaits the network, and
    ///   `resetIssuanceGuards()` - which a cancel or a logout calls - may clear
    ///   those fields and let a new issuance populate them in the meantime. A
    ///   write here would then be the *old* flow overwriting the new flow's
    ///   metadata. The caller applies it to the one credential it is storing,
    ///   which is the only thing it was ever about.
    func verifyVctIntegrity(
        format: String,
        payload: [String: Any],
        offer: CredentialOffer?,
        document: VctmDocument?
    ) async -> (reason: String?, refreshed: VctmDocument?) {
        guard format != "mso_mdoc",
              let expected = payload["vct#integrity"] as? String else {
            return (nil, nil)
        }

        if let document,
           let raw = document.raw.data(using: String.Encoding.utf8),
           Integrity.matches(raw, expected) {
            return (nil, nil)
        }

        var rediscovered: VctmDocument?
        if let offer {
            rediscovered = await vctmFetcher.fetchDocument(
                issuerUrl: offer.credentialIssuerIdentifier,
                scope: offer.credentialConfigurationId,
                vct: offer.vct,
                registryUrl: resolvedRegistryUrl,
                expectedIntegrity: expected
            )
        }

        if let rediscovered {
            #if canImport(os)
            logger.info("Type metadata re-resolved to the document the issuer pinned")
            #endif
            return (nil, rediscovered)
        }

        if document == nil {
            // Nothing was applied, so nothing was tampered with - but say so,
            // because a credential asking to be checked and not being checked
            // is exactly the state this method exists to make visible.
            #if canImport(os)
            logger.warning("Credential pinned vct#integrity but no type metadata could be resolved to check it against")
            #endif
            return (nil, nil)
        }

        return ("The issuer's type metadata does not match what it published", nil)
    }

    private func deleteRenewalSourceBatch(_ oldBatchId: Int64) async {
        let existing = await credentialStore.getAll()
        for cred in existing where cred.batchId == oldBatchId {
            await credentialStore.delete(cred.id)
            await removeBbsHolderStateIfAny(credentialId: cred.id)
        }
        await removeCredentialRefreshToken(batchId: oldBatchId)
    }

    // Not `private`: the type-metadata tests drive it directly, because the
    // behaviour that matters - which document the stored credential is
    // described by - is only observable in what it saves.
    func storeIssuedCredential(
        _ cred: CredentialResult,
        index: Int,
        flowId: String,
        offer: CredentialOffer?,
        vctm: Vctm?,
        vctmDocument: VctmDocument?,
        attestedKeyIds: [String]?,
        batchId: Int64
    ) async -> (stored: Bool, failureReason: String?) {
        // A container this build must not rewrite is read-only. Storing would be
        // silently discarded (`CredentialStore.save` does not throw), and the
        // issuer would then be told the credential was accepted.
        if let refusal = keystore.unsupportedSchemaVersion {
            return (false, refusal.localizedDescription)
        }
        guard let rawCredential = cred.credential else {
            return (false, "The issuer's credential did not arrive")
        }
        if cred.format == "mso_mdoc" {
            // mso_mdoc credentials are base64url-encoded CBOR (a
            // DeviceResponse-shaped envelope, per wallet-frontend#191), never
            // JWT-shaped - the parseJwtPayload-based validation/expiry/
            // metadata path below doesn't apply and would always fail,
            // silently dropping every issued mdoc credential.
            guard let mdocDocument = CredentialUtils.parseMdocDocument(rawCredential) else {
                return (false, "Received credential could not be read")
            }
            if let reason = verifyIssuedType(
                format: cred.format,
                raw: rawCredential,
                declaredType: mdocDocument.docType
            ) {
                return (false, reason)
            }

            // The mdoc's issuer trust (ISO 18013-5 Annex C `issuerAuth`) was
            // decided before anything was stored - see `issuanceTrustGateHandled`.

            var metadata: CredentialMetadata?
            if let off = offer {
                let mddlSchema = await mddlSchemaFetcher.fetch(
                    issuerUrl: off.credentialIssuerIdentifier,
                    scope: off.credentialConfigurationId,
                    doctype: off.doctype,
                    registryUrl: resolvedRegistryUrl
                )
                metadata = CredentialUtils.buildMdocMetadata(offer: off, mddlSchema: mddlSchema)
            }
            let stored = StoredCredential(
                id: randomUint32Id(),
                format: cred.format,
                raw: rawCredential,
                kid: index < (attestedKeyIds?.count ?? 0) ? attestedKeyIds?[index] : nil,
                metadata: metadata,
                notificationId: cred.notificationId,
                credentialIssuerIdentifier: offer?.credentialIssuerIdentifier,
                credentialConfigurationId: offer?.credentialConfigurationId,
                batchId: batchId,
                instanceId: index
            )
            await credentialStore.save(stored)
            notifyCredentialAccepted(cred, flowId: flowId, stored: stored)
            return (true, nil)
        }

        guard let payload = CredentialUtils.parseJwtPayload(rawCredential) else {
            return (false, "Received credential could not be read")
        }
        let exp = payload["exp"] as? Int64
        let now = Int64(Date().timeIntervalSince1970)
        if let exp, exp < now {
            return (false, "Issued credential was already expired")
        }

        if let reason = verifyIssuedType(
            format: cred.format,
            raw: rawCredential,
            declaredType: payload["vct"] as? String
        ) {
            return (false, reason)
        }
        let integrity = await verifyVctIntegrity(
            format: cred.format, payload: payload, offer: offer, document: vctmDocument
        )
        if let reason = integrity.reason {
            return (false, reason)
        }

        // `verifyVctIntegrity` may have re-resolved the type metadata against
        // this credential's own `vct#integrity`. The `vctm` snapshot taken
        // before it ran then describes the document the issuer did NOT sign
        // over, and persisting its display and claim metadata would store the
        // very thing the pin exists to prevent - accepted, but described by the
        // wrong document. Scoped to this credential rather than read back from
        // shared issuance state, which a cancelled or superseded flow may have
        // replaced while the re-resolution was in flight.
        let effectiveVctm = integrity.refreshed?.vctm ?? vctm
        let metadata = offer.flatMap {
            CredentialUtils.buildMetadata(offer: $0, vctm: effectiveVctm, rawCredential: rawCredential)
        }

        let stored = StoredCredential(
            id: randomUint32Id(),
            format: cred.format,
            raw: rawCredential,
            kid: index < (attestedKeyIds?.count ?? 0) ? attestedKeyIds?[index] : nil,
            metadata: metadata,
            issuedAt: payload["iat"] as? Int64,
            expiresAt: exp,
            notificationId: cred.notificationId,
            credentialIssuerIdentifier: offer?.credentialIssuerIdentifier,
            credentialConfigurationId: offer?.credentialConfigurationId,
            batchId: batchId,
            instanceId: index
        )
        await credentialStore.save(stored)

        // OID4VCI §10: confirm acceptance to the issuer (via the backend)
        // while the issuance access token is still valid. The backend
        // forwards using ephemeral flow state; nothing is stored there.
        notifyCredentialAccepted(cred, flowId: flowId, stored: stored)
        return (true, nil)
    }

    private func notifyCredentialAccepted(_ cred: CredentialResult, flowId: String, stored: StoredCredential) {
        if let notificationId = cred.notificationId {
            lock.lock(); let notifier = credentialNotifier; lock.unlock()
            notifier?.sendCredentialNotification(
                flowId: flowId,
                notificationId: notificationId,
                event: CredentialNotificationEvent.accepted
            )
        }

        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onCredentialReceived(credential: stored)
    }

    // Credential re-issuance/renewal plan (Phase 2): durably capture this
    // batch's refresh_token + DPoP key in privatedata
    // (S.credentialRefreshTokens - see setCredentialRefreshToken's doc
    // comment) so renewCredential() can use it later, including after an app
    // restart or on a different device sharing this account.
    //
    // `offer` (activeOffer) is best-effort display metadata - on a renewal
    // it's rebuilt by re-fetching issuer metadata (see renewCredential's doc
    // comment) and is left nil if that fetch fails. Falling back to
    // `msg.credentialIssuer`/`msg.selectedCredentialConfigurationId` (which
    // the engine always sends alongside `refreshToken`) means a flaky
    // metadata fetch doesn't also silently break the next renewal by never
    // storing its refresh_token at all.
    private func captureRefreshTokenIfPresent(msg: FlowCompleteMessage, offer: CredentialOffer?, batchId: Int64) async {
        guard let token = msg.refreshToken else { return }
        guard let issuerIdentifier = offer?.credentialIssuerIdentifier ?? msg.credentialIssuer,
              let configId = offer?.credentialConfigurationId ?? msg.selectedCredentialConfigurationId else { return }
        await setCredentialRefreshToken(
            batchId: batchId,
            entry: CredentialRefreshTokenEntry(
                refreshToken: token,
                dpopJwk: msg.dpopJwk,
                credentialIssuerIdentifier: issuerIdentifier,
                credentialConfigurationId: configId,
                dpopKeyId: msg.dpopKeyId
            )
        )
    }

    // AttributeDiffService-equivalent (ISSU_59): if this was a renewal,
    // compare the new batch's claims against the old one's - a silent
    // renewal only stays silent when nothing actually changed. See
    // onCredentialRenewedWithAttributeDiff's doc comment for why this fires
    // in addition to (not instead of) onCredentialReceived.
    private func notifyRenewalAttributeDiffIfNeeded(wasRenewal: Bool, oldClaims: [DisplayClaim]?, batchId: Int64) async {
        guard wasRenewal, let oldClaims else { return }
        let allNow = await credentialStore.getAll()
        guard let newRepresentative = allNow.first(where: { $0.batchId == batchId && $0.instanceId == 0 }) else { return }
        let diff = CredentialUtils.computeAttributeDiff(before: oldClaims, after: CredentialUtils.extractClaims(newRepresentative))
        guard diff.hasChanges else { return }
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onCredentialRenewedWithAttributeDiff(credential: newRepresentative, diff: diff)
    }
}
