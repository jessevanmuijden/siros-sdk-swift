// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

extension SirosWallet {
    /// The issuance trust gate (fail closed), run on `flow_complete` before
    /// ANYTHING is stored, superseded, captured or synced. See
    /// `issuanceTrustRefusal` for the policy.
    ///
    /// - Returns: true when the completion has been dealt with and the caller
    ///   must stop (the issuance was refused, or the session ended while the
    ///   trust check was awaiting the network); false to carry on and store.
    func issuanceTrustGateHandled(_ msg: FlowCompleteMessage, offer: CredentialOffer?, epoch tag: Int?) async -> Bool {
        let credentials = msg.credentials ?? []
        // A completion that would store credentials, carries a negative report or
        // carries issuance metadata (a refresh token, the issuer, the configuration)
        // must be able to prove which issuance it belongs to. Without a start tag it
        // cannot (cannot compare => refuse): it is dropped, nothing stored or captured.
        let epoch: Int
        if let tag {
            epoch = tag
        } else if !credentials.isEmpty || msg.issuerTrust?.trusted == false || Self.carriesIssuanceMetadata(msg) {
            #if canImport(os)
            logger.error("Flow \(msg.flowId, privacy: .public) completed with no start tag; its issuance cannot be established, dropping it")
            #endif
            return true
        } else {
            lock.lock(); epoch = issuanceEpoch; lock.unlock()
        }
        lock.lock(); let generation = sessionGeneration; lock.unlock()
        // Also for a completion with no credentials: an explicit negative engine
        // report refuses regardless of how many credentials came with it, so no
        // refresh token is captured and the flow is not reported complete.
        let refusal = await issuanceTrustRefusal(
            credentials: credentials,
            engineTrust: msg.issuerTrust,
            mdocTrust: { await self.mdocIssuanceTrustResult($0) }
        )
        guard let refusal else {
            return !isStillOwner(generation: generation, epoch: epoch, flowId: msg.flowId)
        }
        await refuseUntrustedIssuance(msg: msg, offer: offer, reason: refusal, generation: generation, epoch: epoch)
        return true
    }

    /// Whether this completion still owns the issuance state: the session did
    /// not end (logout / account replacement) and the issuance was not reset
    /// (cancel, a newer flow) while the trust check awaited the network.
    private func isStillOwner(generation: Int, epoch: Int, flowId: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let owner = sessionGeneration == generation && issuanceEpoch == epoch
        #if canImport(os)
        if !owner {
            logger.warning("Flow \(flowId, privacy: .public) was cancelled or its session ended during its trust check; dropping its completion")
        }
        #endif
        return owner
    }

    /// Decodes an issued `mso_mdoc` credential and evaluates its issuer; nil
    /// if it cannot be verified (unparseable, no x5chain, bad signature, or a
    /// platform without the Security framework).
    func mdocIssuanceTrustResult(_ credential: CredentialResult) async -> TrustResult? {
        if let hook = mdocIssuanceTrustHook { return await hook(credential) }
        guard let raw = credential.credential, let document = CredentialUtils.parseMdocDocument(raw) else {
            #if canImport(os)
            logger.warning("Issued mdoc credential could not be parsed for the issuer trust check")
            #endif
            return nil
        }
        return await verifyAndEvaluateIssuerTrust(document.issuerSigned.issuerAuth, docType: document.docType)
    }

    /// Ends an issuance whose issuer trust was not established: nothing is
    /// stored, no refresh token is captured, nothing is synced, a renewal's old
    /// batch is left untouched, and the issuer is told the wallet did not
    /// accept the credential (OID4VCI `credential_failure`, best effort, a
    /// fixed code and no detail).
    private func refuseUntrustedIssuance(
        msg: FlowCompleteMessage, offer: CredentialOffer?, reason: String, generation: Int, epoch: Int
    ) async {
        // One claim, under the lock a logout / cancel also takes: ownership check,
        // guard release and the state commit are a single step, so a cancelled
        // flow cannot clear a newer flow's guards and a logout cannot be undone
        // by restoring the old user's state. The credentials shown come from the
        // current state; no store read can suspend in between.
        lock.lock()
        guard sessionGeneration == generation, issuanceEpoch == epoch else {
            lock.unlock()
            #if canImport(os)
            logger.warning("Refusal of flow \(msg.flowId, privacy: .public) dropped: its session or issuance was superseded")
            #endif
            return
        }
        resetIssuanceGuardsLocked()
        let newState: WalletState?
        switch _state {
        case .flowActive(let userId, let displayName, _, _, _, let creds):
            newState = .ready(userId: userId, displayName: displayName, credentials: creds)
        default:
            newState = nil
        }
        var continuations: [AsyncStream<WalletState>.Continuation] = []
        if let newState {
            _state = newState
            continuations = Array(stateContinuations.values)
        }
        let notifier = credentialNotifier
        let listener = eventListener
        lock.unlock()
        for c in continuations { if let newState { c.yield(newState) } }

        let issuer = offer?.credentialIssuerIdentifier ?? msg.credentialIssuer ?? msg.issuerTrust?.issuer
        #if canImport(os)
        logger.error("Refusing issuance for flow \(msg.flowId, privacy: .public) from \(issuer ?? "unknown issuer", privacy: .public): \(reason, privacy: .public)")
        #endif
        for notificationId in (msg.credentials ?? []).compactMap({ $0.notificationId }) {
            notifier?.sendCredentialNotification(
                flowId: msg.flowId,
                notificationId: notificationId,
                event: CredentialNotificationEvent.failure,
                eventDescription: "issuer_not_trusted"
            )
        }
        listener?.onIssuerNotTrusted(flowId: msg.flowId, issuer: issuer, reason: reason)
        listener?.onFlowError(flowId: msg.flowId, errorMessage: issuerNotTrustedMessage, redirectUri: msg.redirectUri)
    }

    /// Whether the completion carries anything only an issuance produces, which
    /// `handleFlowComplete` would act on (capture a refresh token, supersede a batch).
    static func carriesIssuanceMetadata(_ msg: FlowCompleteMessage) -> Bool {
        msg.refreshToken != nil || msg.dpopJwk != nil || msg.dpopKeyId != nil
            || msg.credentialIssuer != nil || msg.selectedCredentialConfigurationId != nil
    }

    /// Whether the issuance that took the guard at `epoch` still owns it: a
    /// cancel (or a newer start) since then bumped the epoch, and its suspended
    /// start must unwind instead of sending a flow nobody owns.
    func startStillOwned(_ epoch: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return issuanceEpoch == epoch
    }

    /// The renewal's commit: if the renewal that took the guard at `epoch` still owns
    /// the wallet, publish its fetched offer (if any), record its source batch and send its `flow_start` (`send` receives
    /// the epoch to tag it with), all under `lock`; otherwise do nothing. `send` must
    /// not take the wallet lock.
    /// - Returns: whether the start was sent.
    @discardableResult
    func commitRenewalStart(epoch: Int, batchId: Int64, offer: CredentialOffer? = nil, send: (Int) -> Void) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard issuanceEpoch == epoch else { return false }
        // The display offer is published here, with the batch and the send, never earlier.
        if let offer { activeOffer = offer }
        pendingRenewalSourceBatchId = batchId
        send(issuanceEpoch)
        return true
    }
}
