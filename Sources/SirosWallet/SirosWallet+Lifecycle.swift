// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosTransport
import SirosAuth
import SirosKeystore
import SirosFlow

#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

extension SirosWallet {
    /// Force a fresh engine WebSocket connection before starting a new flow,
    /// rather than trusting a connection that may have gone idle since the
    /// last one - mirrors `completeAuthorization`'s existing zombie-connection
    /// handling. A connection left open across a backend restart or any other
    /// silent network drop can look connected while actually discarding every
    /// send, and that failure mode isn't unique to the post-OAuth-redirect gap.
    // Not `private`: `SirosWallet+Renewal.swift`'s `renewCredential` needs
    // it too - same cross-file-extension-access reason as `keystore` above.
    func ensureEngineConnected(_ engine: WalletEngineSession) async throws {
        guard let tokens = authTokens else {
            throw SirosError.wallet(message: "Not connected")
        }
        let token = try await tokens.ensureBackendToken()
        engine.forceReconnect(appToken: token.raw)
        try await engine.awaitConnected()
    }

    /// Clear the ambient issuance-in-progress guard fields, unconditionally.
    ///
    /// Every terminal path for an issuance attempt must call this - a
    /// `flow_complete`/`flow_error` from the engine, a client-side
    /// termination (e.g. `reportSignFailure`), a synchronous start failure,
    /// or the user cancelling before the engine ever assigned a flow ID at
    /// all (see `cancelCurrentFlow`'s doc comment for why that last case is
    /// real, not just defensive). Not `private`, for the same
    /// cross-file-extension-access reason as `activeOffer` etc.
    func resetIssuanceGuards() {
        lock.lock()
        resetIssuanceGuardsLocked()
        lock.unlock()
    }

    /// `resetIssuanceGuards()` for a caller that already holds `lock` (the
    /// start's failure path and `cancelCurrentFlow` reset the guards and the
    /// state in one critical section). Also bumps `issuanceEpoch`: whatever
    /// completion was already underway for the state being cleared no longer owns
    /// it (see `issuanceTrustGateHandled`).
    func resetIssuanceGuardsLocked() {
        issuanceEpoch &+= 1
        activeOffer = nil
        activeVctm = nil
        activeVctmDocument = nil
        activeMddlSchema = nil
        activeAttestedKeyIds = nil
        issuanceInFlight = false
        // A failed/cancelled renewal must not leave this pointing at a
        // batch that a later, unrelated flow_complete would then be
        // misinterpreted as superseding (see `renewCredential`'s doc
        // comment and `SirosWallet+Notifications.swift`'s
        // `supersedeRenewalSourceBatchIfNeeded`) - every terminal path
        // (success or error) routes through here, same as `activeOffer`
        // etc. above.
        pendingRenewalSourceBatchId = nil
    }

    /// Cancel the current flow.
    ///
    /// `resetIssuanceGuards()` is called unconditionally, not just inside the
    /// `.flowActive` branch - a slow/unresponsive issuer leaves the wallet in
    /// `.ready` the whole time `startIssuance`/`startIssuanceByOffer` is
    /// awaiting the engine's first progress message, since the engine
    /// doesn't assign (and report) a flow ID until then. Gating the local
    /// guard reset on `.flowActive` too meant cancelling during exactly that
    /// window did nothing at all - not even a local reset - permanently
    /// stranding `issuanceInFlight` at `true` and blocking every subsequent
    /// issuance attempt until the app process was killed (real bug hit
    /// against a slow Geneva interop test issuer). The backend `cancelFlow`
    /// send stays gated on `.flowActive`, since only then does a real
    /// `flowId` exist to send to the server - the local guard reset does
    /// not need one, and is a no-op if no issuance was ever in flight, so
    /// it's always safe to call unconditionally.
    ///
    /// A start still suspended in network work (see
    /// ``WalletState/isPendingFlow``) is invalidated first, so it unwinds at its
    /// next step with `CancellationError` instead of sending the engine a flow
    /// that was cancelled. A pending state has no engine flow yet, so nothing
    /// is sent to the engine for it.
    ///
    /// Not covered: a cancel after `flow_start` went out but before the engine
    /// named a flow. The engine's first event for that flow is not recognised
    /// as abandoned (the Kotlin SDK tracks this with per-connection
    /// generations in its engine session, which this SDK does not have yet).
    public func cancelCurrentFlow() {
        // One critical section with the start's admission, advances and
        // failure cleanup (`SirosWallet+IssuanceStart.swift`): invalidating the
        // epoch, resetting the state and clearing the guards cannot interleave
        // with any of them.
        lock.lock()
        issuanceStartEpoch.invalidate()
        var reset: WalletState?
        var cancelFlowId: String?
        if case .flowActive(let userId, let displayName, let flowId, _, _, let creds) = _state {
            if !_state.isPendingFlow { cancelFlowId = flowId }
            reset = .ready(userId: userId, displayName: displayName, credentials: creds)
        }
        if let reset { _state = reset }
        let conts = reset == nil ? [] : Array(stateContinuations.values)
        let engine = engineSession
        let peer = wmpPeer
        // Only the issuance being cancelled holds response keys; a flow that ends for other reasons drops
        // its own state per flow id, and an unrelated presentation ending must not touch it.
        credentialResponseKeys.removeAll()
        decryptedCredentialResponses.removeAll()
        credentialResponseEpoch += 1
        // The requests the engine session has received so far belong to what was just cancelled, even before any
        // progress named a flow (the wallet may still be `.ready`): they are refused when handled.
        engine?.invalidateBufferedRequests()
        resetIssuanceGuardsLocked()
        lock.unlock()
        if let cancelFlowId {
            try? engine?.cancelFlow(flowId: cancelFlowId)
            // The flow is over for this wallet: marked ended, so a request for it still buffered on the legacy
            // WebSocket is refused instead of recreating its key.
            cancelTransactionTasks(flowId: cancelFlowId)
        }
        // On WMP the parents and their sign/match children live in the peer, and the wallet state need not say a flow
        // is active (nothing sets it there): everything the peer is running for flows stops here, before this
        // returns, whatever the state was.
        peer?.cancelAllFlowsNow()
        if let reset { for c in conts { c.yield(reset) } }
    }

    // MARK: - Identity Verification

    /// Perform identity verification via a plugin provider and automatically start
    /// credential issuance with the resulting offer.
    ///
    /// This is the primary integration point for IDV flows (FaceTec, iProov, etc.).
    /// The provider handles all capture UI and backend communication; this method
    /// bridges the IDV result into the standard OID4VCI issuance flow.
    ///
    /// - Parameters:
    ///   - provider: An ``IdentityVerificationProvider`` implementation.
    ///   - presentingViewController: The UIViewController to present the IDV UI from.
    /// - Throws: ``IDVError`` if verification fails, or ``SirosError`` if issuance fails.
    public func verifyIdentityAndIssue(
        provider: IdentityVerificationProvider,
        presentingViewController: Any
    ) async throws {
        guard await provider.isAvailable() else {
            throw IDVError.unavailable(reason: "\(provider.name) is not available on this device")
        }
        let result = try await provider.startVerification(
            presentingViewController: presentingViewController
        )
        try await startIssuance(offerUri: result.credentialOfferURI)
    }

    /// Complete an OAuth authorization flow.
    ///
    /// If a pending authorization context was captured from this flow's
    /// `authorization_required` progress message, resumes issuance via a
    /// brand-new `flow_start` (not a `flow_action` on the original flow_id,
    /// which isn't guaranteed to survive the OAuth browser round-trip) -
    /// mirrors the wallet-backend's `resumeWithAuthCode` contract already
    /// used by the web client. The engine WebSocket is force-reconnected
    /// first in case it silently went stale ("zombie") during the redirect.
    /// Falls back to the legacy `flow_action`-based completion if no pending
    /// context was captured (e.g. an older backend that doesn't send it).
    public func completeAuthorization(flowId: String, code: String, state: String) {
        lock.lock()
        let engine = engineSession
        // Peek, don't remove yet - removing before the state check below
        // meant a mismatched (e.g. attacker-forged) callback destroyed the
        // real, still-pending context, so any later legitimate completion
        // attempt for the same flowId fell through to the no-context branch,
        // which sends the flow action straight through with no CSRF check
        // at all. Only remove once the check actually passes.
        let pending = pendingAuthorizations[flowId]
        let tokens = authTokens
        let listener = eventListener
        lock.unlock()

        guard let engine else { return }

        guard let pending else {
            engine.sendFlowAction(
                flowId: flowId,
                action: "authorization_complete",
                payload: ["code": .string(code), "state": .string(state)]
            )
            return
        }

        guard pending.state == state else {
            listener?.onFlowError(flowId: flowId, errorMessage: "Authorization state mismatch", redirectUri: nil)
            return
        }

        lock.lock(); pendingAuthorizations.removeValue(forKey: flowId); lock.unlock()

        // The resume continues THIS flow's issuance: refuse it unless that issuance
        // can be identified and still owns the wallet (not cancelled, not superseded).
        guard let startEpoch = pending.startEpoch else {
            listener?.onFlowError(
                flowId: flowId,
                errorMessage: "Failed to resume issuance: the authorization cannot be tied to the issuance that started it",
                redirectUri: nil
            )
            return
        }
        guard startStillOwned(startEpoch) else { return }

        Task {
            do {
                try await resumeAuthorization(
                    engine: engine, pending: pending, code: code, startEpoch: startEpoch, tokens: tokens
                )
            } catch {
                lock.lock(); let listener = eventListener; lock.unlock()
                listener?.onFlowError(
                    flowId: flowId,
                    errorMessage: "Failed to resume issuance: \(error.localizedDescription)",
                    redirectUri: nil
                )
            }
        }
    }

    /// The asynchronous half of `completeAuthorization`: reconnect the engine, then
    /// resume the originating issuance with a fresh `flow_start`.
    ///
    /// Its tag and its ownership check use `startEpoch`, the epoch the ORIGINATING
    /// issuance started under (`PendingAuthorization.startEpoch`), never a fresh
    /// sample: the token and connection awaits can outlast a cancel and a newer start,
    /// and then this resume belongs to nobody and is not sent.
    func resumeAuthorization(
        engine: WalletEngineSession,
        pending: PendingAuthorization,
        code: String,
        startEpoch: Int,
        tokens: AuthTokens?
    ) async throws {
        let token: String
        if let tokenHook = authorizationResumeTokenHook {
            token = try await tokenHook()
        } else {
            guard let tokens else {
                throw SirosError.wallet(message: "Not connected")
            }
            token = try await tokens.ensureBackendToken().raw
        }
        // BEFORE the reconnect: forceReconnect closes whatever socket is current, which
        // after a cancel and a newer start is the NEWER issuance's. A resume that no
        // longer owns the wallet must not touch it.
        guard startStillOwned(startEpoch) else { return }
        if let connect = authorizationResumeConnectHook {
            try await connect(engine)
        } else {
            engine.forceReconnect(appToken: token)
            try await engine.awaitConnected()
        }
        // Client attestation for the resumed flow: Execute() sets up
        // h.attestationProvider identically whether msg.AuthCode is
        // set or not (it runs before that branch), so the engine
        // sends its `request_attestation` sign request on resume
        // exactly as on a fresh start - and the token request (which
        // only ever happens via this resume path for redirect-based
        // authorization_code issuers; a real geneva2026.mdoc.online
        // run once showed "No OAuth Client Attestations were
        // provided" when resume skipped it) gets the headers from
        // `handleSignRequest`'s answer. Nothing to pre-resolve here.
        guard startStillOwned(startEpoch) else { return }
        if let send = authorizationResumeSendHook {
            send(startEpoch)
            return
        }
        engine.resumeIssuance(
            offer: pending.offer,
            credentialOfferUri: pending.credentialOfferUri,
            redirectUri: pending.redirectUri,
            authCode: code,
            codeVerifier: pending.codeVerifier,
            startTag: startEpoch
        )
    }

    /// Release all resources. Instance must not be reused after this.
    public func destroy() {
        lock.lock()
        blindSessionEnded = true
        let engine = engineSession
        let peer = wmpPeer
        wmpPeer = nil
        engineSession = nil
        credentialNotifier = nil
        apiClient = nil
        lock.unlock()
        engine?.disconnect()
        // The WMP session goes too, and its child-flow handlers stop before their state is cleared.
        peer?.shutdownProfiles()
        if let peer { Task { try? await peer.close() } }
        cancelEngineTasks()
        clearBlindIssuanceState()
        keystore.lock()
        resetDefaultTransactionLogStore()
        // Same reason as logout()'s: a self-driven re-login still awaiting the
        // old session's teardown must not log back in after the host has torn
        // this wallet down. The flag is what stops a *later* signal - the
        // state is deliberately left as it was (a destroyed wallet is not a
        // logged-out one), so it would otherwise still look replaceable.
        lock.lock(); isDestroyed = true; lock.unlock()
        bumpSessionGeneration()
    }

    /// Roll back a locally-stored credential after a failed registration.
    /// Prevents orphaned passkeys from appearing in the login picker.
    // Not `private`: called from `SirosWallet.swift`'s own
    // `startIssuanceByOffer`/`startIssuance` (this function now lives in
    // `SirosWallet+Lifecycle.swift`) - same cross-file-extension-access
    // reason as `keystore` above.
    func rollbackLocalCredential() {
        if let local = authProvider as? LocalAuthProvider {
            local.rollbackLastRegistration()
        }
    }

    // MARK: - Private helpers

    func setState(_ newState: WalletState) {
        lock.lock()
        _state = newState
        let conts = Array(stateContinuations.values)
        lock.unlock()
        for c in conts { c.yield(newState) }
    }

    private func setupApiClient(session: AuthSession) {
        let client = BackendApiClient(
            baseUrl: config.backendUrl,
            tenantId: config.tenantId,
            httpFn: Self.defaultHttpFn
        )
        client.setAppToken(session.appToken)
        lock.lock(); apiClient = client; lock.unlock()
    }

    // Not `private`: called from `SirosWallet.swift`'s `login`/`register`/
    // `resumeSession` (this function now lives in
    // `SirosWallet+Lifecycle.swift`) - same cross-file-extension-access
    // reason as `keystore` above.
    func setupApiClientWithTokens(_ tokens: AuthTokens) {
        let client = BackendApiClient(
            baseUrl: config.backendUrl,
            tenantId: config.tenantId,
            httpFn: Self.defaultHttpFn
        )
        client.setAuthTokens(tokens)
        lock.lock(); apiClient = client; lock.unlock()
    }

    private func saveSession(session: AuthSession, credentialId: Data, prfSalt: Data, hkdfSalt: Data, hkdfInfo: Data) {
        sessionStore.appToken = session.appToken
        sessionStore.refreshToken = session.refreshToken
        sessionStore.userId = session.uuid
        sessionStore.displayName = session.displayName
        sessionStore.tenantId = config.tenantId
        sessionStore.credentialId = Self.b64UrlEncode(credentialId)
        sessionStore.prfSalt = Self.b64Encode(prfSalt)
        sessionStore.hkdfSalt = Self.b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = Self.b64Encode(hkdfInfo)
    }

    // Not `private`: called from `SirosWallet.swift`'s `unlockKeystore`
    // (this function now lives in `SirosWallet+Lifecycle.swift`) - same
    // cross-file-extension-access reason as `keystore` above.
    /// The encrypted private-data container for this session, or empty when it
    /// could not be fetched - a first login has none yet, and a transient
    /// failure must not take down a login that can still unlock from what the
    /// session store holds.
    ///
    /// The one failure that is **not** tolerated is a wallet lifecycle refusal
    /// (SID-AUTH-06): this is the first wallet-API call a login makes, so a
    /// suspended instance or a deactivated wallet is usually met right here.
    /// Swallowed, it became an empty container and then a keystore-unlock
    /// error, and the wallet never reached `WalletState.lifecycleBlocked` -
    /// nor forgot the account of a wallet that had been deactivated. It is
    /// rethrown so the caller's `handleLifecycleRefusal` can see it.
    func fetchPrivateData() async throws -> Data {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { return Data() }
        do {
            let response = try await client.getPrivateData()
            if let pd = response["privateData"] {
                if let pdDict = pd as? [String: Any], let b64u = pdDict["$b64u"] as? String {
                    let containerBytes = Self.b64UrlDecode(b64u) ?? Data()
                    if !containerBytes.isEmpty {
                        sessionStore.privateDataJwe = String(data: containerBytes, encoding: .utf8)
                    }
                    return containerBytes
                } else if let pdStr = pd as? String {
                    let containerBytes = Data(pdStr.utf8)
                    sessionStore.privateDataJwe = pdStr
                    return containerBytes
                }
            }
        } catch {
            // See this function's doc comment: a lifecycle refusal is a state
            // the caller has to enter, not a fetch that came back empty.
            if let sirosError = error as? SirosError, sirosError.walletLifecycleRefusal != nil {
                throw sirosError
            }
            #if canImport(os)
            logger.warning("Could not fetch privateData: \(error.localizedDescription)")
            #endif
        }
        return Data()
    }

    // Not `private`: called from `SirosWallet.swift`'s `register`
    // (this function now lives in `SirosWallet+Lifecycle.swift`) - same
    // cross-file-extension-access reason as `keystore` above.
    func syncPrivateDataToBackend() async throws {
        lock.lock(); let client = apiClient; lock.unlock()
        try await syncPrivateDataToBackend(using: client, containerJson: sessionStore.privateDataJwe)
    }

    /// Syncs through `client`, captured by the caller when its operation STARTED, so a logout and a
    /// new login in between can never make this write through the next account's client.
    func syncPrivateDataToBackend(using client: BackendApiClient?, containerJson: String?) async throws {
        guard let client else { return }
        guard let containerJson else { return }
        do {
            // Parse the JSON string back to a dict and send
            if let data = containerJson.data(using: .utf8),
               let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                _ = try await client.updatePrivateData(dict)
            }
        } catch {
            #if canImport(os)
            logger.error("Failed to sync private data: \(error.localizedDescription)")
            #endif
            lock.lock(); let listener = eventListener; lock.unlock()
            listener?.onFlowError(flowId: "sync", errorMessage: "Private data sync failed: \(error.localizedDescription)", redirectUri: nil)
            // Rethrow: this function is declared `async throws` precisely so
            // callers (`register`, `persistAndSyncKeystore`) can react to a
            // sync failure - swallowing it here made every `try await
            // syncPrivateDataToBackend()` call site's own catch block
            // unreachable for this specific failure, silently treating it
            // as success.
            throw error
        }
    }

    func persistAndSyncKeystore() async {
        guard keystore.isUnlocked else { return }
        do {
            try await exportAndSyncKeystore(generation: currentAccountGeneration())
        } catch {
            #if canImport(os)
            logger.error("Failed to persist keystore: \(error.localizedDescription)")
            #endif
        }
    }

    /// Exports the container and syncs it, one operation at a time. The account scope (generation)
    /// and the API client are captured when the operation STARTS, under the mutex; the account is
    /// revalidated immediately after the awaited export, before anything is assigned or sent, and
    /// the sync goes through the captured client. A logout and re-login during the export therefore
    /// writes nothing into the next session. Residual: the sync's own network call, once started,
    /// cannot be recalled; it carries the old account's container through the old account's client.
    func exportAndSyncKeystore(generation: Int) async throws {
        try await keystorePersistMutex.withLock {
            lock.lock()
            let client = apiClient
            let sameAccount = transactionLogGeneration == generation
            lock.unlock()
            guard sameAccount, keystore.isUnlocked else { throw TransactionLogError("the account changed before the container was exported") }
            let container = try await keystore.exportEncryptedContainer()
            // The check and the assignment are one step under the wallet lock, which a logout's generation
            // bump also takes; and the sync is handed THIS container rather than re-reading the store.
            let json = String(data: container, encoding: .utf8)
            lock.lock()
            let stillSame = transactionLogGeneration == generation && keystore.isUnlocked
            if stillSame { sessionStore.privateDataJwe = json }
            lock.unlock()
            guard stillSame else { throw TransactionLogError("the account changed while the container was being exported") }
            try await syncPrivateDataToBackend(using: client, containerJson: json)
        }
    }

    // Not `private`: called from `SirosWallet.swift`'s `logout` and
    // `SirosWallet+Engine.swift`'s `connectEngine` (this function now lives
    // in `SirosWallet+Lifecycle.swift`) - same cross-file-extension-access
    // reason as `keystore` above.
    func cancelEngineTasks() {
        for t in engineTasks { t.cancel() }
        engineTasks.removeAll()
        lock.lock()
        let consentTasks = transactionTasks.values.map(\.cancel)
        transactionTasks.removeAll()
        transactionTaskEpoch += 1
        flowEndSeq.removeAll()
        legacyFlowSnapshotQueue.removeAll()
        legacyFlowSnapshots.removeAll()
        credentialResponseKeys.removeAll()
        decryptedCredentialResponses.removeAll()
        credentialResponseEpoch += 1
        lock.unlock()
        for cancel in consentTasks { cancel() }
    }

}
