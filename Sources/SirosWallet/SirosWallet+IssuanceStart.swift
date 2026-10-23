// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

// Wiring of the pending issuance state (see `IssuancePendingState.swift`) to
// the wallet: the first thing a start call does is publish it, each slow step
// advances it, and a failure or a cancel takes it away again.
extension SirosWallet {
    /// Admission of an issuance start, as ONE critical section under `lock`:
    /// refuse when another issuance is in flight, take the in-flight guard,
    /// allocate this attempt's epoch and publish the synchronous pre-engine
    /// state - the first thing a start call does, before any network work. The
    /// same lock covers every later commit (`advanceIssuanceStart`,
    /// `failIssuanceStart`) and `cancelCurrentFlow`, so a cancel can never fall
    /// between claiming the guard and allocating the epoch, and an epoch can
    /// never be validated and then acted on after it went stale.
    ///
    /// The pending state is only published from `.ready`; from any other state
    /// the start proceeds as before without a visible flow state. Returns this
    /// attempt's epoch. Observers are notified after the lock is released.
    func admitIssuanceStart() throws -> Int {
        lock.lock()
        if issuanceInFlight {
            lock.unlock()
            throw SirosError.wallet(message: "Another issuance is already in progress")
        }
        issuanceInFlight = true
        issuanceStartHook?("admit.afterGuard")
        let epoch = issuanceStartEpoch.begin()
        let pending = _state.beginningIssuanceStart()
        if let pending { _state = pending }
        let observers = pending == nil ? [] : Array(stateContinuations.values)
        lock.unlock()
        if let pending { for c in observers { c.yield(pending) } }
        return epoch
    }

    /// Advance the pre-engine step, and stop a start that was cancelled while
    /// it was suspended: `cancelCurrentFlow()` has already reset the wallet, so
    /// a cancelled start only has to unwind (`CancellationError`) - it must not
    /// touch state again, which by now may belong to a newer attempt.
    ///
    /// The epoch check, the step commit and `commit` (which publishes whatever
    /// the step's work produced, and must not take `lock`) are one critical
    /// section: a cancel cannot slip between the check and the writes, so a
    /// stale start can neither resurrect the spinner nor write into a newer
    /// attempt's fields.
    func advanceIssuanceStart(_ epoch: Int, _ step: String, commit: (() -> Void)? = nil) throws {
        lock.lock()
        guard issuanceStartEpoch.isCurrent(epoch) else {
            lock.unlock()
            throw CancellationError()
        }
        issuanceStartHook?("advance.afterCheck")
        commit?()
        let next = _state.advancingPendingStep(to: step)
        if let next { _state = next }
        let observers = next == nil ? [] : Array(stateContinuations.values)
        lock.unlock()
        if let next { for c in observers { c.yield(next) } }
    }

    /// The engine half of an issuance start, as two visible steps: reconnect
    /// (see `ensureEngineConnected` for why every start reconnects) and wait
    /// for the session. Token refresh, the socket handshake and the server's
    /// session message are all in here and are the first of the silent seconds.
    func connectEngineForIssuance(_ engine: WalletEngineSession, epoch: Int) async throws {
        try advanceIssuanceStart(epoch, WalletState.FlowActive.stepConnectingEngine)
        guard let tokens = authTokens else {
            throw SirosError.wallet(message: "Not connected")
        }
        let token = try await tokens.ensureBackendToken()
        // The socket replacement is part of the epoch-checked commit: a
        // superseded attempt must not close the socket a newer one owns.
        try replaceEngineSocketForIssuance(epoch: epoch) {
            engine.forceReconnect(appToken: token.raw)
        }
        try await engine.awaitConnected()
    }

    /// Replace the engine socket (`reconnect`) as the epoch-checked commit of the
    /// `establishing_session` step: validation and replacement are one critical
    /// section with cancellation and admission, so a stale attempt can never
    /// close a newer attempt's socket. The caller waits for the new connection
    /// (`awaitConnected`) outside the lock.
    func replaceEngineSocketForIssuance(epoch: Int, reconnect: () -> Void) throws {
        try withoutActuallyEscaping(reconnect) {
            try advanceIssuanceStart(epoch, WalletState.FlowActive.stepEstablishingSession, commit: $0)
        }
    }

    /// Send `flow_start` (`send`) as the epoch-checked commit of the
    /// `starting_flow` step: a start cancelled before this point never reaches
    /// the engine. Whatever `send` needs that takes `lock` (e.g.
    /// `authorizationDetailsForActiveOffer()`) must be computed by the caller
    /// beforehand; `send` itself must not take the wallet lock.
    func dispatchIssuanceStart(epoch: Int, send: () -> Void) throws {
        try withoutActuallyEscaping(send) {
            try advanceIssuanceStart(epoch, WalletState.FlowActive.stepStartingFlow, commit: $0)
        }
    }

    /// Failure path of a start. A current attempt clears the in-flight guards,
    /// drops the pending flow state (so the host is not left on a spinner
    /// nothing will ever clear) and returns `error` for the caller to throw. An
    /// attempt that was cancelled meanwhile returns `CancellationError` and
    /// leaves everything alone - the cancel already reset it, and it may now
    /// belong to a newer attempt. The currency check and the cleanup are one
    /// critical section, so a newer attempt's guard and state cannot be cleared
    /// by this one.
    func failIssuanceStart(_ epoch: Int, _ error: Error) -> Error {
        lock.lock()
        guard issuanceStartEpoch.isCurrent(epoch) else {
            lock.unlock()
            return CancellationError()
        }
        issuanceStartHook?("fail.afterCheck")
        resetIssuanceGuardsLocked()
        let ready = _state.abandoningPendingStart()
        if let ready { _state = ready }
        let observers = ready == nil ? [] : Array(stateContinuations.values)
        lock.unlock()
        if let ready { for c in observers { c.yield(ready) } }
        return error
    }
}
