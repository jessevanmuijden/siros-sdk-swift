// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

// Wiring of the pending issuance state (see `IssuancePendingState.swift`) to
// the wallet: the first thing a start call does is publish it, each slow step
// advances it, and a failure or a cancel takes it away again.
extension SirosWallet {
    /// Publish the synchronous pre-engine state of an issuance start - the
    /// first thing a start call does, before any network work. Only from
    /// `.ready`; from any other state the start proceeds as before without a
    /// visible flow state. Returns this attempt's epoch.
    func beginIssuanceStart() -> Int {
        let epoch = issuanceStartEpoch.begin()
        if let pending = state.beginningIssuanceStart() {
            setState(pending)
        }
        return epoch
    }

    /// Advance the pre-engine step, and stop a start that was cancelled while
    /// it was suspended: `cancelCurrentFlow()` has already reset the wallet, so
    /// a cancelled start only has to unwind (`CancellationError`) - it must not
    /// touch state again, which by now may belong to a newer attempt.
    func advanceIssuanceStart(_ epoch: Int, _ step: String) throws {
        try issuanceStartEpoch.checkCurrent(epoch)
        if let next = state.advancingPendingStep(to: step) {
            setState(next)
            // A synchronous observer of the state may have cancelled while it
            // was published; stop before the caller goes on to send anything.
            try issuanceStartEpoch.checkCurrent(epoch)
        }
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
        // Stop a superseded attempt before it replaces the socket a newer one owns.
        try advanceIssuanceStart(epoch, WalletState.FlowActive.stepEstablishingSession)
        engine.forceReconnect(appToken: token.raw)
        try await engine.awaitConnected()
    }

    /// Failure path of a start. A current attempt clears the in-flight guards,
    /// drops the pending flow state (so the host is not left on a spinner
    /// nothing will ever clear) and returns `error` for the caller to throw. An
    /// attempt that was cancelled meanwhile returns `CancellationError` and
    /// leaves everything alone - the cancel already reset it, and it may now
    /// belong to a newer attempt.
    func failIssuanceStart(_ epoch: Int, _ error: Error) -> Error {
        guard issuanceStartEpoch.isCurrent(epoch) else { return CancellationError() }
        resetIssuanceGuards()
        if let ready = state.abandoningPendingStart() {
            setState(ready)
        }
        return error
    }
}
