// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore

// The commits of the session-start paths (login, keystore unlock) and of flow
// completions that persist or publish account state, each as an admitted write on
// the `TeardownGate`: a ticket taken before the path's first await is re-checked at
// the write, so an account wipe that landed meanwhile is never undone.
extension SirosWallet {
    /// Throws `CancellationError` when a wipe closed the gate after `ticket` was taken.
    func requireAdmitted(_ ticket: TeardownGate.Ticket) throws {
        guard teardownGate.isValid(ticket) else { throw CancellationError() }
    }

    /// Runs `body` as an admitted write, or throws `CancellationError` without running it.
    func admittedCommit<T>(_ ticket: TeardownGate.Ticket, _ body: () async throws -> T) async throws -> T {
        guard let result = try await teardownGate.admit(ticket, body) else { throw CancellationError() }
        return result
    }

    /// Publishes `newState` only while `ticket` is valid; the check and the write are one step under the
    /// wallet lock, which the wipe also takes to close the gate. Returns whether it was published.
    @discardableResult
    func setStateIfAdmitted(_ newState: WalletState, ticket: TeardownGate.Ticket) -> Bool {
        lock.lock()
        guard teardownGate.isValid(ticket) else { lock.unlock(); return false }
        _state = newState
        let continuations = Array(stateContinuations.values)
        lock.unlock()
        for continuation in continuations { continuation.yield(newState) }
        return true
    }

    /// `unlockKeystore`'s commit: the keystore unlock (which restores the container's credentials and keys), the
    /// account-cache heal and the `.ready` state, admitted together. Throws `CancellationError` when refused.
    func commitKeystoreUnlock(
        ticket: TeardownGate.Ticket,
        container: Data,
        resolved: UnlockKeystorePrfResolution,
        assertion: PasskeyAssertion,
        userId: String,
        displayName: String?
    ) async throws {
        try await admittedCommit(ticket) {
            try await keystore.unlock(
                prfOutput: resolved.prfOutput.first,
                encryptedContainer: container,
                hkdfSalt: resolved.hkdfSalt,
                hkdfInfo: resolved.hkdfInfo
            )
            if let recoveredSalt = resolved.recoveredSalt, let accountId = sessionStore.activeAccountId {
                healAccountCache(
                    accountId: accountId, userId: userId, displayName: displayName,
                    credentialId: assertion.credentialId, prfSalt: recoveredSalt,
                    hkdfSalt: resolved.hkdfSalt, hkdfInfo: resolved.hkdfInfo
                )
            }
        }
        let creds = await credentialStore.getAll()
        guard setStateIfAdmitted(.ready(userId: userId, displayName: displayName, credentials: creds), ticket: ticket) else {
            throw CancellationError()
        }
    }

    /// `login`'s keystore commit: the unlock and the session/registry bookkeeping (which creates the account
    /// registry entry), admitted together. Throws `CancellationError` when refused.
    func commitLoginUnlock(
        ticket: TeardownGate.Ticket,
        privateData: Data,
        resolved: LoginPrfResolution,
        accountId: String,
        session: LoginFinishResult,
        assertion: PasskeyAssertion
    ) async throws {
        try await admittedCommit(ticket) {
            try await keystore.unlock(
                prfOutput: resolved.prfOutput.first,
                encryptedContainer: privateData,
                hkdfSalt: resolved.hkdfSalt,
                hkdfInfo: resolved.hkdfInfo,
                prfSalt: resolved.prfSalt
            )
            recordSuccessfulLogin(
                accountId: accountId, session: session, assertion: assertion,
                prfSaltBytes: resolved.prfSalt, hkdfSalt: resolved.hkdfSalt, hkdfInfo: resolved.hkdfInfo,
                recoveredSalt: resolved.recoveredSalt
            )
        }
    }

    /// `login`'s last step: the new session's `.ready` state. Throws `CancellationError` when refused.
    func commitLoginReady(ticket: TeardownGate.Ticket, session: LoginFinishResult) async throws {
        bumpSessionGeneration()
        let creds = await credentialStore.getAll()
        guard setStateIfAdmitted(.ready(userId: session.uuid, displayName: session.displayName, credentials: creds), ticket: ticket) else {
            throw CancellationError()
        }
    }

    /// The `.ready` state after a flow completion, from a credential read that can resume after a wipe: refused
    /// (and `.disconnected` left alone) when `ticket` is no longer valid.
    func restoreReadyState(ticket: TeardownGate.Ticket) async {
        switch state {
        case .flowActive(let userId, let displayName, _, _, _, _), .ready(let userId, let displayName, _, _):
            let creds = await credentialStore.getAll()
            setStateIfAdmitted(.ready(userId: userId, displayName: displayName, credentials: creds), ticket: ticket)
        default:
            break
        }
    }
}
