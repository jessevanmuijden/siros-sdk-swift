// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore

extension SirosWallet {

    /// Add a passkey to the signed-in account (`register-begin`, then
    /// `register-finish`), the way the web wallet's Settings page does
    /// (go-wallet-backend#352).
    ///
    /// An account that already has a passkey needs one of them to authorise
    /// the addition: `authorizer` answers that assertion (by default with this
    /// wallet's own `AuthProvider`) and is asked first, so declining it creates
    /// nothing. Then the new passkey is created, its PRF output wraps the
    /// keystore's main key under an entry of its own, and passkey, assertion
    /// and the updated private data go to the backend in one request. The
    /// keystore and the local account cache change only once the backend
    /// accepted it; the platform passkey just created is rolled back otherwise
    /// where the `AuthProvider` supports it.
    ///
    /// The authenticator that creates the new passkey must support PRF, else
    /// the result is `.prfUnsupported`.
    ///
    /// - Parameter nickname: the user's name for the new passkey (1-256 characters).
    /// - Throws: `SirosError` when no session is active, the nickname is
    ///   invalid, the transport fails before `register-finish`, or the backend
    ///   answers outside its contract. A failure OF `register-finish` is the
    ///   result `.finishOutcomeUnknown`, not a throw.
    public func addPasskey(
        nickname: String,
        authorizer: StepUpAssertionProvider? = nil
    ) async throws -> AddPasskeyResult {
        // One enrolment ceremony at a time: the platform authenticator provider has a single pending request, so two
        // overlapping calls would hand one ceremony's response to the other (and strand the first).
        try await addPasskeyCeremonyMutex.withLock {
            try await performAddPasskey(nickname: nickname, authorizer: authorizer)
        }
    }

    private func performAddPasskey(
        nickname: String,
        authorizer: StepUpAssertionProvider?
    ) async throws -> AddPasskeyResult {
        guard !nickname.trimmingCharacters(in: .whitespaces).isEmpty, nickname.count <= 256 else {
            throw SirosError.wallet(message: "nickname must be 1-256 characters")
        }
        guard let client = currentAddPasskeyClient() else { throw SirosError.auth(message: "Not logged in") }
        guard keystore.isUnlocked else { return .walletLocked(message: nil) }

        // Captured before the first `await`: if the session moves on (a
        // logout, or a login/re-login - possibly to a DIFFERENT account -
        // completing) before the backend accepts this enrolment, that
        // accepted response must not be applied to whatever account/keystore
        // happens to be active when it finally arrives. See the matching
        // check right before the local writes below.
        let startGeneration = currentSessionGeneration()
        let startEpoch = currentEnrollmentEpoch()

        let challenge: PasskeyEnrollmentChallenge
        switch try await client.passkeyRegisterBegin() {
        case let .ready(ready): challenge = ready
        case let .forbidden(message): return .insufficientScope(message: message)
        case let .sessionRevoked(message): return .sessionRevoked(message: message)
        }

        // The assertion goes first: declining it creates nothing.
        var authorization: AuthenticateResult?
        if let options = challenge.authorization {
            do {
                authorization = try await (authorizer ?? { [authProvider] in try await authProvider.authenticate(options: $0) })(options)
            } catch {
                return .authorizerUnavailable(message: error.localizedDescription)
            }
        }

        let prfSalt = Self.randomBytes(32)
        // The new entry's own HKDF salt, so the keystore's pick-by-salt finds
        // this passkey's entry rather than the first one.
        let hkdfSalt = Self.randomBytes(32)
        let hkdfInfo = Data(Self.hkdfInfo.utf8)
        var createOptions = challenge.createOptions
        createOptions.prfSalt = prfSalt
        let created: RegisterResult
        do {
            created = try await authProvider.register(options: createOptions)
        } catch {
            return .passkeyCreationUnavailable(message: error.localizedDescription)
        }

        let prfOutput: PrfOutput
        do {
            prfOutput = try await resolvePrfOutput(
                ceremonyPrf: created.prfOutput, credentialId: created.credentialId, salt: prfSalt
            )
        } catch {
            rollbackLocalCredential(credentialId: created.credentialId)
            return .prfUnsupported(message: "PRF not supported by authenticator - cannot encrypt wallet data")
        }

        let result: EnrolmentTransaction
        do {
            result = try await runEnrolmentTransaction(EnrolmentContext(
                client: client, challenge: challenge, created: created, prfOutput: prfOutput, authorization: authorization,
                nickname: nickname, prfSalt: prfSalt, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo,
                startGeneration: startGeneration, startEpoch: startEpoch
            ))
        } catch {
            // Nothing above throws any more except the lock itself failing, before anything was sent.
            rollbackLocalCredential(credentialId: created.credentialId)
            throw error
        }

        return try settleEnrolment(result, created: created, startGeneration: startGeneration, startEpoch: startEpoch)
    }

    /// Turns one locked transaction's outcome into the public result, rolling the new credential back only where
    /// nothing reached the backend (or it definitively refused).
    private func settleEnrolment(
        _ result: EnrolmentTransaction, created: RegisterResult, startGeneration: Int, startEpoch: UInt64
    ) throws -> AddPasskeyResult {
        switch result {
        case let .refused(outcome):
            rollbackLocalCredential(credentialId: created.credentialId)
            return Self.addPasskeyRefusal(outcome)
        case let .preparationFailed(error):
            rollbackLocalCredential(credentialId: created.credentialId)
            throw error
        case let .finishOutcomeUnknown(error):
            // Kept: the backend may hold this passkey and its PRF entry, and deleting the credential would make them
            // unusable. The caller reconciles later (list the account's passkeys / retry).
            return .finishOutcomeUnknown(message: error.localizedDescription)
        case let .sessionChanged(accepted):
            if accepted { return .sessionChanged(message: nil) }
            // register-finish was never sent: the credential just created is unused.
            rollbackLocalCredential(credentialId: created.credentialId)
            return .notSubmitted(message: nil)
        case let .committed(credentialId):
            return .added(credentialId: credentialId)
        case let .acceptedButNotCommitted(credentialId, error):
            if currentEnrollmentIsLive(generation: startGeneration, epoch: startEpoch),
               let userId = sessionStore.userId {
                setState(.keystoreLocked(userId: userId, displayName: sessionStore.displayName))
            }
            return .localCommitFailed(credentialId: credentialId, message: error.localizedDescription)
        }
    }

    /// The locked transaction itself; see the comment on its body.
    private func runEnrolmentTransaction(_ context: EnrolmentContext) async throws -> EnrolmentTransaction {
        let client = context.client, challenge = context.challenge, created = context.created
        let prfOutput = context.prfOutput, authorization = context.authorization, nickname = context.nickname
        let prfSalt = context.prfSalt, hkdfSalt = context.hkdfSalt, hkdfInfo = context.hkdfInfo
        let startGeneration = context.startGeneration, startEpoch = context.startEpoch
        // ONE transaction under `keystoreContainerLock` (shared with
        // `persistAndSyncKeystore()`, see its doc comment): the snapshot the
        // backend is sent, the precondition matching that snapshot, the
        // finish, the keystore commit and the cache publication. Anything
        // narrower lets another enrolment or a queued sync move the
        // container or its ETag in between, so the backend ends up with an
        // older snapshot under a newer tag and a passkey's PRF entry is
        // erased, or a stale container is cached under the wrong tag.
        return try await keystoreContainerLock.withLock {
            // Nothing may be prepared from, or sent for, a session that has
            // already moved on: the keystore now holds another account.
            guard currentEnrollmentIsLive(generation: startGeneration, epoch: startEpoch) else {
                return .sessionChanged(accepted: false)
            }
            let prepared: PreparedPrfKey
            do {
                prepared = try await keystore.preparePrfKey(
                    credentialId: created.credentialId, prfOutput: prfOutput.first,
                    prfSalt: prfSalt, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo
                )
            } catch {
                return .preparationFailed(error)
            }
            // Read inside the same transaction as the snapshot above, so it
            // is the tag of exactly that state. After a session resume
            // `client` is a fresh `BackendApiClient` with no ETag of its
            // own (see `BackendApiClient.privateDataEtag`'s doc comment):
            // fall back to the one persisted with the cached container.
            let ifMatch = client.privateDataEtag ?? sessionStore.privateDataEtag
            // A definitive refusal comes back as a value; anything thrown here (timeout, lost response, 5xx)
            // leaves the backend's state unknown.
            let outcome: AddPasskeyOutcome
            do {
                outcome = try await client.passkeyRegisterFinish(
                    challengeId: challenge.challengeId,
                    credential: created,
                    nickname: nickname,
                    privateData: prepared.container,
                    authorization: authorization,
                    ifMatch: ifMatch
                )
            } catch {
                return .finishOutcomeUnknown(error)
            }
            guard case let .added(credentialId) = outcome else { return .refused(outcome) }

            // From here the backend has accepted the passkey: nothing below
            // may roll the authenticator credential back.
            // The one operation that mutates the (single, reused)
            // keystore: skipped when the session moved on while the
            // backend round trip was in flight. A switch landing after
            // this check is caught by the keystore itself, which refuses a
            // key prepared in another unlocked session.
            guard currentEnrollmentIsLive(generation: startGeneration, epoch: startEpoch) else {
                return .sessionChanged(accepted: true)
            }
            var commitError: Error?
            do { try await keystore.commitPrfKey(prepared) } catch { commitError = error }

            // Check and publish as one step under the wallet lock, which a
            // login, logout or unlock also takes to move the scope.
            let published = publishAcceptedEnrollment(prepared: prepared, context: context)
            guard published else { return .sessionChanged(accepted: true) }
            if let commitError {
                // A keystore that lacks the accepted entry must not export
                // and push a container without it: lock it, so the next
                // unlock reads the cached container that has the entry.
                keystore.lock()
                return .acceptedButNotCommitted(credentialId: credentialId, error: commitError)
            }
            return .committed(credentialId: credentialId)
        }
    }

    private func currentEnrollmentIsLive(generation: Int, epoch: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return enrollmentIsCurrentLocked(generation: generation, epoch: epoch)
    }

    /// Writes an accepted enrolment's container, tag and passkey to the local
    /// caches, but only while the session it was started for is still the
    /// live one. The check and the writes are one step under the wallet lock.
    private func publishAcceptedEnrollment(prepared: PreparedPrfKey, context: EnrolmentContext) -> Bool {
        let client = context.client, created = context.created, prfSalt = context.prfSalt
        let nickname = context.nickname, generation = context.startGeneration, epoch = context.startEpoch
        lock.lock(); defer { lock.unlock() }
        guard enrollmentIsCurrentLocked(generation: generation, epoch: epoch) else { return false }
        sessionStore.privateDataJwe = String(data: prepared.container, encoding: .utf8)
        sessionStore.privateDataEtag = client.privateDataEtag
        recordAddedPasskey(created.credentialId, prfSalt: prfSalt, nickname: nickname)
        return true
    }

    private func currentAddPasskeyClient() -> BackendApiClient? {
        lock.lock(); defer { lock.unlock() }
        return apiClient
    }

    private static func addPasskeyRefusal(_ outcome: AddPasskeyOutcome) -> AddPasskeyResult {
        switch outcome {
        case let .added(credentialId): return .added(credentialId: credentialId)
        case let .authorizationRequired(message): return .authorizationRequired(message: message)
        case let .authorizationFailed(message): return .authorizationFailed(message: message)
        case let .retryNeeded(message): return .retryNeeded(reason: message)
        case .privateDataConflict: return .privateDataConflict(message: nil)
        case let .registrationRejected(_, message): return .registrationRejected(message: message)
        case let .sessionRevoked(message): return .sessionRevoked(message: message)
        }
    }

    /// Remembers the new passkey in the local account cache so a cached login
    /// can offer it with its own PRF salt.
    private func recordAddedPasskey(_ credentialId: Data, prfSalt: Data, nickname: String) {
        guard let accountId = accountRegistry.activeAccountId,
              var account = accountRegistry.findAccount(accountId: accountId) else { return }
        let id = Self.b64UrlEncode(credentialId)
        guard !account.passkeys.contains(where: { $0.credentialId == id }) else { return }
        account.passkeys.append(CachedPasskey(credentialId: id, prfSalt: Self.b64Encode(prfSalt), nickname: nickname))
        accountRegistry.upsertAccount(account)
    }
}

// What one locked prepare-finish-commit-publish attempt produced.
private enum EnrolmentTransaction {
    /// The backend refused it (or left the account unchanged for any
    /// other reason) - nothing was committed.
    case refused(AddPasskeyOutcome)
    /// The session moved on, either before anything was prepared (the
    /// backend was never asked) or after the backend accepted it. In
    /// the second case the passkey is real but is deliberately not
    /// applied to whatever keystore and account are active now.
    case sessionChanged(accepted: Bool)
    /// The keystore could not prepare the new entry: nothing was sent.
    case preparationFailed(Error)
    /// The request to register-finish failed in transport (timeout, lost response, 5xx): whether the backend
    /// stored the passkey is UNKNOWN, so the credential must not be rolled back.
    case finishOutcomeUnknown(Error)
    /// Accepted, committed into the live keystore and published to the
    /// local caches.
    case committed(credentialId: String?)
    /// Accepted and published to the caches, but the live keystore
    /// refused the entry.
    case acceptedButNotCommitted(credentialId: String?, error: Error)
}

/// Everything one locked enrolment transaction needs, bundled to keep the helper signatures short.
private struct EnrolmentContext {
    let client: BackendApiClient
    let challenge: PasskeyEnrollmentChallenge
    let created: RegisterResult
    let prfOutput: PrfOutput
    let authorization: AuthenticateResult?
    let nickname: String
    let prfSalt: Data
    let hkdfSalt: Data
    let hkdfInfo: Data
    let startGeneration: Int
    let startEpoch: UInt64
}
