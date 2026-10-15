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
    ///   invalid, or the transport fails / the backend answers outside its
    ///   contract.
    public func addPasskey(
        nickname: String,
        authorizer: StepUpAssertionProvider? = nil
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
            rollbackLocalCredential()
            return .prfUnsupported(message: "PRF not supported by authenticator - cannot encrypt wallet data")
        }

        let prepared: PreparedPrfKey
        do {
            prepared = try await keystore.preparePrfKey(
                credentialId: created.credentialId, prfOutput: prfOutput.first,
                prfSalt: prfSalt, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo
            )
        } catch {
            rollbackLocalCredential()
            throw error
        }

        // What one locked finish-then-commit attempt produced - see below.
        enum FinishAndCommit {
            /// The backend refused it (or left the account unchanged for any
            /// other reason) - nothing was committed.
            case refused(AddPasskeyOutcome)
            /// The backend accepted it, but the session moved on (logout, or
            /// a login/re-login - possibly to a different account) before the
            /// commit below could run, so it was deliberately skipped rather
            /// than applied to whatever keystore is active now.
            case sessionChanged
            /// The backend accepted it AND it is committed into the (still
            /// correct) live keystore.
            case committed(credentialId: String?)
        }

        let finishResult: FinishAndCommit
        do {
            // One lock scope spanning finish AND commit - shared with
            // `persistAndSyncKeystore()`, see `keystoreContainerLock`'s doc
            // comment. Two separate `withLock` calls here (release the lock
            // between finish's accept and the commit) would reopen exactly
            // the race this exists to close: a `persistAndSyncKeystore()`
            // slipping in between them would still export the container as
            // it stood BEFORE the new entry and push it, erasing what this
            // finish just had the backend accept.
            finishResult = try await keystoreContainerLock.withLock {
                let outcome = try await client.passkeyRegisterFinish(
                    challengeId: challenge.challengeId,
                    credential: created,
                    nickname: nickname,
                    privateData: prepared.container,
                    authorization: authorization,
                    // After a session resume, `client` is a fresh
                    // `BackendApiClient` with no ETag of its own yet (see
                    // `BackendApiClient.privateDataEtag`'s doc comment) -
                    // fall back to the one persisted alongside the cached
                    // container at the last successful read/write, so this
                    // still carries a real precondition instead of silently
                    // omitting `If-Match` and risking a stale-cache overwrite
                    // of another device's changes.
                    ifMatch: client.privateDataEtag ?? sessionStore.privateDataEtag
                )
                guard case let .added(credentialId) = outcome else { return .refused(outcome) }
                // Checked here, still holding the lock, immediately before
                // the one operation that mutates the (single, reused)
                // keystore instance: a logout (or a login/re-login,
                // possibly to a different account) completing while the
                // backend round trip was in flight must not let this
                // `commitPrfKey` append account A's entry to account B's
                // now-unlocked keystore.
                guard currentSessionGeneration() == startGeneration else { return .sessionChanged }
                try await keystore.commitPrfKey(prepared)
                return .committed(credentialId: credentialId)
            }
        } catch {
            rollbackLocalCredential()
            throw error
        }

        switch finishResult {
        case let .refused(outcome):
            rollbackLocalCredential()
            return Self.addPasskeyRefusal(outcome)
        case .sessionChanged:
            return .sessionChanged(message: nil)
        case let .committed(credentialId):
            // Re-checked once more, now that the lock is released: the
            // commit above is done either way, but the account-cache writes
            // below are about THIS session, not the keystore, and must not
            // mislabel whatever account is active now if a switch landed in
            // the narrow gap since the check inside the lock.
            guard currentSessionGeneration() == startGeneration else {
                return .sessionChanged(message: nil)
            }
            sessionStore.privateDataJwe = String(data: prepared.container, encoding: .utf8)
            sessionStore.privateDataEtag = client.privateDataEtag
            recordAddedPasskey(created.credentialId, prfSalt: prfSalt, nickname: nickname)
            return .added(credentialId: credentialId)
        }
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
