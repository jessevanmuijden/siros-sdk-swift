// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore

extension SirosWallet {

    /// Delete the account (go-wallet-backend#352): a fresh passkey assertion
    /// (step-up) plus the typed confirmation authorise the backend to erase
    /// the user's data and end every session. Irreversible.
    ///
    /// The assertion is obtained from `stepUp`, or from the wallet's
    /// `AuthProvider` when nil, for the options the backend returns; it is
    /// valid 2 minutes and used once, so a retry needs a new call.
    ///
    /// Local state is wiped only when the backend accepted the deletion
    /// (`deleted`, `cleanupPending`, `operatorRequired`); any other result
    /// leaves it as it was.
    ///
    /// - Parameter confirmation: must equal `accountDeletionConfirmation`.
    public func deleteAccount(
        confirmation: String,
        stepUp: StepUpAssertionProvider? = nil
    ) async -> DeleteAccountResult {
        guard confirmation == accountDeletionConfirmation else { return .failed(.confirmationRequired) }
        let client = currentApiClient()
        guard let client else { return .failed(.notLoggedIn) }

        let challenge: AccountDeletionChallenge
        do {
            challenge = try await client.deleteAccountBegin()
        } catch {
            return .failed(Self.deletionFailure(for: error))
        }

        let assertion: AuthenticateResult
        do {
            let options = AuthenticateOptions(
                rpId: challenge.rpId,
                challenge: challenge.challenge,
                allowCredentials: challenge.allowCredentials,
                userVerification: challenge.userVerification
            )
            assertion = try await (stepUp ?? { [authProvider] in try await authProvider.authenticate(options: $0) })(options)
        } catch {
            return .failed(.stepUpAborted(message: error.localizedDescription))
        }

        let response: AccountDeletionResponse
        do {
            response = try await client.deleteAccount(
                challengeId: challenge.challengeId,
                credential: Self.assertionCredential(assertion),
                confirm: confirmation
            )
        } catch {
            return .failed(Self.deletionFailure(for: error))
        }

        switch response {
        case .deleted: return .deleted(localWipe: await wipeLocalState())
        case .cleanupPending: return .cleanupPending(localWipe: await wipeLocalState())
        case .operatorRequired: return .operatorRequired(localWipe: await wipeLocalState())
        case let .incomplete(message): return .retryNeeded(.incomplete(message: message))
        case .stepUpFailed: return .retryNeeded(.stepUpFailed)
        case .stepUpExpired: return .retryNeeded(.stepUpExpired)
        case .stepUpRequired: return .retryNeeded(.stepUpRequired)
        case .confirmationRequired: return .failed(.confirmationRequired)
        case .sessionRejected: return .failed(.sessionRejected)
        case .accountNotFound: return .failed(.accountNotFound)
        }
    }

    /// What a long-running handler captures before its first `await`: the
    /// session generation and an admission ticket from the `TeardownGate`. If
    /// either has moved when the handler resumes (the account was deleted, the
    /// session ended), its results must not be applied. Nil while a wipe has
    /// closed the gate: such a handler must not start.
    struct TeardownToken: Equatable {
        let generation: Int
        let ticket: TeardownGate.Ticket
    }

    func currentTeardownToken() -> TeardownToken? {
        lock.lock(); defer { lock.unlock() }
        guard let ticket = teardownGate.ticket() else { return nil }
        return TeardownToken(generation: sessionGeneration, ticket: ticket)
    }

    /// The caller holds `lock`.
    func isCurrentLocked(_ token: TeardownToken) -> Bool {
        sessionGeneration == token.generation && teardownGate.isValid(token.ticket)
    }

    /// Admits writes again for a new session (login, register, resume): after a
    /// wipe, also reopens key creation in the keystores it closed. Waits for a
    /// wipe still in progress.
    func reopenForNewSession() async {
        if await teardownGate.reopen() {
            for (_, store) in distinctKeystores() { store.reopenKeyOperations() }
        }
    }

    private func currentApiClient() -> BackendApiClient? {
        lock.lock(); defer { lock.unlock() }
        return apiClient
    }

    /// The default keystore, then each other registered one once, labelled for
    /// the report. The default keeps the historical "keystore" label.
    func distinctKeystores() -> [(label: String, store: KeystoreManager)] {
        var result: [(label: String, store: KeystoreManager)] = [("keystore", keystore)]
        var seen: Set<ObjectIdentifier> = [ObjectIdentifier(keystore)]
        for (pluginId, store) in (config.availableKeystores ?? [:]).sorted(by: { $0.key < $1.key })
        where seen.insert(ObjectIdentifier(store)).inserted {
            result.append(("keystore \(pluginId)", store))
        }
        return result
    }

    private func dropInMemoryHolderState() {
        lock.lock()
        resetPresentationHistoryLocked()
        lastTrustResults.removeAll()
        pendingMatchResultsByFlow.removeAll()
        pendingAuthorizations.removeAll()
        lock.unlock()
        resetIssuanceGuards()
    }

    private static func assertionCredential(_ result: AuthenticateResult) -> [String: Any] {
        var response: [String: Any] = [
            "authenticatorData": b64UrlEncode(result.authenticatorData),
            "clientDataJSON": b64UrlEncode(result.clientDataJSON),
            "signature": b64UrlEncode(result.signature),
        ]
        if let userHandle = result.userHandle { response["userHandle"] = b64UrlEncode(userHandle) }
        return [
            "id": b64UrlEncode(result.credentialId),
            "rawId": b64UrlEncode(result.credentialId),
            "type": "public-key",
            "response": response,
        ]
    }

    private static func deletionFailure(for error: Error) -> DeleteAccountFailure {
        if case let SirosError.backendApi(code, _, _) = error {
            if code == 401 { return .sessionRejected }
            if code == 403 { return .notPermitted }
            if code == 404 { return .accountNotFound }
            if code == 400, (error as? SirosError)?.apiErrorCode == errorNoPasskey { return .noPasskey }
        }
        return .requestFailed(message: error.localizedDescription)
    }

    /// Remove everything this wallet holds locally: keystore contents and key
    /// material, credentials, presentation records and history, every
    /// account's session (Keychain included: tokens, PRF salts, instance key),
    /// the account registry, trust and credential-status caches and the WSCD
    /// selection policy. Ends the session without a server call, since the
    /// backend has already refused its tokens.
    ///
    /// Continues past a failing step and reports each. Hardware keys on an
    /// external authenticator are not erased; stores the host app owns
    /// (transaction log, Digital Credentials API registry, file caches) are
    /// the host's to clear.
    func wipeLocalState() async -> LocalWipeReport {
        var failures: [LocalWipeFailure] = []
        func step(_ component: String, _ body: () async throws -> Void) async {
            do { try await body() } catch {
                failures.append(LocalWipeFailure(component: component, message: error.localizedDescription))
            }
        }

        // Close write admission FIRST - synchronously, before any await of the
        // teardown - then wait for the writes already admitted. It reopens only
        // when a new session starts (`reopenForNewSession`).
        lock.lock(); teardownGate.close(); lock.unlock()
        defer { teardownGate.endWipe() }
        await teardownGate.drain()

        // Every distinct keystore, not only the default one: holder keys can
        // be generated in any store registered in `availableKeystores`. A
        // keystore container is only writable while unlocked; when locked
        // there is nothing in memory and its persisted form is in the session
        // store, removed below. Signing keys are erased before the lock.
        for (label, store) in distinctKeystores() {
            if store.isUnlocked {
                await step("\(label) credentials") { try await store.clearCredentials() }
                await step("\(label) presentation records") { try await store.clearPresentationRecords() }
            }
            await step("\(label) signing keys") { try await store.eraseKeyMaterial() }
            store.lock()
        }
        await step("credential store") { try await credentialStore.eraseAll() }
        // Scoped to the active account's storage, so before the session ends.
        wscdSelectionPolicy.clearAll()

        endSessionLocally()
        // `AuthServerClient` keeps its own token cache beside `AuthTokens`;
        // left warm, a token for the deleted account would be served to the
        // next request. Awaited before the disconnected state is published.
        await authServerClient?.clearTokenCache()
        await step("session store") { try sessionStore.eraseAll() }
        await step("account registry") { try accountRegistry.eraseAll() }
        trustDecisionCache.clear()
        await clearCredentialStatusCachesAwaited()
        dropInMemoryHolderState()

        setState(.disconnected(cachedAccounts: []))
        return LocalWipeReport(failures: failures)
    }
}
