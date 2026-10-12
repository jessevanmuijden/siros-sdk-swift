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
                allowCredentials: challenge.allowCredentials.isEmpty ? nil : challenge.allowCredentials,
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

    private func currentApiClient() -> BackendApiClient? {
        lock.lock(); defer { lock.unlock() }
        return apiClient
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

        // The keystore container is only writable while unlocked; when locked
        // there is nothing in memory and its persisted form is in the session
        // store, removed below.
        if keystore.isUnlocked {
            await step("keystore credentials") { try await keystore.clearCredentials() }
            await step("keystore presentation records") { try await keystore.clearPresentationRecords() }
        }
        await step("credential store") { await credentialStore.clear() }
        // Scoped to the active account's storage, so before the session ends.
        wscdSelectionPolicy.clearAll()

        endSessionLocally()
        sessionStore.clearAll()
        accountRegistry.clear()
        trustCache.clear()
        await clearCredentialStatusCachesAwaited()
        dropInMemoryHolderState()

        setState(.disconnected(cachedAccounts: []))
        return LocalWipeReport(failures: failures)
    }
}
