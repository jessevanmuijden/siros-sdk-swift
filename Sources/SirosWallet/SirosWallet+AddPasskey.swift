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

        let outcome: AddPasskeyOutcome
        do {
            outcome = try await client.passkeyRegisterFinish(
                challengeId: challenge.challengeId,
                credential: created,
                nickname: nickname,
                privateData: prepared.container,
                authorization: authorization
            )
        } catch {
            rollbackLocalCredential()
            throw error
        }
        guard case let .added(credentialId) = outcome else { rollbackLocalCredential(); return Self.addPasskeyRefusal(outcome) }

        try await keystore.commitPrfKey(prepared)
        sessionStore.privateDataJwe = String(data: prepared.container, encoding: .utf8)
        sessionStore.privateDataEtag = client.privateDataEtag
        recordAddedPasskey(created.credentialId, prfSalt: prfSalt, nickname: nickname)
        return .added(credentialId: credentialId)
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
