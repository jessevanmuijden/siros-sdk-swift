import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore

// MARK: - Passkey assertion shared by login() and unlockKeystore()

extension SirosWallet {
    /// Outcome of one passkey assertion against the auth server's login
    /// challenge: what `loginFinish` needs, plus the PRF output already
    /// resolved so the caller can fail before touching the server session.
    struct PasskeyAssertion {
        let challengeId: String
        let credential: [String: Any]
        /// nil exactly when no PRF salt for `credentialId` was known locally
        /// - neither this ceremony's per-credential candidates nor the active
        /// session's own stored salt named one. Most commonly: the local
        /// account cache was wiped (reinstall, cleared app data, device
        /// migration) while the passkey itself is still perfectly healthy in
        /// the platform authenticator. Rather than derive a PRF output from a
        /// guessed salt - which can never unwrap the real container, and used
        /// to fail only much later (and much less clearly) at
        /// `keystore.unlock`'s unwrap step - this is left nil so the caller
        /// can recover the real salt from the account's own server-synced
        /// privateData container instead. See `login()`'s recovery branch.
        let prfOutput: PrfOutput?
        /// The salt `prfOutput` was evaluated for - what the session store must
        /// record, since the container's PRF key is bound to it. nil under the
        /// same condition as `prfOutput`.
        let prfSalt: Data?
        /// The cached account whose passkey answered the ceremony, if known.
        let cachedAccount: CachedAccount?
        /// The credential the ceremony actually completed with. Kept raw
        /// alongside `cachedAccount` because that is only ever the *first*
        /// registry match, which is not enough to decide anything destructive
        /// - see `loginRefusalSubject(forCredential:)`.
        let credentialId: Data
    }

    /// What `recoverPrfFromPrivateData` recovered from one `PrfKeyInfo` entry.
    struct RecoveredPrf {
        let prfOutput: PrfOutput
        let prfSalt: Data
        let hkdfSalt: Data
        let hkdfInfo: Data
    }

    /// What `resolveLoginPrf` resolved for `login()` to unlock with.
    struct LoginPrfResolution {
        let prfOutput: PrfOutput
        let prfSalt: Data
        let hkdfSalt: Data
        let hkdfInfo: Data
        /// Non-nil exactly when recovered from privateData - see
        /// `recordSuccessfulLogin`'s doc comment on what that triggers.
        let recoveredSalt: Data?
    }

    /// What `resolveUnlockKeystorePrf` resolved for `unlockKeystore()` to
    /// unlock with.
    struct UnlockKeystorePrfResolution {
        let prfOutput: PrfOutput
        let hkdfSalt: Data
        let hkdfInfo: Data
        /// Non-nil exactly when recovered from privateData - the caller heals
        /// the account cache in that case, same as `LoginPrfResolution`'s.
        let recoveredSalt: Data?
    }

    /// Runs `loginBegin` -> platform `authenticate` -> PRF resolution.
    ///
    /// Shared by `login()` and `unlockKeystore()`. The PRF output is resolved
    /// here, BEFORE the caller's `loginFinish`: `getPrfOutput` fails closed for
    /// an authenticator without PRF, and the server must not be handed a
    /// completed login for a session this side can never unlock.
    ///
    /// - Parameter accountId: restrict the offered passkeys to this cached
    ///   account (unlock of a resumed session, whose container is fixed); nil
    ///   offers every loginable account's passkeys (login).
    func performPasskeyAssertion(asClient: AuthServerClient, accountId: String? = nil) async throws -> PasskeyAssertion {
        // After logout() the account-scoped session store is empty, so the
        // durable source of salts is the account registry: offer every
        // loginable credential with its own salt (WebAuthn evalByCredential)
        // and let the authenticator evaluate PRF for whichever one the user
        // picks. The session store's salt still covers the unlock-after-resume
        // case, where the active account is known.
        let storedPrfSalt = sessionStore.prfSalt.flatMap { Self.b64Decode($0) }
        let candidates = loginPrfCandidates(accountId: accountId)

        let challengeResponse = try await asClient.loginBegin()
        guard let challengeId = challengeResponse["challengeId"] as? String else {
            throw SirosError.auth(message: "Missing challengeId")
        }
        guard let getOptions = challengeResponse["getOptions"] as? [String: Any],
              let publicKey = getOptions["publicKey"] as? [String: Any] else {
            throw SirosError.auth(message: "Missing getOptions.publicKey")
        }
        guard let rpId = publicKey["rpId"] as? String else {
            throw SirosError.auth(message: "Missing rpId")
        }
        guard let challengeB64 = publicKey["challenge"] as? String,
              let challenge = Self.b64UrlDecode(challengeB64) else {
            throw SirosError.auth(message: "Missing challenge")
        }

        // When scoped to one account, also restrict discovery to its passkeys:
        // the PRF map only supplies inputs, it does not stop the platform from
        // offering every passkey for the RP.
        let allow: [AllowCredential]? = accountId == nil || candidates.isEmpty
            ? nil
            : candidates.keys.map { AllowCredential(id: $0) }
        let options = AuthenticateOptions(
            rpId: rpId,
            challenge: challenge,
            allowCredentials: allow,
            prfSalt: storedPrfSalt,
            prfSaltsByCredential: candidates.isEmpty ? nil : candidates
        )
        let result = try await authProvider.authenticate(options: options)

        // Belt and braces for the scoped case: a credential known to belong to
        // a different cached account must not complete this ceremony - the
        // resumed account's container could never be unwrapped with it, and
        // loginFinish would still have been handed a valid assertion.
        let cachedAccount = cachedAccount(owning: result.credentialId)
        if let accountId, let owner = cachedAccount?.accountId, owner != accountId {
            throw SirosError.auth(message: "Passkey belongs to a different account than the one being unlocked")
        }

        var responseDict: [String: Any] = [
            "authenticatorData": Self.b64UrlEncode(result.authenticatorData),
            "clientDataJSON": Self.b64UrlEncode(result.clientDataJSON),
            "signature": Self.b64UrlEncode(result.signature),
        ]
        if let uh = result.userHandle {
            responseDict["userHandle"] = Self.b64UrlEncode(uh)
        }
        let credential: [String: Any] = [
            "id": Self.b64UrlEncode(result.credentialId),
            "rawId": Self.b64UrlEncode(result.credentialId),
            "type": "public-key",
            "response": responseDict,
        ]
        // The salt that applies to the credential the user actually used: its
        // registry entry first; else the session store's salt, but only when
        // the credential is not known to belong to a different cached account
        // (the session salt is the active account's - pairing it with another
        // account's credential would derive a real PRF under the wrong salt
        // and fail only later, at unwrap).
        let sessionSaltApplies = cachedAccount == nil || cachedAccount?.accountId == sessionStore.activeAccountId
        let knownSalt = options.prfSalt(for: result.credentialId)
            ?? (sessionSaltApplies ? storedPrfSalt : nil)

        // The ceremony's own PRF output, if any, is always authoritative and
        // checked FIRST, before the cache-miss guard below: a real
        // authenticator only ever produces one when it was actually given an
        // input salt for this exact credential (i.e. `knownSalt` could not
        // really be nil here on a real platform) - but a few test doubles
        // model `authenticate` more loosely, and in any case trusting data
        // already in hand is strictly better than discarding it.
        if let ceremonyPrf = result.prfOutput {
            return PasskeyAssertion(
                challengeId: challengeId,
                credential: credential,
                prfOutput: ceremonyPrf,
                prfSalt: knownSalt ?? Self.randomBytes(32),
                cachedAccount: cachedAccount,
                credentialId: result.credentialId
            )
        }

        guard let knownSalt else {
            // Nothing locally known ties this credential to a salt at all -
            // this is the cache-miss condition itself, not merely an
            // authenticator without PRF support (that failure mode is
            // below, and is unaffected: it still runs, and still fails
            // closed, whenever a salt *is* known). Previously this fell
            // through to a fresh random salt (or a stale `storedPrfSalt`
            // belonging to a different account entirely) and spent a real
            // authenticator ceremony deriving a PRF output from it - one
            // that could never unwrap the real container, silently wrong
            // rather than visibly absent. Returning here instead, with no
            // second ceremony spent on a salt already known to be useless,
            // lets the caller recover the real salt from privateData and
            // spend exactly one real recovery ceremony - see `login()`.
            return PasskeyAssertion(
                challengeId: challengeId,
                credential: credential,
                prfOutput: nil,
                prfSalt: nil,
                cachedAccount: cachedAccount,
                credentialId: result.credentialId
            )
        }

        let prfOutput = try await authProvider.getPrfOutput(credentialId: result.credentialId, salt: knownSalt)
        return PasskeyAssertion(
            challengeId: challengeId,
            credential: credential,
            prfOutput: prfOutput,
            prfSalt: knownSalt,
            cachedAccount: cachedAccount,
            credentialId: result.credentialId
        )
    }

    /// `(credentialId, prfSalt)` for every passkey the ceremony should offer:
    /// just `accountId`'s when given, otherwise every loginable account's on
    /// THIS wallet's backend and tenant - the registry spans environments, and
    /// the auth server the challenge came from can only authenticate its own
    /// passkeys. Which one the user picks is only known once the ceremony
    /// completes. Mirrors the Kotlin SDK's `loginCandidates`.
    func loginPrfCandidates(accountId: String? = nil) -> [Data: Data] {
        let accounts = accountId.map { id in accountRegistry.findAccount(accountId: id).map { [$0] } ?? [] }
            ?? accountRegistry.listLoginableAccounts(tenantId: config.tenantId)
                .filter { $0.backendUrl == config.backendUrl }
        var candidates: [Data: Data] = [:]
        for account in accounts {
            for passkey in account.passkeys where !passkey.prfSalt.isEmpty {
                guard let credentialId = Self.b64UrlDecode(passkey.credentialId),
                      let salt = Self.b64Decode(passkey.prfSalt) else { continue }
                candidates[credentialId] = salt
            }
        }
        return candidates
    }

    /// The account `credentialId` belongs to *in this deployment*, or nil when
    /// that cannot be answered unambiguously. What `login()` names as the
    /// account a `.deactivated` refusal may forget.
    ///
    /// Resolved against the same scope `loginPrfCandidates` offered its
    /// candidates under - this tenant, this backend - rather than by filtering
    /// `cachedAccount(owning:)` afterwards: that answers the *first* match
    /// anywhere in the registry, so an out-of-scope duplicate arriving first
    /// would hide the real owner. Only an unambiguous single owner counts.
    ///
    /// Everything else answers nil - forget nothing: a platform passkey with
    /// no registry entry, a credential that belongs to another tenant or
    /// deployment, and a registry that somehow holds the same credential id
    /// twice in scope. This decides whether a `.deactivated` refusal deletes a
    /// cached account, so "not sure" has to mean "don't".
    func accountId(owningInScope credentialId: Data) -> String? {
        let credIdB64url = Self.b64UrlEncode(credentialId)
        let owners = accountRegistry.listAccounts().filter { account in
            account.tenantId == config.tenantId
                && account.backendUrl == config.backendUrl
                && account.passkeys.contains { $0.credentialId == credIdB64url }
        }
        guard owners.count == 1 else { return nil }
        return owners.first?.accountId
    }

    /// The cached account that registered `credentialId`, if any.
    func cachedAccount(owning credentialId: Data) -> CachedAccount? {
        let credIdB64url = Self.b64UrlEncode(credentialId)
        return accountRegistry.listAccounts().first { account in
            account.passkeys.contains { $0.credentialId == credIdB64url }
        }
    }

    /// Resolves the PRF output for a completed WebAuthn ceremony.
    ///
    /// Prefers the PRF output the ceremony itself produced (a real
    /// ASAuthorization PRF assertion, or LocalAuthProvider's locally computed
    /// value) so the user isn't prompted twice; otherwise runs a separate
    /// `getPrfOutput()` ceremony with the real credential ID — never an empty
    /// placeholder. `getPrfOutput` fails closed for authenticators without
    /// PRF, so callers resolve this BEFORE completing the server-side
    /// register/login step.
    func resolvePrfOutput(ceremonyPrf: PrfOutput?, credentialId: Data, salt: Data) async throws -> PrfOutput {
        if let ceremonyPrf { return ceremonyPrf }
        return try await authProvider.getPrfOutput(credentialId: credentialId, salt: salt)
    }

    /// Recovers the `PrfKeyInfo` entry `credentialId` was registered with
    /// from the account's own server-synced `privateData` container, then
    /// spends one more authenticator ceremony to get the real PRF output for
    /// it.
    ///
    /// Used by `login()`'s cache-miss branch, after `performPasskeyAssertion`
    /// returns a nil `prfOutput`/`prfSalt` (see that struct's doc comment):
    /// every credential's `PrfKeyInfo` entry in `privateData` carries the
    /// exact `prfSalt`/`hkdfSalt`/`hkdfInfo` it was registered with, keyed by
    /// `credentialId` - recoverable even when the local account cache never
    /// saw this registration at all (reinstall, cleared app data, device
    /// migration). The passkey itself is unaffected by any of that; this is
    /// recovery, not re-registration, and it's why `JweKeystore.unlock`
    /// threads the real salt into a brand-new container's own `PrfKeyInfo`
    /// rather than a disconnected random one - without that, there would be
    /// nothing here to recover.
    ///
    /// - Throws: `SirosError.wallet` with the same user-facing message either
    ///   when no matching `PrfKeyInfo` entry exists in `privateData` (this
    ///   passkey isn't one this account's container actually knows), or when
    ///   the authenticator's ceremony with the recovered salt fails for any
    ///   reason (no PRF support, cancellation, etc.) - both come down to the
    ///   same outcome for the user: the wallet data cannot be decrypted.
    func recoverPrfFromPrivateData(
        credentialId: Data,
        privateData: Data
    ) async throws -> RecoveredPrf {
        let prfKeyInfo = try recoverPrfKeyInfo(credentialId: credentialId, from: privateData)
        do {
            let prfOutput = try await authProvider.getPrfOutput(credentialId: credentialId, salt: prfKeyInfo.prfSalt)
            return RecoveredPrf(
                prfOutput: prfOutput, prfSalt: prfKeyInfo.prfSalt,
                hkdfSalt: prfKeyInfo.hkdfSalt, hkdfInfo: prfKeyInfo.hkdfInfo
            )
        } catch {
            throw SirosError.wallet(
                message: "PRF not supported by authenticator — cannot decrypt wallet data",
                underlying: error
            )
        }
    }

    /// The pure lookup half of `recoverPrfFromPrivateData` - parses
    /// `privateData` and finds the `PrfKeyInfo` entry for `credentialId`, with
    /// no authenticator ceremony involved. Split out so it's directly
    /// testable without the network/ceremony seams `recoverPrfFromPrivateData`
    /// needs - see `SirosWalletPasskeyAssertionTests`.
    func recoverPrfKeyInfo(credentialId: Data, from privateData: Data) throws -> PrfKeyInfo {
        let container: ContainerData
        do {
            container = try EncryptedContainer.parse(privateData)
        } catch {
            throw SirosError.wallet(
                message: "PRF not supported by authenticator — cannot decrypt wallet data",
                underlying: error
            )
        }
        guard let prfKeyInfo = container.prfKeys.first(where: { $0.credentialId == credentialId }) else {
            throw SirosError.wallet(message: "PRF not supported by authenticator — cannot decrypt wallet data")
        }
        return prfKeyInfo
    }

    /// `login()`'s own PRF/HKDF resolution, extracted so the caller stays
    /// readable: either trusts `assertion`'s own resolved values (the normal
    /// case - `hkdfSalt`/`hkdfInfo` come from the session store, then the
    /// confirmed account's registry entry, then fresh random values for a
    /// first login on this install), or - when the local account cache
    /// didn't know this credential at all, see `PasskeyAssertion.prfOutput`'s
    /// doc comment - recovers all four from `privateData` instead.
    ///
    /// - Parameter cachedAccount: the registry entry for the account the
    ///   server just confirmed this login is for (not merely whichever
    ///   account `assertion.cachedAccount` names - that may be a different
    ///   account entirely in the recovery case).
    /// - Returns: `recoveredSalt` is non-nil exactly when recovery happened,
    ///   so the caller knows to heal the account cache afterward.
    func resolveLoginPrf(
        assertion: PasskeyAssertion,
        privateData: Data,
        cachedAccount: CachedAccount?
    ) async throws -> LoginPrfResolution {
        if let knownPrfOutput = assertion.prfOutput, let knownPrfSalt = assertion.prfSalt {
            let hkdfSalt = sessionStore.hkdfSalt.flatMap { Self.b64Decode($0) }
                ?? cachedAccount.flatMap { Self.b64Decode($0.hkdfSalt) }
                ?? Self.randomBytes(32)
            let hkdfInfo = sessionStore.hkdfInfo.flatMap { Self.b64Decode($0) }
                ?? cachedAccount.flatMap { Self.b64Decode($0.hkdfInfo) }
                ?? Data(Self.hkdfInfo.utf8)
            return LoginPrfResolution(
                prfOutput: knownPrfOutput, prfSalt: knownPrfSalt,
                hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo, recoveredSalt: nil
            )
        }
        // The recovered values are this credential's own real
        // registration-time salts - not a guess - so they take priority over
        // whatever `sessionStore`/`cachedAccount` hold (stale, or simply
        // absent on a device that never completed a normal login for this
        // account).
        let recovered = try await recoverPrfFromPrivateData(
            credentialId: assertion.credentialId, privateData: privateData
        )
        return LoginPrfResolution(
            prfOutput: recovered.prfOutput, prfSalt: recovered.prfSalt,
            hkdfSalt: recovered.hkdfSalt, hkdfInfo: recovered.hkdfInfo, recoveredSalt: recovered.prfSalt
        )
    }

    /// Session/account bookkeeping once `login()`'s keystore unlock has
    /// actually succeeded: records which credential/salts this installation
    /// logs in with (`generateWIA` needs `sessionStore.credentialId` to bind
    /// the wallet instance to it, SID-AUTH-06), and - when this login
    /// recovered its PRF salt from `privateData` (`recoveredSalt` non-nil) -
    /// heals the account cache via `healAccountCache` so the next login for
    /// this account is a normal one-tap match again.
    func recordSuccessfulLogin(
        accountId: String,
        session: LoginFinishResult,
        assertion: PasskeyAssertion,
        prfSaltBytes: Data,
        hkdfSalt: Data,
        hkdfInfo: Data,
        recoveredSalt: Data?
    ) {
        accountRegistry.activeAccountId = accountId
        sessionStore.userId = session.uuid
        sessionStore.displayName = session.displayName
        sessionStore.tenantId = config.tenantId
        if let credentialId = assertion.credential["id"] as? String {
            sessionStore.credentialId = credentialId
        }
        sessionStore.prfSalt = Self.b64Encode(prfSaltBytes)
        sessionStore.hkdfSalt = Self.b64Encode(hkdfSalt)
        sessionStore.hkdfInfo = Self.b64Encode(hkdfInfo)

        if let recoveredSalt {
            healAccountCache(
                accountId: accountId,
                userId: session.uuid,
                displayName: session.displayName,
                credentialId: assertion.credentialId,
                prfSalt: recoveredSalt,
                hkdfSalt: hkdfSalt,
                hkdfInfo: hkdfInfo
            )
        }
    }

    /// `unlockKeystore()`'s own PRF/HKDF resolution - the resume-after-logout
    /// counterpart to `resolveLoginPrf`. Simpler: `encryptedContainer` here is
    /// always `storedContainer` (this account was already resumed from a
    /// prior session) and the known-salt branch has nothing to fall back to
    /// (an absent `sessionStore.hkdfSalt` is a genuine error, not a case for
    /// a fresh random value, since this isn't a first-time setup). The
    /// recovery branch needs no extra network round trip: `storedContainer`
    /// is already in hand.
    func resolveUnlockKeystorePrf(
        assertion: PasskeyAssertion,
        storedContainer: Data
    ) async throws -> UnlockKeystorePrfResolution {
        if let knownPrfOutput = assertion.prfOutput {
            guard let hkdfSalt = sessionStore.hkdfSalt.flatMap({ Self.b64Decode($0) }) else {
                throw SirosError.keystore(message: "Missing HKDF salt")
            }
            let hkdfInfo = sessionStore.hkdfInfo.flatMap { Self.b64Decode($0) } ?? Data(Self.hkdfInfo.utf8)
            return UnlockKeystorePrfResolution(prfOutput: knownPrfOutput, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo, recoveredSalt: nil)
        }
        let recovered = try await recoverPrfFromPrivateData(
            credentialId: assertion.credentialId, privateData: storedContainer
        )
        return UnlockKeystorePrfResolution(
            prfOutput: recovered.prfOutput, hkdfSalt: recovered.hkdfSalt,
            hkdfInfo: recovered.hkdfInfo, recoveredSalt: recovered.prfSalt
        )
    }

    /// Heals the local account cache after a successful PRF-salt recovery
    /// (`recoverPrfFromPrivateData`), so the *next* login for this account is
    /// a normal one-tap match again instead of repeating the recovery
    /// ceremony every time. Upserts a `CachedAccount`/`CachedPasskey` entry
    /// for `credentialId` with the salt that was actually recovered - the
    /// real value this credential needs, not a guess - alongside whatever
    /// else the registry entry already has.
    func healAccountCache(
        accountId: String,
        userId: String,
        displayName: String?,
        credentialId: Data,
        prfSalt: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) {
        let credIdStr = Self.b64UrlEncode(credentialId)
        let healedPasskey = CachedPasskey(credentialId: credIdStr, prfSalt: Self.b64Encode(prfSalt))
        let existing = accountRegistry.findAccount(accountId: accountId)
        var account = existing ?? CachedAccount(
            userId: userId,
            tenantId: config.tenantId,
            displayName: displayName ?? "",
            backendUrl: config.backendUrl,
            hkdfSalt: Self.b64Encode(hkdfSalt),
            hkdfInfo: Self.b64Encode(hkdfInfo)
        )
        account.passkeys = (existing?.passkeys.filter { $0.credentialId != credIdStr } ?? []) + [healedPasskey]
        accountRegistry.upsertAccount(account)
    }
}
