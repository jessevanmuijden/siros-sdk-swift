// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosWallet

/// Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319/#340) at the
/// facade: the blocked state and which of its three refusals forgets the
/// cached account, the once-only re-login guard, `isThisDevice`.
///
/// Uses a stub `KeystoreManager` (like `SirosWalletRegistryUrlTests`) so it
/// runs identically on Linux and Apple platforms, without CryptoKit.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

private final class StubKeystoreManager: KeystoreManager, @unchecked Sendable {
    var isUnlocked: Bool { true }
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { "key" }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "proof" }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
    func exportEncryptedContainer() async throws -> Data { Data() }
    func listKeys() -> [KeyInfo] { [] }
    func saveCredential(id: Int64, json: String) async throws {}
    func getCredential(id: Int64) async throws -> String? { nil }
    func getAllCredentials() async throws -> [Int64: String] { [:] }
    func deleteCredential(id: Int64) async throws {}
    func clearCredentials() async throws {}
    func savePresentationRecord(id: Int64, json: String) async throws {}
    func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
    func clearPresentationRecords() async throws {}
    func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    // The WIA-generation path signs a PoP with the instance key; the protocol's
    // default implementation throws, which would make
    // `ensureWalletInstanceAttestation()` bail before ever reaching the
    // request under test.
    func generateKeyProof(
        keyId: String, typ: String, issuer: String, audience: String, extraClaims: [String: String]
    ) async throws -> String { "pop.jwt" }
}

/// Minimal queued-response HTTP stub (the `SirosAuthTests` MockHttpServer
/// lives in another test target).
private final class StubHttpServer: @unchecked Sendable {
    private let lock = NSLock()
    private var responses: [Result<Data, Error>] = []
    private(set) var requestCount = 0
    /// Parsed JSON body of each request, in order.
    private(set) var bodies: [[String: Any]?] = []

    func enqueue(_ json: String) {
        lock.lock(); responses.append(.success(Data(json.utf8))); lock.unlock()
    }

    func enqueueFailure(code: Int, body: String) {
        lock.lock()
        responses.append(.failure(SirosError.backendApi(code: code, message: "API request failed: \(code)", body: body)))
        lock.unlock()
    }

    struct Exhausted: Error {}

    var httpFunction: @Sendable (String, URL, [String: String], Data?) async throws -> Data {
        { [weak self] _, _, _, body in
            guard let self else { throw Exhausted() }
            self.lock.lock()
            self.requestCount += 1
            self.bodies.append(body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] })
            guard !self.responses.isEmpty else { self.lock.unlock(); throw Exhausted() }
            let next = self.responses.removeFirst()
            self.lock.unlock()
            return try next.get()
        }
    }
}

/// Registry storage that puts the active-account id straight back whenever it
/// is deleted, once `restoring` is on - the deterministic stand-in for a login
/// started concurrently while the blocked path awaits `clearTokenCache()`.
private final class ActiveIdRestoringStorage: AccountRegistryStorage, @unchecked Sendable {
    /// `AccountRegistry.Keys.active`, which is private to it.
    private static let activeKey = "siros_active_account_id"
    private let inner = InMemoryAccountRegistryStorage()
    private let restoreTo: String
    var restoring = false

    init(restoreTo: String) { self.restoreTo = restoreTo }

    func readData(_ key: String) -> Data? { inner.readData(key) }
    func writeData(_ key: String, _ data: Data) { inner.writeData(key, data) }
    func deleteAll() { inner.deleteAll() }
    func deleteKey(_ key: String) {
        inner.deleteKey(key)
        if restoring, key == Self.activeKey { inner.writeData(key, Data(restoreTo.utf8)) }
    }
}

/// Records the two lifecycle callbacks under test.
private final class RecordingListener: WalletEventListener, @unchecked Sendable {
    var reauthenticationRequired = false
    var blocked: (reason: SirosError.WalletLifecycleRefusal, message: String?)?
    func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] { [] }
    func onReauthenticationRequired() { reauthenticationRequired = true }
    func onWalletLifecycleBlocked(reason: SirosError.WalletLifecycleRefusal, message: String?) {
        blocked = (reason, message)
    }
}

final class SirosWalletLifecycleTests: XCTestCase {

    private func makeWallet(
        registry: AccountRegistry = AccountRegistry.inMemory(),
        sessionStore: SessionStoreProtocol = InMemorySessionStore()
    ) -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://wallet.example.invalid")
        let wallet = SirosWallet(
            config: config,
            authProvider: StubAuthProvider(),
            sessionStore: sessionStore,
            keystore: StubKeystoreManager(),
            accountRegistry: registry
        )
        XCTAssertNotNil(wallet)
        return wallet!
    }

    private func seededRegistry() -> AccountRegistry {
        let registry = AccountRegistry.inMemory()
        let account = CachedAccount(
            userId: "user-1",
            tenantId: "default",
            displayName: "Alice",
            backendUrl: "https://wallet.example.invalid",
            passkeys: [CachedPasskey(credentialId: "cred-1", prfSalt: "c2FsdA==")]
        )
        registry.upsertAccount(account)
        registry.activeAccountId = account.accountId
        return registry
    }

    /// header.{claims}.sig - just enough for `CredentialUtils.parseJwtPayload`.
    private func fakeWiaJwt(exp: Int, jkt: String) -> String {
        let json = try! JSONSerialization.data(withJSONObject: ["exp": exp, "cnf": ["jkt": jkt]])
        let b64 = json.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "eyJ.\(b64).sig"
    }

    private func seedWia(_ wallet: SirosWallet, jkt: String) {
        let exp = Int(Date().timeIntervalSince1970) + 3600
        wallet.cachedWia = fakeWiaJwt(exp: exp, jkt: jkt)
        wallet.cachedWiaExpiresAt = exp
    }

    // MARK: - The blocked state

    /// A login refused with `403 WALLET_SUSPENDED` is a state, not an error:
    /// the instance can be reactivated from another device, so the cached
    /// account stays on the login screen and nothing local is lost.
    func testSuspendedRefusalKeepsTheCachedAccount()async {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let listener = RecordingListener()
        wallet.setEventListener(listener)
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        let handled = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403,
            message: "AS request failed: 403",
            body: #"{"error":"WALLET_SUSPENDED","message":"This device is suspended"}"#
        ), forAccount: "default:user-1")

        XCTAssertTrue(handled)
        guard case let .lifecycleBlocked(reason, message, accounts) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked, got \(wallet.state)")
        }
        XCTAssertEqual(reason, .suspended)
        XCTAssertEqual(message, "This device is suspended")
        XCTAssertEqual(accounts.count, 1, "a suspended instance keeps its cached account")
        XCTAssertEqual(registry.listLoginableAccounts().count, 1)
        XCTAssertEqual(listener.blocked?.reason, .suspended)
        XCTAssertEqual(listener.blocked?.message, "This device is suspended")
    }

    /// `WALLET_REVOKED` at scope `instance` ends this device and nothing else
    /// (the EUDI wallet-unit lifecycle, which SIROS adopts exactly): the
    /// user's other devices keep working, so the cached account stays -
    /// forgetting it here would destroy the other passkeys that still work.
    func testRevokedInstanceRefusalKeepsTheCachedAccount()async {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        let handled = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403,
            message: "AS request failed: 403",
            body: #"{"error":"WALLET_REVOKED","scope":"instance","message":"This device was removed"}"#
        ), forAccount: "default:user-1")

        XCTAssertTrue(handled)
        guard case let .lifecycleBlocked(reason, message, accounts) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked, got \(wallet.state)")
        }
        XCTAssertEqual(reason, .revoked)
        XCTAssertEqual(message, "This device was removed")
        XCTAssertEqual(accounts.count, 1)
        XCTAssertEqual(
            registry.listLoginableAccounts().count, 1,
            "the account survives: a revoked instance is not a deactivated wallet"
        )
    }

    /// `WALLET_REVOKED` with no `scope` at all - every deployment until
    /// go-wallet-backend#340 ships. It MUST resolve to the per-instance case
    /// and keep the account, which is exactly the behaviour that predates
    /// `scope`; a `message` that reads like a deactivation changes nothing.
    func testRevokedRefusalWithoutScopeKeepsTheCachedAccount()async {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        let handled = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403,
            message: "AS request failed: 403",
            body: #"{"error":"WALLET_REVOKED","message":"This wallet was deactivated and its data erased"}"#
        ), forAccount: "default:user-1")

        XCTAssertTrue(handled)
        guard case let .lifecycleBlocked(reason, _, accounts) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked, got \(wallet.state)")
        }
        XCTAssertEqual(reason, .revoked, "a scope-less WALLET_REVOKED is per-instance, never guessed from the message")
        XCTAssertEqual(accounts.count, 1)
        XCTAssertEqual(registry.listLoginableAccounts().count, 1)
    }

    /// A `scope` this SDK does not know is a backend newer than it; falling
    /// back to the per-instance case is the only safe reading.
    func testRevokedRefusalWithUnrecognisedScopeKeepsTheCachedAccount()async {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        _ = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403,
            message: "AS request failed: 403",
            body: #"{"error":"WALLET_REVOKED","scope":"tenant","message":"x"}"#
        ), forAccount: "default:user-1")

        guard case let .lifecycleBlocked(reason, _, accounts) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked, got \(wallet.state)")
        }
        XCTAssertEqual(reason, .revoked)
        XCTAssertEqual(accounts.count, 1)
        XCTAssertEqual(registry.listLoginableAccounts().count, 1)
    }

    /// `WALLET_REVOKED` at scope `wallet` is the one refusal that is terminal
    /// for the whole wallet: every instance is revoked and the data erased
    /// server-side, so the cached account decrypts a vault that no longer
    /// exists. The SDK forgets it, as `forgetAccount(accountId:)` does,
    /// and the blocked state it publishes no longer lists the account.
    func testDeactivatedRefusalForgetsTheCachedAccount()async {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let listener = RecordingListener()
        wallet.setEventListener(listener)
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        let handled = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403,
            message: "AS request failed: 403",
            body: #"{"error":"WALLET_REVOKED","scope":"wallet","message":"This wallet was deactivated"}"#
        ), forAccount: "default:user-1")

        XCTAssertTrue(handled)
        guard case let .lifecycleBlocked(reason, message, accounts) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked, got \(wallet.state)")
        }
        XCTAssertEqual(reason, .deactivated)
        XCTAssertEqual(message, "This wallet was deactivated")
        XCTAssertEqual(accounts.count, 0, "a deactivated wallet leaves nothing to log back in to")
        XCTAssertEqual(
            registry.listLoginableAccounts().count, 0,
            "the cached account is forgotten, exactly as forgetAccount(accountId:) forgets it"
        )
        XCTAssertNil(registry.activeAccountId)
        XCTAssertEqual(listener.blocked?.reason, .deactivated)
    }

    /// A suspended instance is reactivated from another device and the app
    /// retries `login()`, which reuses the same AS session cookie. An
    /// unawaited `DELETE /auth/session` scheduled by the block could land
    /// after that retry's `loginFinish` and invalidate the session it had just
    /// established - so the blocked path tears down locally and never asks the
    /// AS to end a session the backend has already refused.
    func testALifecycleBlockDoesNotEndTheServerSession() async throws {
        let wallet = makeWallet(registry: seededRegistry())
        let server = RecordingAuthServer()
        wallet.authServerClient = server.client
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        _ = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_SUSPENDED"}"#
        ), forAccount: "default:user-1")
        // Whatever the blocked path scheduled has had every chance to run.
        try await Task.sleep(nanoseconds: 100_000_000)

        XCTAssertEqual(
            server.deletedSessions, 0,
            "no DELETE /auth/session may race the retry the user is about to make"
        )

        // The contrast: an explicit logout does end the server session.
        wallet.logout()
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(server.deletedSessions, 1)
    }

    /// `login()` is refused by `loginFinish`, before it moves the registry's
    /// active account (that only happens once the keystore unlock succeeds), so
    /// on a login from the picker after a logout there is no active id to
    /// forget. It names the account the passkey resolved to instead
    /// (`.resolved`), which the registry can never override.
    func testADeactivationDuringLoginForgetsTheAccountTheLoginWasFor() async {
        let registry = seededRegistry()
        // What a logged-out login looks like: the account is cached and
        // loginable, but nothing is active.
        registry.activeAccountId = nil
        let wallet = makeWallet(registry: registry)

        let handled = await wallet.handleLifecycleRefusal(
            SirosError.backendApi(
                code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"wallet"}"#
            ),
            forAccount: "default:user-1"
        )

        XCTAssertTrue(handled)
        XCTAssertEqual(
            registry.listLoginableAccounts().count, 0,
            "the account the refused login was for is forgotten even with no active account"
        )
    }

    /// The candidate must win outright: forgetting whatever happened to be
    /// active instead would drop the wrong user's passkeys.
    func testADeactivationDuringLoginNeverForgetsTheOtherActiveAccount() async {
        let registry = seededRegistry()  // active: default:user-1
        let other = CachedAccount(
            userId: "user-2",
            tenantId: "default",
            displayName: "Bob",
            backendUrl: "https://wallet.example.invalid",
            passkeys: [CachedPasskey(credentialId: "cred-2", prfSalt: "c2FsdA==")]
        )
        registry.upsertAccount(other)
        let wallet = makeWallet(registry: registry)

        _ = await wallet.handleLifecycleRefusal(
            SirosError.backendApi(
                code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"wallet"}"#
            ),
            forAccount: other.accountId
        )

        let left = registry.listLoginableAccounts().map(\.userId)
        XCTAssertEqual(left, ["user-1"], "only the account the refusal was about is forgotten")
    }

    /// `login()` can complete with a platform passkey that has no registry
    /// entry (or one belonging to another deployment, which it refuses to
    /// accept as the owner). It then knows nothing, and knowing nothing must
    /// mean forgetting nothing: falling back to whatever account happens to be
    /// active would destroy a working wallet that the refusal was not about.
    /// A stale entry on the login screen is the cheaper mistake.
    func testADeactivationDuringLoginWithAnUnknownPasskeyForgetsNothing() async {
        let registry = seededRegistry()  // active: default:user-1
        let wallet = makeWallet(registry: registry)

        let handled = await wallet.handleLifecycleRefusal(
            SirosError.backendApi(
                code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"wallet"}"#
            ),
            forAccount: nil
        )

        XCTAssertTrue(handled, "the refusal is still handled - only the forgetting is skipped")
        guard case .lifecycleBlocked(.deactivated, _, _) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked(.deactivated), got \(wallet.state)")
        }
        XCTAssertEqual(
            registry.listLoginableAccounts().count, 1,
            "an unidentified deactivation must not forget the account that was active"
        )
    }

    /// The passkey's owner is resolved against the scope the ceremony offered
    /// its candidates under (this tenant, this backend) - not by taking the
    /// first match anywhere in the registry and filtering afterwards, which an
    /// out-of-scope duplicate arriving first would defeat. Only an owner in
    /// that scope may name the account a deactivation forgets.
    func testTheLoginRefusalSubjectOnlyAcceptsAnOwnerFromThisDeployment() {
        // Registry order matters: the out-of-scope duplicate is inserted first,
        // which is exactly what a first-match-then-filter lookup falls for.
        let registry = AccountRegistry.inMemory()
        registry.upsertAccount(account(userId: "user-elsewhere", backendUrl: "https://other.example.invalid"))
        registry.upsertAccount(account(userId: "user-othertenant", tenantId: "other"))
        registry.upsertAccount(account(userId: "user-1"))
        let wallet = makeWallet(registry: registry)  // tenant "default", https://wallet.example.invalid

        XCTAssertEqual(
            wallet.accountId(owningInScope: Data("cred".utf8)),
            "default:user-1",
            "the in-scope owner, even though two out-of-scope duplicates precede it"
        )
        XCTAssertEqual(
            wallet.accountId(owningInScope: Data("nobodys-credential".utf8)),
            nil,
            "a platform passkey with no registry entry identifies nothing"
        )
    }

    /// A registry that somehow holds the same credential twice *in scope*
    /// names no one account, and the destructive path must read that as
    /// "unknown" rather than pick one.
    func testAnAmbiguousOwnerIdentifiesNothing() {
        let registry = AccountRegistry.inMemory()
        registry.upsertAccount(account(userId: "user-1"))
        registry.upsertAccount(account(userId: "user-2"))
        let wallet = makeWallet(registry: registry)

        XCTAssertNil(wallet.accountId(owningInScope: Data("cred".utf8)))
    }

    /// One account holding the shared credential id `cred` (base64url of
    /// "cred" is "Y3JlZA"), in this deployment unless told otherwise.
    private func account(
        userId: String,
        tenantId: String = "default",
        backendUrl: String = "https://wallet.example.invalid"
    ) -> CachedAccount {
        CachedAccount(
            userId: userId,
            tenantId: tenantId,
            displayName: userId,
            backendUrl: backendUrl,
            passkeys: [CachedPasskey(credentialId: "Y3JlZA", prfSalt: "c2FsdA==")]
        )
    }

    /// The account to forget comes from the caller alone. Whatever the registry
    /// calls active at refusal time is never consulted: the refusal arrives
    /// after async work, and a login landing in between would make the registry
    /// name the replacement account.
    func testTheAccountToForgetComesFromTheCallerNotTheRegistry() async {
        let registry = seededRegistry()  // active: default:user-1
        let wallet = makeWallet(registry: registry)

        _ = await wallet.handleLifecycleRefusal(
            SirosError.backendApi(
                code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"wallet"}"#
            ),
            forAccount: "default:user-9"  // an account the registry does not hold
        )

        XCTAssertEqual(
            registry.listLoginableAccounts().map(\.userId), ["user-1"],
            "the active account is not the one named, so it survives"
        )
    }

    /// Forgetting the account on a deactivation must not drag in `logout()`'s
    /// `DELETE /auth/session`: the blocked path deliberately never ends the
    /// server session, and the account-forgetting path only avoids `logout()`
    /// because `endSessionLocally()` has already cleared the active id. If the
    /// order ever flips, this fires.
    func testADeactivationBlockStillDoesNotEndTheServerSession() async throws {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let server = RecordingAuthServer()
        wallet.authServerClient = server.client
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        _ = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"wallet"}"#
        ), forAccount: "default:user-1")
        try await Task.sleep(nanoseconds: 100_000_000)

        XCTAssertEqual(server.deletedSessions, 0)
        XCTAssertEqual(registry.listLoginableAccounts().count, 0, "the account is still forgotten")
    }

    /// The blocked path forgets the account *after* awaiting
    /// `clearTokenCache()`, so it cannot assume the active account id is still
    /// the nil `endSessionLocally()` left - a login started concurrently can
    /// have put it back. Removing through `forgetAccount` would then take its
    /// `logout()` branch and send the `DELETE /auth/session` this path exists
    /// to avoid, killing the replacement session. Simulated here by restoring
    /// the active id from the stub AS the moment the token cache is cleared.
    func testADeactivationDoesNotDeleteTheSessionEvenIfTheActiveIdComesBack() async throws {
        let storage = ActiveIdRestoringStorage(restoreTo: "default:user-1")
        let registry = AccountRegistry(storage: storage)
        registry.upsertAccount(account(userId: "user-1"))
        registry.activeAccountId = "default:user-1"
        storage.restoring = true
        let wallet = makeWallet(registry: registry)
        let server = RecordingAuthServer()
        wallet.authServerClient = server.client
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        _ = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 403, message: "", body: #"{"error":"WALLET_REVOKED","scope":"wallet"}"#
        ), forAccount: "default:user-1")
        try await Task.sleep(nanoseconds: 100_000_000)

        XCTAssertEqual(
            server.deletedSessions, 0,
            "a re-appearing active id must not turn the removal into a remote logout"
        )
        XCTAssertEqual(registry.listLoginableAccounts().count, 0, "the account is still forgotten")
    }

    /// `fetchPrivateData()` is the first wallet-API call a login makes, and it
    /// tolerates every failure so a transient one cannot take down a login that
    /// can still unlock from the session store. A lifecycle refusal is the
    /// exception: swallowed, `403 WALLET_REVOKED` became an empty container and
    /// then a keystore-unlock error, and the wallet never reached
    /// `.lifecycleBlocked` - nor forgot a deactivated wallet's account.
    func testFetchPrivateDataRethrowsALifecycleRefusalOnly() async throws {
        let wallet = makeWallet(registry: seededRegistry())

        let refusing = StubHttpServer()
        refusing.enqueueFailure(code: 403, body: #"{"error":"WALLET_REVOKED","scope":"wallet","message":"gone"}"#)
        wallet.apiClient = Self.apiClient(over: refusing)
        do {
            _ = try await wallet.fetchPrivateData()
            XCTFail("the refusal must reach the caller's handleLifecycleRefusal")
        } catch {
            XCTAssertEqual((error as? SirosError)?.walletLifecycleRefusal, .deactivated)
        }

        let broken = StubHttpServer()
        broken.enqueueFailure(code: 500, body: "upstream is having a day")
        wallet.apiClient = Self.apiClient(over: broken)
        let data = try await wallet.fetchPrivateData()
        XCTAssertEqual(data, Data(), "every other failure stays tolerated")
    }

    private static func apiClient(over server: StubHttpServer) -> BackendApiClient {
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFunction)
        client.setAppToken("t")
        return client
    }

    /// Counts `DELETE /auth/session` calls.
    private final class RecordingAuthServer: @unchecked Sendable {
        private let lock = NSLock()
        private var deletes = 0
        var deletedSessions: Int { lock.lock(); defer { lock.unlock() }; return deletes }

        lazy var client: AuthServerClient = AuthServerClient(
            baseUrl: "https://wallet.example.invalid",
            tenantId: "default"
        ) { [self] method, url, _, _ in
            if method == "DELETE", url.path.hasSuffix("/auth/session") {
                self.lock.lock(); self.deletes += 1; self.lock.unlock()
            }
            return Data("{}".utf8)
        }
    }

    /// Everything that is not one of the two lifecycle codes keeps the
    /// existing error path, untouched.
    func testOtherFailuresAreNotLifecycleRefusals()async {
        let wallet = makeWallet(registry: seededRegistry())

        let plain401 = await wallet.handleLifecycleRefusal(SirosError.backendApi(
            code: 401, message: "AS request failed: 401", body: #"{"error":"auth_failed"}"#
        ), forAccount: "default:user-1")
        XCTAssertFalse(plain401)
        let offline = await wallet.handleLifecycleRefusal(SirosError.network(message: "offline"), forAccount: "default:user-1")
        XCTAssertFalse(offline)
        if case .lifecycleBlocked = wallet.state {
            XCTFail("a non-lifecycle failure must not enter the blocked state")
        }
    }

    // MARK: - One re-login, never a loop

    /// Once per session, not once per call. Requests issued before a cut-off
    /// complete long after it and each of their 401s re-enters the signal, so
    /// releasing the in-progress flag must not re-open the door for the same
    /// session - only a new session may be cut off again.
    func testSelfDrivenReloginHappensOncePerSession() {
        let wallet = makeWallet()
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        XCTAssertNotNil(wallet.beginSelfDrivenRelogin())
        XCTAssertNil(wallet.beginSelfDrivenRelogin(), "a second signal must not start another re-login")
        wallet.endSelfDrivenRelogin()
        XCTAssertNil(
            wallet.beginSelfDrivenRelogin(),
            "a late 401 from the session already handled must not start a second re-login"
        )

        // A new session - a successful login bumps the generation - may be cut
        // off in its own right.
        wallet.bumpSessionGeneration()
        XCTAssertNotNil(wallet.beginSelfDrivenRelogin(), "a cut-off on the new session is handled")
    }

    /// There is nothing to replace once the session is gone, and a silent
    /// WebAuthn prompt after an explicit logout would be the wrong answer.
    func testNoSelfDrivenReloginWithoutASessionToReplace() {
        let wallet = makeWallet()

        wallet.setState(.disconnected())
        XCTAssertNil(wallet.beginSelfDrivenRelogin())
        wallet.bumpSessionGeneration()
        wallet.setState(.error(message: "boom"))
        XCTAssertNil(wallet.beginSelfDrivenRelogin())
        wallet.bumpSessionGeneration()
        wallet.setState(.lifecycleBlocked(reason: .suspended, message: nil))
        XCTAssertNil(wallet.beginSelfDrivenRelogin())
    }

    /// `destroy()` leaves the state alone - a destroyed wallet is not a
    /// logged-out one - so the generation bump on its own would still let a
    /// reauthentication signal from a task still unwinding pass the guard and
    /// log back in after the host tore the wallet down.
    func testNoSelfDrivenReloginAfterDestroy() {
        let wallet = makeWallet()
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))
        wallet.destroy()

        XCTAssertNil(wallet.beginSelfDrivenRelogin())
    }

    /// `.connecting` is also where the initial `login()` and `resumeSession()`
    /// sit before their own setup finishes, and a 401 from `/auth/token` fires
    /// the signal immediately - a second ceremony started underneath the first
    /// would race its state, its API client and its keystore.
    func testConnectingIsNotAReplaceableSession() {
        let wallet = makeWallet()
        wallet.setState(.connecting)

        XCTAssertNil(wallet.beginSelfDrivenRelogin())
    }

    /// The teardown a re-login performs awaits the old session's WMP peer and
    /// token caches; a logout landing in that window must abandon the attempt
    /// rather than resurrect the session the user just ended.
    func testReloginAbandonsWhenTheSessionItReplacedIsAlreadyGone() async throws {
        let wallet = makeWallet(registry: seededRegistry())
        let (asClient, loginAttempts) = refusingAuthServer("WALLET_SUSPENDED", message: "suspended")
        wallet.authServerClient = asClient
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))
        let generation = try XCTUnwrap(wallet.beginSelfDrivenRelogin())

        // What logout()/destroy() do to the generation, landing while the
        // re-login is between claiming the signal and reaching login().
        wallet.bumpSessionGeneration()
        await wallet.reloginAfterCutOff(replacing: generation)
        wallet.endSelfDrivenRelogin()

        XCTAssertEqual(loginAttempts(), 0, "no login is attempted for a session that is already gone")
    }

    /// Regression (review finding): `reloginAfterCutOff` performed its own,
    /// separate teardown that skipped `clearCredentialStatusCaches()`
    /// entirely - unlike `endSessionLocally()`'s teardown, which already
    /// cleared it. A cut-off's own likely CAUSE is a revocation, so a
    /// self-driven re-login reusing a prior session's cached status/Status
    /// List Token would be the worst possible time to serve a stale one.
    ///
    /// Forces the SAME early-abandon path
    /// `testReloginAbandonsWhenTheSessionItReplacedIsAlreadyGone` does
    /// (rather than letting the re-login reach `login()`) so this test
    /// actually isolates `reloginAfterCutOff`'s OWN direct teardown: a
    /// first attempt using `refusingAuthServer` to let `login()` fail
    /// passed even without the fix, because that failure routes through
    /// `handleLifecycleRefusal` -> `endSessionLocally()`, which already
    /// clears both caches on an entirely different path - proving nothing
    /// about the teardown this finding is actually about. The clearing
    /// happens before the abandon check, so it still runs here.
    func testReloginAfterCutOffClearsTheCredentialStatusCaches() async throws {
        let wallet = makeWallet(registry: seededRegistry())
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))
        let generation = try XCTUnwrap(wallet.beginSelfDrivenRelogin())

        wallet.credentialStatusCache.set(
            42, .revoked,
            generation: wallet.credentialStatusCache.currentGeneration(),
            idGeneration: wallet.credentialStatusCache.currentIdGeneration(42)
        )
        XCTAssertEqual(wallet.cachedCredentialStatus(of: 42), .revoked, "sanity: the stale entry is actually there")

        // What logout()/destroy() do to the generation, landing while the
        // re-login is between claiming the signal and reaching login() -
        // same technique as testReloginAbandonsWhenTheSessionItReplacedIsAlreadyGone,
        // which this borrows specifically to make login() unreachable.
        wallet.bumpSessionGeneration()
        await wallet.reloginAfterCutOff(replacing: generation)
        wallet.endSelfDrivenRelogin()

        XCTAssertEqual(
            wallet.cachedCredentialStatus(of: 42), .valid,
            "a cut-off-triggered re-login must not leave the superseded session's cached status behind"
        )
    }

    // MARK: - This device

    /// The facade marks the row that is this installation by comparing the
    /// backend's instance ids to the instance-key thumbprint it already sends
    /// as `wallet_instance_id` (the WIA's `cnf.jkt`).
    func testListWalletInstancesMarksThisDeviceFromTheInstanceKeyThumbprint() async throws {
        let wallet = makeWallet()
        seedWia(wallet, jkt: "jkt-self")
        let server = StubHttpServer()
        server.enqueue(#"{"instances":[{"id":"jkt-self","status":"active"},{"id":"jkt-other","status":"suspended"}]}"#)
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFunction)
        client.setAppToken("t")
        wallet.apiClient = client

        let instances = try await wallet.listWalletInstances()

        XCTAssertEqual(wallet.thisInstanceId, "jkt-self")
        XCTAssertEqual(instances.count, 2)
        XCTAssertTrue(try XCTUnwrap(instances.first { $0.id == "jkt-self" }).isThisDevice)
        XCTAssertFalse(try XCTUnwrap(instances.first { $0.id == "jkt-other" }).isThisDevice)
        // The thumbprint was already known, so no attestation round trip.
        XCTAssertEqual(server.requestCount, 1)
    }

    func testThisInstanceIdIsNilWithoutAWia() {
        XCTAssertNil(makeWallet().thisInstanceId)
    }

    // MARK: - The cut-off re-login

    /// An authorization server that refuses every login with one lifecycle
    /// code, and counts how many times it was asked.
    private func refusingAuthServer(
        _ code: String, message: String, scope: String? = nil
    ) -> (AuthServerClient, () -> Int) {
        let counter = Counter()
        let scopeField = scope.map { ",\"scope\":\"\($0)\"" } ?? ""
        let body = "{\"error\":\"\(code)\"\(scopeField),\"message\":\"\(message)\"}"
        let client = AuthServerClient(baseUrl: "https://wallet.example.invalid", tenantId: "default") { _, url, _, _ in
            // Count only the login attempts: `logout()` posts to this same
            // client on its way through the blocked state, and that is not a
            // second attempt at logging in.
            if url.path.hasSuffix("/login/begin") { counter.increment() }
            throw SirosError.backendApi(code: 403, message: "AS request failed: 403", body: body)
        }
        return (client, { counter.value })
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var count = 0
        func increment() { lock.lock(); count += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    }

    /// The token cut-off: after a lifecycle change made elsewhere every
    /// request is refused with 401, the SDK's reauthentication signal fires,
    /// and the SDK itself attempts exactly one login - which the AS refuses
    /// with the lifecycle code. The host's own hook still fires, so apps that
    /// drive their own prompt see no change in ordering.
    func testReauthenticationSignalDrivesOneReloginIntoTheBlockedState() async throws {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let listener = RecordingListener()
        wallet.setEventListener(listener)
        let (asClient, loginAttempts) = refusingAuthServer(
            "WALLET_REVOKED", message: "This device was removed", scope: "instance"
        )
        wallet.authServerClient = asClient
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        wallet.handleReauthenticationRequired()
        // The attempt runs in a detached Task; wait for it to settle.
        try await waitUntil { loginAttempts() == 1 && !wallet.reloginInProgress }

        XCTAssertTrue(listener.reauthenticationRequired, "the host hook still fires")
        XCTAssertEqual(loginAttempts(), 1)
        XCTAssertEqual(listener.blocked?.reason, .revoked)
        guard case .lifecycleBlocked(.revoked, _, _) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked(.revoked), got \(wallet.state)")
        }
        XCTAssertEqual(
            registry.listLoginableAccounts().count, 1,
            "the account survives a revoked instance: it is one device, not the whole wallet"
        )
    }

    /// The same cut-off path, but the wallet itself was deactivated: the AS
    /// answers the SDK's one re-login with `WALLET_REVOKED` at scope `wallet`,
    /// and the account that can no longer be logged into anywhere is dropped
    /// from the login screen. End to end through `handleReauthenticationRequired`,
    /// not just the refusal helper, so the whole chain is covered.
    func testReauthenticationSignalIntoADeactivatedWalletForgetsTheAccount() async throws {
        let registry = seededRegistry()
        let wallet = makeWallet(registry: registry)
        let listener = RecordingListener()
        wallet.setEventListener(listener)
        let (asClient, loginAttempts) = refusingAuthServer(
            "WALLET_REVOKED", message: "This wallet was deactivated", scope: "wallet"
        )
        wallet.authServerClient = asClient
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        wallet.handleReauthenticationRequired()
        try await waitUntil { loginAttempts() == 1 && !wallet.reloginInProgress }

        XCTAssertEqual(listener.blocked?.reason, .deactivated)
        guard case let .lifecycleBlocked(.deactivated, _, accounts) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked(.deactivated), got \(wallet.state)")
        }
        XCTAssertEqual(accounts.count, 0)
        XCTAssertEqual(
            registry.listLoginableAccounts().count, 0,
            "a deactivated wallet cannot be logged into again: its cached account goes"
        )
    }

    /// The contrast with the cut-off re-login above: a login the *user* started
    /// is refused before its passkey ceremony ever completes (the AS refuses
    /// `loginBegin` too). It has identified no account, and the one the
    /// registry still calls active belongs to the session this login was going
    /// to replace - possibly another user - so nothing is forgotten.
    func testAUserDrivenLoginRefusedBeforeTheCeremonyForgetsNothing() async {
        let registry = seededRegistry()  // active: default:user-1
        let wallet = makeWallet(registry: registry)
        let (asClient, _) = refusingAuthServer(
            "WALLET_REVOKED", message: "This wallet was deactivated", scope: "wallet"
        )
        wallet.authServerClient = asClient

        try? await wallet.login()

        guard case .lifecycleBlocked(.deactivated, _, _) = wallet.state else {
            return XCTFail("expected .lifecycleBlocked(.deactivated), got \(wallet.state)")
        }
        XCTAssertEqual(
            registry.listLoginableAccounts().count, 1,
            "a login that never identified an account must not forget the previous session's"
        )
    }

    /// Exactly once, never a loop: the 401s the re-login's own requests may
    /// provoke re-enter the same signal, and must not start a second attempt.
    func testARepeatedReauthenticationSignalDoesNotStartASecondRelogin() async throws {
        let wallet = makeWallet(registry: seededRegistry())
        let (asClient, loginAttempts) = refusingAuthServer("WALLET_SUSPENDED", message: "suspended")
        wallet.authServerClient = asClient
        wallet.setState(.ready(userId: "user-1", displayName: "Alice", credentials: []))

        wallet.handleReauthenticationRequired()
        wallet.handleReauthenticationRequired()
        try await waitUntil { !wallet.reloginInProgress && loginAttempts() >= 1 }

        XCTAssertEqual(loginAttempts(), 1)
    }

    private func waitUntil(
        timeout: TimeInterval = 5,
        _ condition: @escaping () -> Bool
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("condition not met within \(timeout)s")
    }

    // MARK: - The passkey link at WIA generation

    /// A `credential_id` the backend refuses as not the caller's own would, if
    /// the SDK gave up, leave this instance with no attestation at all - and
    /// the first link recorded for an instance wins, so guessing another id
    /// could lock the real passkey out of the per-device gate for good. Retry
    /// once without the link and drop the stale id.
    func testWiaGenerationRetriesWithoutThePasskeyLinkWhenTheBackendRefusesIt() async throws {
        let sessionStore = InMemorySessionStore()
        // The store is account-scoped: nothing can be written to it before an
        // account is active (the same reason `login()` scopes it before it
        // records the passkey link).
        sessionStore.activeAccountId = "default:user-1"
        sessionStore.credentialId = "stale-passkey"
        let wallet = makeWallet(sessionStore: sessionStore)
        let server = StubHttpServer()
        server.enqueue(#"{"challenge":"chal-1"}"#)                                       // WIA challenge
        server.enqueueFailure(code: 403, body: #"{"error":"CREDENTIAL_NOT_OWNED"}"#)     // with the stale link
        server.enqueue(#"{"wallet_instance_attestation":"wia.jwt"}"#)                    // retry without it
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFunction)
        client.setAppToken("t")
        wallet.apiClient = client

        let wia = await wallet.ensureWalletInstanceAttestation()

        XCTAssertEqual(wia, "wia.jwt")
        XCTAssertNil(sessionStore.credentialId, "the stale link is dropped, never replaced with a guess")
        XCTAssertEqual(server.requestCount, 3)
        XCTAssertEqual(server.bodies[1]?["credential_id"] as? String, "stale-passkey")
        XCTAssertNil(server.bodies[2]?["credential_id"], "the retry must not carry the refused link")
    }

    /// The happy path, and the reason the link exists at all: the passkey this
    /// installation logs in with is what the backend binds the instance to, so
    /// suspending the instance also refuses that passkey at login.
    func testWiaGenerationSendsTheRecordedPasskeyLink() async throws {
        let sessionStore = InMemorySessionStore()
        sessionStore.activeAccountId = "default:user-1"
        sessionStore.credentialId = "pk-1"
        let wallet = makeWallet(sessionStore: sessionStore)
        let server = StubHttpServer()
        server.enqueue(#"{"challenge":"chal-1"}"#)
        server.enqueue(#"{"wallet_instance_attestation":"wia.jwt"}"#)
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFunction)
        client.setAppToken("t")
        wallet.apiClient = client

        let wia = await wallet.ensureWalletInstanceAttestation()

        XCTAssertEqual(wia, "wia.jwt")
        XCTAssertEqual(sessionStore.credentialId, "pk-1", "a link the backend accepted is kept")
        XCTAssertEqual(server.requestCount, 2)
        XCTAssertEqual(server.bodies[1]?["credential_id"] as? String, "pk-1")
    }
}
