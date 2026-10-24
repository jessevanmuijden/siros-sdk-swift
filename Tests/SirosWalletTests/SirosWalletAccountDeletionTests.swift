// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
import SwiftCBOR
@testable import SirosWallet

/// `SirosWallet.deleteAccount` (go-wallet-backend#352): the begin -> assertion
/// -> delete sequence, every backend outcome as a result value, and the
/// invariant that local state is wiped for exactly the three accepted
/// outcomes. Stubs only, so it runs on Linux and Apple platforms alike.
final class SirosWalletAccountDeletionTests: XCTestCase {

    // MARK: - Doubles

    private final class RecordingAuthProvider: AuthProvider, @unchecked Sendable {
        private let lock = NSLock()
        private(set) var options: [AuthenticateOptions] = []
        var failure: Error?
        func register(options: RegisterOptions) async throws -> RegisterResult { fatalError("unused") }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { fatalError("unused") }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult {
            lock.lock(); self.options.append(options); lock.unlock()
            if let failure { throw failure }
            return AuthenticateResult(
                credentialId: Data("pk-1".utf8),
                authenticatorData: Data([1]),
                clientDataJSON: Data([2]),
                signature: Data([3]),
                userHandle: Data([4])
            )
        }
    }

    private final class RecordingKeystore: KeystoreManager, @unchecked Sendable {
        var isUnlocked = true
        var clearCredentialsError: Error?
        private(set) var clearedCredentials = false
        private(set) var clearedPresentationRecords = false
        private(set) var savedPresentationRecords = 0
        private(set) var locked = false
        var eraseKeyMaterialError: Error?
        private(set) var erasedKeyMaterial = false
        func eraseKeyMaterial() async throws {
            erasedKeyMaterial = true
            if let eraseKeyMaterialError { throw eraseKeyMaterialError }
        }
        func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
        func lock() { locked = true; isUnlocked = false }
        func generateKey(algorithm: String) async throws -> String { "key" }
        func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
        func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "" }
        func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
        func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
        func exportEncryptedContainer() async throws -> Data { Data() }
        var keyIds: [String] = []
        func listKeys() -> [KeyInfo] { keyIds.map { KeyInfo(keyId: $0, algorithm: "ES256") } }
        func saveCredential(id: Int64, json: String) async throws {}
        func getCredential(id: Int64) async throws -> String? { nil }
        func getAllCredentials() async throws -> [Int64: String] { [:] }
        func deleteCredential(id: Int64) async throws {}
        /// When set, `clearCredentials` parks here: the wipe is suspended inside its keystore erase.
        var clearGate: ConsentGate?
        /// When set, the proximity signing parks here before returning.
        var signGate: ConsentGate?
        func signMdocPresentationForProximity(
            credentialBytes: Data, disclosedClaims: [String]?, sessionTranscriptBytes: Data, kid: String?
        ) async throws -> Data {
            if let signGate { await signGate.park() }
            return Data([0xA0])
        }
        func clearCredentials() async throws {
            if let clearGate { await clearGate.park() }
            if let clearCredentialsError { throw clearCredentialsError }
            clearedCredentials = true
        }
        func savePresentationRecord(id: Int64, json: String) async throws { savedPresentationRecords += 1 }
        func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
        func clearPresentationRecords() async throws { clearedPresentationRecords = true }
        func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    }

    private final class RecordingCredentialStore: CredentialStore, @unchecked Sendable {
        private(set) var cleared = false
        func getAll() async -> [StoredCredential] { [] }
        func getById(_ id: Int64) async -> StoredCredential? { nil }
        func save(_ credential: StoredCredential) async {}
        func update(_ credential: StoredCredential) async {}
        func delete(_ id: Int64) async {}
        var eraseError: Error?
        func clear() async { cleared = true }
        func eraseAll() async throws {
            if let eraseError { throw eraseError }
            cleared = true
        }
    }

    private final class Server: @unchecked Sendable {
        struct Call { let method: String; let path: String; let body: [String: Any]? }
        private let lock = NSLock()
        private(set) var calls: [Call] = []
        var begin: Result<String, Error> = .success(
            #"{"challengeId":"ch-1","publicKey":{"challenge":{"$b64u":"AQID"},"rpId":"wallet.example.com","userVerification":"required","allowCredentials":[{"type":"public-key","id":{"$b64u":"cGstMQ"}}]}}"#
        )
        var delete: Result<String, Error> = .success(#"{"result":"DELETED"}"#)

        func failDelete(_ code: Int, _ body: String) {
            delete = .failure(SirosError.backendApi(code: code, message: "failed", body: body))
        }

        var httpFn: @Sendable (String, URL, [String: String], Data?) async throws -> Data {
            { [self] method, url, _, body in
                lock.lock(); defer { lock.unlock() }
                calls.append(Call(
                    method: method, path: url.path,
                    body: body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                ))
                let reply = url.path == "/user/session/delete-begin" ? begin : delete
                return Data(try reply.get().utf8)
            }
        }
    }

    private struct Fixture {
        let wallet: SirosWallet
        let server: Server
        let auth: RecordingAuthProvider
        let keystore: RecordingKeystore
        let credentials: RecordingCredentialStore
        let sessionStore: InMemorySessionStore
        let registry: AccountRegistry
    }

    private func makeFixture(loggedIn: Bool = true) async -> Fixture {
        let auth = RecordingAuthProvider()
        let keystore = RecordingKeystore()
        let credentials = RecordingCredentialStore()
        let sessionStore = InMemorySessionStore()
        let registry = AccountRegistry.inMemory()
        let wallet = SirosWallet(
            config: WalletConfig(backendUrl: "https://wallet.example.invalid", credentialStore: credentials),
            authProvider: auth,
            sessionStore: sessionStore,
            keystore: keystore,
            accountRegistry: registry
        )!

        for user in ["user-1", "user-2"] {
            let account = CachedAccount(
                userId: user, tenantId: "default", displayName: user,
                backendUrl: "https://wallet.example.invalid",
                passkeys: [CachedPasskey(credentialId: "cred-\(user)", prfSalt: "c2FsdA==")]
            )
            registry.upsertAccount(account)
            sessionStore.activeAccountId = account.accountId
            sessionStore.appToken = "token-\(user)"
            sessionStore.mainKey = "main-key-\(user)"
            sessionStore.prfSalt = "salt-\(user)"
            sessionStore.instanceKeyId = "instance-\(user)"
        }
        registry.activeAccountId = "default:user-1"
        sessionStore.activeAccountId = "default:user-1"
        wallet.wscdSelectionPolicy.setGlobalUserOverride(pluginId: "fido2")
        wallet.wscdSelectionPolicy.setUserOverride(issuer: "iss", credentialType: "t", pluginId: "fido2")

        let server = Server()
        if loggedIn {
            let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFn)
            client.setAppToken("t")
            wallet.apiClient = client
        }
        // After the API client is set: replacing the client clears the cache.
        _ = try? await wallet.trustDecisionCache.getOrEvaluate(key: "verifier") { try XCTUnwrap(JSONSerialization.jsonObject(with: Data(#"{"decision":true}"#.utf8)) as? [String: Any]) }
        return Fixture(
            wallet: wallet, server: server, auth: auth, keystore: keystore,
            credentials: credentials, sessionStore: sessionStore, registry: registry
        )
    }

    private func assertKept(_ f: Fixture, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(f.keystore.clearedCredentials, "keystore credentials untouched", file: file, line: line)
        XCTAssertFalse(f.keystore.clearedPresentationRecords, file: file, line: line)
        XCTAssertFalse(f.keystore.locked, "keystore stays unlocked", file: file, line: line)
        XCTAssertFalse(f.credentials.cleared, file: file, line: line)
        XCTAssertEqual(f.registry.listAccounts().count, 2, "accounts kept", file: file, line: line)
        XCTAssertEqual(f.sessionStore.appToken, "token-user-1", "session kept", file: file, line: line)
        XCTAssertEqual(f.sessionStore.instanceKeyId, "instance-user-1", file: file, line: line)
        XCTAssertNotNil(f.wallet.apiClient, "api client kept", file: file, line: line)
        XCTAssertEqual(f.wallet.wscdGlobalOverride, "fido2", file: file, line: line)
        XCTAssertEqual(f.wallet.trustDecisionCache.size, 1, "the trust decision is kept", file: file, line: line)
    }

    private func assertWiped(_ f: Fixture, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(f.keystore.clearedCredentials, file: file, line: line)
        XCTAssertTrue(f.keystore.clearedPresentationRecords, file: file, line: line)
        XCTAssertTrue(f.keystore.locked, "key material locked away", file: file, line: line)
        XCTAssertTrue(f.credentials.cleared, file: file, line: line)
        XCTAssertTrue(f.registry.listAccounts().isEmpty, "every account forgotten", file: file, line: line)
        XCTAssertNil(f.registry.activeAccountId, file: file, line: line)
        XCTAssertNil(f.wallet.apiClient, file: file, line: line)
        XCTAssertNil(f.wallet.wscdGlobalOverride, file: file, line: line)
        XCTAssertTrue(f.wallet.wscdUserOverrides.isEmpty, file: file, line: line)
        XCTAssertEqual(f.wallet.trustDecisionCache.size, 0, "the trust decisions are cleared", file: file, line: line)
        // Both accounts, not just the active one, and the Keychain-class
        // material (PRF salt, main key, instance key) with them.
        for user in ["user-1", "user-2"] {
            f.sessionStore.activeAccountId = "default:\(user)"
            XCTAssertNil(f.sessionStore.appToken, user, file: file, line: line)
            XCTAssertNil(f.sessionStore.mainKey, user, file: file, line: line)
            XCTAssertNil(f.sessionStore.prfSalt, user, file: file, line: line)
            XCTAssertNil(f.sessionStore.instanceKeyId, user, file: file, line: line)
        }
        guard case let .disconnected(accounts) = f.wallet.state else {
            return XCTFail("expected .disconnected, got \(f.wallet.state)", file: file, line: line)
        }
        XCTAssertTrue(accounts.isEmpty, file: file, line: line)
    }

    // MARK: - Sequence

    func testBeginThenDeleteWithTheAssertionAndConfirmation() async {
        let f = await makeFixture()

        let result = await f.wallet.deleteAccount(confirmation: "DELETE")

        XCTAssertEqual(result, .deleted(localWipe: LocalWipeReport()))
        XCTAssertEqual(f.server.calls.map { "\($0.method) \($0.path)" },
                       ["POST /user/session/delete-begin", "DELETE /user/session"])
        let options = f.auth.options
        XCTAssertEqual(options.count, 1)
        XCTAssertEqual(options[0].rpId, "wallet.example.com")
        XCTAssertEqual(options[0].challenge, Data([1, 2, 3]))
        XCTAssertEqual(options[0].userVerification, "required")
        XCTAssertEqual(options[0].allowCredentials?.map(\.id), [Data("pk-1".utf8)])
        XCTAssertNil(options[0].prfSalt, "no PRF is requested for a step-up")
        let body = f.server.calls[1].body
        XCTAssertEqual(body?["challengeId"] as? String, "ch-1")
        XCTAssertEqual(body?["confirm"] as? String, "DELETE")
        let credential = body?["credential"] as? [String: Any]
        XCTAssertEqual(credential?["id"] as? String, SirosWallet.b64UrlEncode(Data("pk-1".utf8)))
        XCTAssertEqual(credential?["type"] as? String, "public-key")
        let response = credential?["response"] as? [String: Any]
        XCTAssertEqual(response?["signature"] as? String, SirosWallet.b64UrlEncode(Data([3])))
        XCTAssertEqual(response?["userHandle"] as? String, SirosWallet.b64UrlEncode(Data([4])))
    }

    func testAStepUpClosureReplacesTheAuthProvider() async {
        let f = await makeFixture()
        let seen = OptionsBox()

        let result = await f.wallet.deleteAccount(confirmation: "DELETE") { options in
            seen.options = options
            return AuthenticateResult(
                credentialId: Data("sk".utf8), authenticatorData: Data(), clientDataJSON: Data(), signature: Data([9])
            )
        }

        XCTAssertEqual(result, .deleted(localWipe: LocalWipeReport()))
        XCTAssertEqual(seen.options?.rpId, "wallet.example.com")
        XCTAssertTrue(f.auth.options.isEmpty)
        let credential = f.server.calls[1].body?["credential"] as? [String: Any]
        XCTAssertEqual(credential?["id"] as? String, SirosWallet.b64UrlEncode(Data("sk".utf8)))
    }

    private final class OptionsBox: @unchecked Sendable { var options: AuthenticateOptions? }

    // MARK: - Accepted outcomes wipe everything

    func testDeletedWipesAllLocalState() async {
        let f = await makeFixture()
        let result = await f.wallet.deleteAccount(confirmation: "DELETE")
        XCTAssertEqual(result, .deleted(localWipe: LocalWipeReport()))
        XCTAssertTrue(result.wipedLocalState)
        assertWiped(f)
    }

    func testCleanupPendingWipesAllLocalState() async {
        let f = await makeFixture()
        f.server.delete = .success(#"{"error":"DELETION_CLEANUP_PENDING","result":"DELETED"}"#)
        let result = await f.wallet.deleteAccount(confirmation: "DELETE")
        XCTAssertEqual(result, .cleanupPending(localWipe: LocalWipeReport()))
        assertWiped(f)
    }

    func testOperatorRequiredWipesAllLocalState() async {
        let f = await makeFixture()
        f.server.delete = .success(#"{"error":"DELETION_OPERATOR_REQUIRED","result":"PENDING"}"#)
        let result = await f.wallet.deleteAccount(confirmation: "DELETE")
        XCTAssertEqual(result, .operatorRequired(localWipe: LocalWipeReport()))
        assertWiped(f)
    }

    // MARK: - Everything else keeps local state

    func testRetryableAndRefusedOutcomesKeepLocalState() async {
        let cases: [(Int, String, DeleteAccountResult)] = [
            (409, #"{"error":"DELETION_INCOMPLETE","message":"again"}"#, .retryNeeded(.incomplete(message: "again"))),
            (401, #"{"error":"STEP_UP_FAILED"}"#, .retryNeeded(.stepUpFailed)),
            (401, #"{"error":"STEP_UP_REQUIRED"}"#, .retryNeeded(.stepUpRequired)),
            (410, #"{"error":"STEP_UP_EXPIRED"}"#, .retryNeeded(.stepUpExpired)),
            (400, #"{"error":"CONFIRMATION_REQUIRED"}"#, .failed(.confirmationRequired)),
            (401, #"{"error":"Unauthorized"}"#, .failed(.sessionRejected)),
            (404, #"{"error":"User not found"}"#, .failed(.accountNotFound)),
        ]
        for (code, body, expected) in cases {
            let f = await makeFixture()
            f.server.failDelete(code, body)
            let result = await f.wallet.deleteAccount(confirmation: "DELETE")
            XCTAssertEqual(result, expected, "\(code) \(body)")
            XCTAssertFalse(result.wipedLocalState)
            assertKept(f)
        }
    }

    func testTransportAndUnexpectedFailuresAreResultsAndKeepLocalState() async {
        let f = await makeFixture()
        f.server.failDelete(500, "")
        let result = await f.wallet.deleteAccount(confirmation: "DELETE")
        guard case .failed(.requestFailed) = result else { return XCTFail("got \(result)") }
        assertKept(f)

        let g = await makeFixture()
        g.server.begin = .failure(SirosError.network(message: "offline"))
        let beginResult = await g.wallet.deleteAccount(confirmation: "DELETE")
        guard case .failed(.requestFailed) = beginResult else { return XCTFail("got \(beginResult)") }
        XCTAssertEqual(g.server.calls.count, 1, "no assertion is asked for without a challenge")
        assertKept(g)
    }

    func testBeginRefusalsMapToFailures() async {
        let cases: [(Int, String, DeleteAccountFailure)] = [
            (401, "", .sessionRejected),
            (404, "", .accountNotFound),
            (403, #"{"error":"insufficient_scope"}"#, .notPermitted),
            (400, #"{"error":"NO_PASSKEY"}"#, .noPasskey),
        ]
        for (code, body, expected) in cases {
            let f = await makeFixture()
            f.server.begin = .failure(SirosError.backendApi(code: code, message: "x", body: body))
            let result = await f.wallet.deleteAccount(confirmation: "DELETE")
            XCTAssertEqual(result, .failed(expected))
            XCTAssertTrue(f.auth.options.isEmpty)
            assertKept(f)
        }
    }

    func testACancelledOrFailedAssertionSendsNoDeleteAndKeepsLocalState() async {
        struct Cancelled: Error, LocalizedError { var errorDescription: String? { "user cancelled" } }
        let f = await makeFixture()
        f.auth.failure = Cancelled()

        let result = await f.wallet.deleteAccount(confirmation: "DELETE")

        XCTAssertEqual(result, .failed(.stepUpAborted(message: "user cancelled")))
        XCTAssertEqual(f.server.calls.map(\.path), ["/user/session/delete-begin"])
        assertKept(f)
    }

    func testAWrongConfirmationNeverReachesTheBackend() async {
        for typed in ["delete", "Delete", " DELETE", "DELETE ", ""] {
            let f = await makeFixture()
            let result = await f.wallet.deleteAccount(confirmation: typed)
            XCTAssertEqual(result, .failed(.confirmationRequired), "'\(typed)'")
            XCTAssertTrue(f.server.calls.isEmpty, "the single-use challenge must not be spent on it")
            assertKept(f)
        }
    }

    func testNotLoggedInIsAFailure() async {
        let f = await makeFixture(loggedIn: false)
        let result = await f.wallet.deleteAccount(confirmation: "DELETE")
        XCTAssertEqual(result, .failed(.notLoggedIn))
        XCTAssertTrue(f.server.calls.isEmpty)
        XCTAssertTrue(f.auth.options.isEmpty)
    }

    // MARK: - Consent handlers that outlive the wipe

    private final class ConsentGate: @unchecked Sendable {
        private let lock = NSLock()
        private var entered = false
        private var releaseContinuation: CheckedContinuation<Void, Never>?
        private var released = false
        func park() async {
            lock.lock(); entered = true
            if released { lock.unlock(); return }
            await withCheckedContinuation { releaseContinuation = $0; lock.unlock() }
        }
        var hasEntered: Bool { lock.lock(); defer { lock.unlock() }; return entered }
        func markEntered() { lock.lock(); entered = true; lock.unlock() }
        func release() {
            lock.lock(); released = true; let c = releaseContinuation; releaseContinuation = nil; lock.unlock()
            c?.resume()
        }
    }

    private final class ConsentListener: WalletEventListener, @unchecked Sendable {
        let gate = ConsentGate()
        let choose: Int64
        init(choose: Int64) { self.choose = choose }
        func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] {
            await gate.park()
            return [choose]
        }
        func onCredentialReceived(credential: StoredCredential) {}
        func onFlowComplete(flowId: String, redirectUri: String?) {}
        func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) {}
        func onNoMatchingCredential(flowId: String, requestedTypes: [String], reason: String?, redirectUri: String?) {}
        func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String) {}
        func onTxCodeRequired(flowId: String, description: String?) -> String? { nil }
        func onReauthenticationRequired() {}
        func onWalletLifecycleBlocked(reason: SirosError.WalletLifecycleRefusal, message: String?) {}
        func onCredentialRenewedWithAttributeDiff(credential: StoredCredential, diff: CredentialAttributeDiff) {}
        func onCredentialNearExpiry(credential: StoredCredential, eligibleRemaining: Int, threshold: Int) {}
        func onTransactionLogFailure() {}
        func onIssuerNotTrusted(flowId: String, issuer: String?, reason: String) {}
    }

    /// A consent listener that returns after the account was deleted must not
    /// bring back cached match results or presentation history.
    func testConsentGivenAfterTheWipeRestoresNothing() async throws {
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(id: 5, format: "dc+sd-jwt", raw: "a.b.c", kid: "k1", batchId: 5, instanceId: 0))
        let keystore = RecordingKeystore()
        keystore.keyIds = ["k1"]
        let wallet = SirosWallet(
            config: WalletConfig(backendUrl: "https://wallet.example.invalid", credentialStore: store),
            authProvider: RecordingAuthProvider(), sessionStore: InMemorySessionStore(), keystore: keystore,
            accountRegistry: .inMemory()
        )!
        wallet.credentialConsumptionPolicy = .neverConsume
        let listener = ConsentListener(choose: 5)
        wallet.eventListener = listener
        let engine = WalletEngineSession(baseUrl: "https://wallet.example.invalid", tenantId: "t")
        let request = try JSONDecoder().decode(
            MatchRequestMessage.self, from: Data(#"{"type":"match_request","flow_id":"flow-1"}"#.utf8)
        )

        let handler = Task { await wallet.handleMatchRequest(engine: engine, msg: request) }
        while !listener.gate.hasEntered { try await Task.sleep(nanoseconds: 5_000_000) }
        _ = await wallet.wipeLocalState()
        listener.gate.release()
        await handler.value

        XCTAssertTrue(wallet.presentationHistory.isEmpty, "no presentation record after the wipe")
        wallet.lock.lock(); let cached = wallet.pendingMatchResultsByFlow.count; wallet.lock.unlock()
        XCTAssertEqual(cached, 0, "no cached match results after the wipe")
        XCTAssertEqual(keystore.savedPresentationRecords, 0)
    }

    // MARK: - Write admission closes at the START of the wipe

    /// An in-memory store whose `save` can park: a write that resumes only after the wipe has finished.
    private final class ParkingStore: CredentialStore, @unchecked Sendable {
        let inner = InMemoryCredentialStore()
        var saveGate: ConsentGate?
        func getAll() async -> [StoredCredential] { await inner.getAll() }
        func getById(_ id: Int64) async -> StoredCredential? { await inner.getById(id) }
        func save(_ credential: StoredCredential) async {
            if let saveGate { await saveGate.park() }
            await inner.save(credential)
        }
        func update(_ credential: StoredCredential) async { await inner.update(credential) }
        func delete(_ id: Int64) async { await inner.delete(id) }
        func clear() async { await inner.clear() }
    }

    private func gateWallet(store: CredentialStore, keystore: RecordingKeystore) -> SirosWallet {
        let wallet = SirosWallet(
            config: WalletConfig(backendUrl: "https://wallet.example.invalid", credentialStore: store),
            authProvider: RecordingAuthProvider(), sessionStore: InMemorySessionStore(), keystore: keystore,
            accountRegistry: .inMemory()
        )!
        wallet.credentialConsumptionPolicy = .neverConsume
        return wallet
    }

    private func jwtCredential() -> String {
        let now = Int64(Date().timeIntervalSince1970)
        let b64 = (try! JSONSerialization.data(withJSONObject: ["exp": now + 3600, "iat": now])).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return "eyJ.\(b64).sig"
    }

    private func completion(_ credentials: [[String: Any]], flowId: String = "flow-1") -> FlowCompleteMessage {
        let obj: [String: Any] = ["type": MessageTypes.flowComplete, "flow_id": flowId, "credentials": credentials]
        var msg = try! JSONDecoder().decode(FlowCompleteMessage.self, from: JSONSerialization.data(withJSONObject: obj))
        msg.startTag = 0
        return msg
    }

    /// A flow completion that STARTS while the wipe is suspended in its keystore erase must not store anything
    /// once the wipe is over: admission was closed before the wipe's first await.
    func testACompletionStartingDuringTheEraseStoresNothing() async throws {
        let store = ParkingStore()
        let saveGate = ConsentGate()
        store.saveGate = saveGate
        let keystore = RecordingKeystore()
        let eraseGate = ConsentGate()
        keystore.clearGate = eraseGate
        let wallet = gateWallet(store: store, keystore: keystore)

        let wiping = Task { await wallet.wipeLocalState() }
        while !eraseGate.hasEntered { try await Task.sleep(nanoseconds: 5_000_000) }
        // The wipe is suspended in the keystore erase; a completion begins now and would park in its save.
        let completing = Task { await wallet.handleFlowComplete(msg: completion([["format": "vc+sd-jwt", "credential": jwtCredential()]])) }
        try await Task.sleep(nanoseconds: 100_000_000)
        eraseGate.release()
        _ = await wiping.value
        saveGate.release()          // a save that was admitted would land only now, after the wipe
        await completing.value

        let saved = await store.getAll()
        XCTAssertTrue(saved.isEmpty, "nothing may be stored by a completion that began during the erase")
    }

    /// The trust-check variant: the completion would pass the issuer trust gate (its hook answers after the wipe
    /// ended) and then save; it must have been refused when it started.
    func testAnMdocCompletionStartingDuringTheEraseNeverReachesTheTrustCheckOrTheStore() async throws {
        let store = ParkingStore()
        let saveGate = ConsentGate()
        store.saveGate = saveGate
        let keystore = RecordingKeystore()
        let eraseGate = ConsentGate()
        keystore.clearGate = eraseGate
        let wallet = gateWallet(store: store, keystore: keystore)
        let trustCalled = ConsentGate()
        wallet.mdocIssuanceTrustHook = { _ in
            trustCalled.markEntered()
            return TrustResult(trusted: true)
        }
        let item: CBOR = .tagged(.encodedCBORDataItem, .byteString(CBOR.map([
            .utf8String("digestID"): .unsignedInt(0), .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String("given_name"), .utf8String("elementValue"): .utf8String("Jane"),
        ]).encode()))
        let mso: CBOR = .map([.utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL")])
        let issuerAuth: CBOR = .array([
            .byteString([]), .map([:]),
            .byteString(CBOR.tagged(.encodedCBORDataItem, .byteString(mso.encode())).encode()), .byteString([UInt8](repeating: 0, count: 64)),
        ])
        let raw = Data(CBOR.map([
            .utf8String("nameSpaces"): .map([.utf8String("org.iso.18013.5.1"): .array([item])]),
            .utf8String("issuerAuth"): issuerAuth,
        ]).encode()).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")

        let wiping = Task { await wallet.wipeLocalState() }
        while !eraseGate.hasEntered { try await Task.sleep(nanoseconds: 5_000_000) }
        let completing = Task { await wallet.handleFlowComplete(msg: completion([["format": "mso_mdoc", "credential": raw]])) }
        try await Task.sleep(nanoseconds: 100_000_000)
        eraseGate.release()
        _ = await wiping.value
        saveGate.release()
        await completing.value

        let saved = await store.getAll()
        XCTAssertTrue(saved.isEmpty)
        XCTAssertFalse(trustCalled.hasEntered, "the trust check is never reached by a completion that began during the erase")
    }

    /// Proximity signing that resumes after the wipe records no presentation and reports the failure.
    func testProximitySigningResumingAfterTheWipeRecordsNothing() async throws {
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(id: 5, format: "mso_mdoc", raw: "YWJj", kid: "k1", batchId: 5, instanceId: 0))
        let keystore = RecordingKeystore()
        keystore.keyIds = ["k1"]
        let signGate = ConsentGate()
        keystore.signGate = signGate
        let wallet = gateWallet(store: store, keystore: keystore)

        let signing = Task { () -> Error? in
            do { _ = try await wallet.signMdocPresentationForProximity(credentialId: 5, disclosedClaims: nil, sessionTranscriptBytes: Data([1])); return nil } catch { return error }
        }
        while !signGate.hasEntered { try await Task.sleep(nanoseconds: 5_000_000) }
        _ = await wallet.wipeLocalState()
        signGate.release()
        let failure = await signing.value

        XCTAssertNotNil(failure, "the presentation is aborted when it can no longer be recorded")
        XCTAssertTrue(wallet.presentationHistory.isEmpty)
        XCTAssertEqual(keystore.savedPresentationRecords, 0)
    }

    /// Admission stays closed after the wipe and opens only for a new session.
    func testAdmissionReopensOnlyForANewSession() async throws {
        let store = InMemoryCredentialStore()
        let wallet = gateWallet(store: store, keystore: RecordingKeystore())
        XCTAssertNotNil(wallet.currentTeardownToken())
        _ = await wallet.wipeLocalState()
        XCTAssertNil(wallet.currentTeardownToken(), "closed once the wipe has finished, not only while it runs")
        await wallet.reopenForNewSession()
        XCTAssertNotNil(wallet.currentTeardownToken())
    }

    // MARK: - Authorization-server token cache

    private final class MintCounter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        var count: Int { lock.lock(); defer { lock.unlock() }; return n }
        func bump() { lock.lock(); n += 1; lock.unlock() }
    }

    /// `AuthServerClient` caches minted tokens on its own; a wipe must drop
    /// them, or the next request would be served the deleted account's token.
    func testTheWipeClearsTheAuthServerTokenCache() async throws {
        let f = await makeFixture()
        let minted = MintCounter()
        let client = AuthServerClient(baseUrl: "https://as.example.invalid", tenantId: "default") { _, _, _, _ in
            minted.bump()
            let claims = #"{"sub":"u","aud":"wallet-backend","tenant_id":"default","tac":"rwlid","exp":4102444800}"#
            let b64 = Data(claims.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
            return Data(#"{"access_token":"e30.\#(b64).sig","token_type":"Bearer","expires_in":3600}"#.utf8)
        }
        f.wallet.authServerClient = client
        _ = try await client.requestAccessToken(aud: "wallet-backend", tac: "rwlid")
        _ = try await client.requestAccessToken(aud: "wallet-backend", tac: "rwlid")
        XCTAssertEqual(minted.count, 1, "warm cache")

        _ = await f.wallet.deleteAccount(confirmation: "DELETE")

        _ = try await client.requestAccessToken(aud: "wallet-backend", tac: "rwlid")
        XCTAssertEqual(minted.count, 2, "the wipe dropped the cached token")
    }

    // MARK: - Wipe error collection

    func testAFailingWipeStepIsReportedAndTheRestStillRuns() async {
        struct Boom: Error, LocalizedError { var errorDescription: String? { "boom" } }
        let f = await makeFixture()
        f.keystore.clearCredentialsError = Boom()

        let result = await f.wallet.deleteAccount(confirmation: "DELETE")

        let report = LocalWipeReport(failures: [LocalWipeFailure(component: "keystore credentials", message: "boom")])
        XCTAssertEqual(result, .deleted(localWipe: report))
        XCTAssertFalse(report.isComplete)
        XCTAssertTrue(f.keystore.clearedPresentationRecords, "later steps run after a failure")
        XCTAssertTrue(f.credentials.cleared)
        XCTAssertTrue(f.registry.listAccounts().isEmpty)
        XCTAssertNil(f.wallet.apiClient)
        XCTAssertNil(f.sessionStore.appToken)
    }

    /// The three stores whose plain clear cannot report: a failing erase must
    /// reach the caller's report while the remaining steps still run.
    func testFailingStoreErasuresAreReported() async {
        struct Boom: Error, LocalizedError { var errorDescription: String? { "boom" } }
        let auth = RecordingAuthProvider()
        let credentials = RecordingCredentialStore()
        credentials.eraseError = Boom()
        let sessionStore = InMemorySessionStore()
        sessionStore.eraseFailure = Boom()
        let storage = InMemoryAccountRegistryStorage()
        storage.eraseFailure = Boom()
        let registry = AccountRegistry(storage: storage)
        let wallet = SirosWallet(
            config: WalletConfig(backendUrl: "https://wallet.example.invalid", credentialStore: credentials),
            authProvider: auth, sessionStore: sessionStore, keystore: RecordingKeystore(), accountRegistry: registry
        )!
        let report = await wallet.wipeLocalState()
        XCTAssertEqual(Set(report.failures.map(\.component)), ["credential store", "session store", "account registry"])
        XCTAssertFalse(report.isComplete)
    }

    /// Holder keys can be generated in any registered keystore: each distinct
    /// one is cleared, has its signing keys erased and is locked, the default
    /// is not handled twice, and a failure names the store it came from.
    func testEveryDistinctRegisteredKeystoreIsWiped() async {
        struct Boom: Error, LocalizedError { var errorDescription: String? { "boom" } }
        let primary = RecordingKeystore()
        let secondary = RecordingKeystore()
        secondary.eraseKeyMaterialError = Boom()
        let server = Server()
        let wallet = SirosWallet(
            config: WalletConfig(
                backendUrl: "https://wallet.example.invalid",
                credentialStore: RecordingCredentialStore(),
                availableKeystores: ["softkey": primary, "fido2": secondary]
            ),
            authProvider: RecordingAuthProvider(), sessionStore: InMemorySessionStore(),
            keystore: primary, accountRegistry: .inMemory()
        )!
        let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFn)
        client.setAppToken("t")
        wallet.apiClient = client

        let result = await wallet.deleteAccount(confirmation: "DELETE")

        XCTAssertEqual(result, .deleted(localWipe: LocalWipeReport(failures: [
            LocalWipeFailure(component: "keystore fido2 signing keys", message: "boom"),
        ])))
        for store in [primary, secondary] {
            XCTAssertTrue(store.clearedCredentials)
            XCTAssertTrue(store.clearedPresentationRecords)
            XCTAssertTrue(store.erasedKeyMaterial)
            XCTAssertTrue(store.locked)
        }
    }

    func testALockedKeystoreIsSkippedNotReportedAsAFailure() async {
        let f = await makeFixture()
        f.keystore.isUnlocked = false

        let result = await f.wallet.deleteAccount(confirmation: "DELETE")

        XCTAssertEqual(result, .deleted(localWipe: LocalWipeReport()))
        XCTAssertTrue(f.registry.listAccounts().isEmpty)
    }
}
