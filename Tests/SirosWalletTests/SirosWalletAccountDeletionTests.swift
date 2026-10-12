// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore
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
        private(set) var locked = false
        func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
        func lock() { locked = true; isUnlocked = false }
        func generateKey(algorithm: String) async throws -> String { "key" }
        func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
        func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "" }
        func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
        func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
        func exportEncryptedContainer() async throws -> Data { Data() }
        func listKeys() -> [KeyInfo] { [] }
        func saveCredential(id: Int64, json: String) async throws {}
        func getCredential(id: Int64) async throws -> String? { nil }
        func getAllCredentials() async throws -> [Int64: String] { [:] }
        func deleteCredential(id: Int64) async throws {}
        func clearCredentials() async throws {
            if let clearCredentialsError { throw clearCredentialsError }
            clearedCredentials = true
        }
        func savePresentationRecord(id: Int64, json: String) async throws {}
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
        func clear() async { cleared = true }
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

    private func makeFixture(loggedIn: Bool = true) -> Fixture {
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
        wallet.trustCache.put(identifier: "verifier", result: TrustResult(trusted: true))

        let server = Server()
        if loggedIn {
            let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFn)
            client.setAppToken("t")
            wallet.apiClient = client
        }
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
        XCTAssertNotNil(f.wallet.trustCache.get(identifier: "verifier"), file: file, line: line)
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
        XCTAssertNil(f.wallet.trustCache.get(identifier: "verifier"), file: file, line: line)
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
        let f = makeFixture()

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
        let f = makeFixture()
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
        let f = makeFixture()
        let result = await f.wallet.deleteAccount(confirmation: "DELETE")
        XCTAssertEqual(result, .deleted(localWipe: LocalWipeReport()))
        XCTAssertTrue(result.wipedLocalState)
        assertWiped(f)
    }

    func testCleanupPendingWipesAllLocalState() async {
        let f = makeFixture()
        f.server.delete = .success(#"{"error":"DELETION_CLEANUP_PENDING","result":"DELETED"}"#)
        let result = await f.wallet.deleteAccount(confirmation: "DELETE")
        XCTAssertEqual(result, .cleanupPending(localWipe: LocalWipeReport()))
        assertWiped(f)
    }

    func testOperatorRequiredWipesAllLocalState() async {
        let f = makeFixture()
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
            let f = makeFixture()
            f.server.failDelete(code, body)
            let result = await f.wallet.deleteAccount(confirmation: "DELETE")
            XCTAssertEqual(result, expected, "\(code) \(body)")
            XCTAssertFalse(result.wipedLocalState)
            assertKept(f)
        }
    }

    func testTransportAndUnexpectedFailuresAreResultsAndKeepLocalState() async {
        let f = makeFixture()
        f.server.failDelete(500, "")
        let result = await f.wallet.deleteAccount(confirmation: "DELETE")
        guard case .failed(.requestFailed) = result else { return XCTFail("got \(result)") }
        assertKept(f)

        let g = makeFixture()
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
            let f = makeFixture()
            f.server.begin = .failure(SirosError.backendApi(code: code, message: "x", body: body))
            let result = await f.wallet.deleteAccount(confirmation: "DELETE")
            XCTAssertEqual(result, .failed(expected))
            XCTAssertTrue(f.auth.options.isEmpty)
            assertKept(f)
        }
    }

    func testACancelledOrFailedAssertionSendsNoDeleteAndKeepsLocalState() async {
        struct Cancelled: Error, LocalizedError { var errorDescription: String? { "user cancelled" } }
        let f = makeFixture()
        f.auth.failure = Cancelled()

        let result = await f.wallet.deleteAccount(confirmation: "DELETE")

        XCTAssertEqual(result, .failed(.stepUpAborted(message: "user cancelled")))
        XCTAssertEqual(f.server.calls.map(\.path), ["/user/session/delete-begin"])
        assertKept(f)
    }

    func testAWrongConfirmationNeverReachesTheBackend() async {
        for typed in ["delete", "Delete", " DELETE", "DELETE ", ""] {
            let f = makeFixture()
            let result = await f.wallet.deleteAccount(confirmation: typed)
            XCTAssertEqual(result, .failed(.confirmationRequired), "'\(typed)'")
            XCTAssertTrue(f.server.calls.isEmpty, "the single-use challenge must not be spent on it")
            assertKept(f)
        }
    }

    func testNotLoggedInIsAFailure() async {
        let f = makeFixture(loggedIn: false)
        let result = await f.wallet.deleteAccount(confirmation: "DELETE")
        XCTAssertEqual(result, .failed(.notLoggedIn))
        XCTAssertTrue(f.server.calls.isEmpty)
        XCTAssertTrue(f.auth.options.isEmpty)
    }

    // MARK: - Wipe error collection

    func testAFailingWipeStepIsReportedAndTheRestStillRuns() async {
        struct Boom: Error, LocalizedError { var errorDescription: String? { "boom" } }
        let f = makeFixture()
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

    func testALockedKeystoreIsSkippedNotReportedAsAFailure() async {
        let f = makeFixture()
        f.keystore.isUnlocked = false

        let result = await f.wallet.deleteAccount(confirmation: "DELETE")

        XCTAssertEqual(result, .deleted(localWipe: LocalWipeReport()))
        XCTAssertTrue(f.registry.listAccounts().isEmpty)
    }
}
