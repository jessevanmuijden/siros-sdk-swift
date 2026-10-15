// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
import SirosAuth
import SirosCredentials
@testable import SirosKeystore
@testable import SirosWallet

/// `SirosWallet.addPasskey` (go-wallet-backend#352): the begin -> authorising
/// assertion -> creation -> finish sequence, the PRF key for the new passkey,
/// every backend outcome as a result value, and the invariant that local state
/// changes only when the backend accepted the passkey. Stubs only.
final class SirosWalletAddPasskeyTests: XCTestCase {

    private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
        private let lock = NSLock()
        private(set) var assertions: [AuthenticateOptions] = []
        private(set) var registrations: [RegisterOptions] = []
        private(set) var order: [String] = []
        private(set) var rollbackCalls = 0
        var assertionFailure: Error?
        var registerFailure: Error?
        var prf: PrfOutput? = PrfOutput(first: Data(repeating: 0x42, count: 32))
        var prfCeremony: Result<PrfOutput, Error> = .failure(SirosError.auth(message: "no prf"))
        func register(options: RegisterOptions) async throws -> RegisterResult {
            lock.lock(); registrations.append(options); order.append("create"); lock.unlock()
            if let registerFailure { throw registerFailure }
            return RegisterResult(
                credentialId: Data("new-pk".utf8), attestationObject: Data([7]), clientDataJSON: Data([8]), prfOutput: prf
            )
        }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult {
            lock.lock(); assertions.append(options); order.append("assert"); lock.unlock()
            if let assertionFailure { throw assertionFailure }
            return AuthenticateResult(
                credentialId: Data("pk-1".utf8), authenticatorData: Data([1]), clientDataJSON: Data([2]),
                signature: Data([3]), userHandle: Data([4])
            )
        }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { try prfCeremony.get() }
        func rollbackLastRegistration() {
            lock.lock(); rollbackCalls += 1; lock.unlock()
        }
    }

    /// A one-shot async gate: `wait()` suspends until `open()` is called
    /// (from anywhere, possibly never, possibly before `wait()` is even
    /// reached). Used to force a deterministic interleaving between
    /// `addPasskey()`'s in-flight `register-finish` and a concurrent
    /// operation the test wants to run while it is still pending.
    private final actor Gate {
        private var opened = false
        private var waiters: [CheckedContinuation<Void, Never>] = []
        func wait() async {
            if opened { return }
            await withCheckedContinuation { waiters.append($0) }
        }
        func open() {
            opened = true
            let pending = waiters
            waiters = []
            for w in pending { w.resume() }
        }
    }

    private final class RecordingKeystore: KeystoreManager, @unchecked Sendable {
        var isUnlocked = true
        var prepareError: Error?
        private let opLock = NSLock()
        private(set) var prepared: [(credentialId: Data, prfOutput: Data, prfSalt: Data, hkdfSalt: Data, hkdfInfo: Data)] = []
        private(set) var committed: [Data] = []
        /// Records "commit"/"export" in the order the keystore actually saw
        /// them - what `testADelayedFinishDoesNotLetAConcurrentSyncEraseTheNewEntry`
        /// checks: a concurrent `persistAndSyncKeystore()` must never export
        /// BEFORE an in-flight `addPasskey()`'s accepted enrolment commits.
        private(set) var operationOrder: [String] = []
        func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
        func lock() { isUnlocked = false }
        func preparePrfKey(
            credentialId: Data, prfOutput: Data, prfSalt: Data, hkdfSalt: Data, hkdfInfo: Data
        ) async throws -> PreparedPrfKey {
            if let prepareError { throw prepareError }
            prepared.append((credentialId, prfOutput, prfSalt, hkdfSalt, hkdfInfo))
            return PreparedPrfKey(container: Data("container-for-new-pk".utf8), credentialId: credentialId)
        }
        func commitPrfKey(_ prepared: PreparedPrfKey) async throws {
            opLock.lock(); committed.append(prepared.credentialId); operationOrder.append("commit"); opLock.unlock()
        }
        func generateKey(algorithm: String) async throws -> String { "key" }
        func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
        func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "" }
        func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
        func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
        func exportEncryptedContainer() async throws -> Data {
            opLock.lock(); operationOrder.append("export"); opLock.unlock()
            return Data("exported".utf8)
        }
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
    }

    private final class Server: @unchecked Sendable {
        struct Call { let method: String; let path: String; let headers: [String: String]; let body: [String: Any]? }
        private let lock = NSLock()
        private(set) var calls: [Call] = []
        static let create = #""createOptions":{"publicKey":{"rp":{"id":"wallet.example.com","name":"Wallet"},"user":{"id":{"$b64u":"dXNlcg"},"name":"alice","displayName":"Alice"},"challenge":{"$b64u":"AQID"}}}"#
        static let authorization = #""authorization":{"publicKey":{"rpId":"wallet.example.com","challenge":{"$b64u":"BAUG"},"allowCredentials":[{"type":"public-key","id":{"$b64u":"cGstMQ"}}],"userVerification":"required"}}"#
        var begin: Result<String, Error> = .success(#"{"username":"alice","challengeId":"ch-1",\#(create),\#(authorization)}"#)
        var finish: Result<String, Error> = .success(#"{"credentialId":"bmV3LXBr"}"#)
        /// When set, `register-finish` and `private-data` POSTs wait for it
        /// before returning - lets a test force an exact interleaving with a
        /// concurrent operation instead of racing on timing.
        var finishGate: Gate?
        /// Opened the moment a `register-finish` request is actually sent,
        /// so a test can wait for "the finish is in flight" without a guess.
        let finishStarted = Gate()

        func failFinish(_ code: Int, _ body: String) {
            finish = .failure(SirosError.backendApi(code: code, message: "failed", body: body))
        }

        var httpFn: @Sendable (String, URL, [String: String], Data?) async throws -> Data {
            { [self] method, url, headers, body in
                lock.lock()
                calls.append(Call(
                    method: method, path: url.path, headers: headers,
                    body: body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                ))
                lock.unlock()
                if url.path.hasSuffix("register-finish") {
                    await finishStarted.open()
                    await finishGate?.wait()
                }
                return Data(try (url.path.hasSuffix("register-begin") ? begin : finish).get().utf8)
            }
        }
    }

    private struct Fixture {
        let wallet: SirosWallet
        let server: Server
        let auth: StubAuthProvider
        let keystore: RecordingKeystore
        let sessionStore: InMemorySessionStore
        let registry: AccountRegistry
    }

    private static let hkdfSalt = Data(repeating: 0x11, count: 32)

    private func makeFixture(loggedIn: Bool = true) -> Fixture {
        let auth = StubAuthProvider()
        let keystore = RecordingKeystore()
        let sessionStore = InMemorySessionStore()
        let registry = AccountRegistry.inMemory()
        let wallet = SirosWallet(
            config: WalletConfig(backendUrl: "https://wallet.example.invalid"),
            authProvider: auth, sessionStore: sessionStore, keystore: keystore, accountRegistry: registry
        )!
        let account = CachedAccount(
            userId: "user-1", tenantId: "default", displayName: "user-1", backendUrl: "https://wallet.example.invalid",
            passkeys: [CachedPasskey(credentialId: "cGstMQ", prfSalt: "c2FsdA==")]
        )
        registry.upsertAccount(account)
        registry.activeAccountId = account.accountId
        sessionStore.activeAccountId = account.accountId
        sessionStore.hkdfSalt = Self.hkdfSalt.base64EncodedString()
        sessionStore.hkdfInfo = Data("eDiplomas PRF".utf8).base64EncodedString()
        sessionStore.privateDataJwe = "old-container"

        let server = Server()
        if loggedIn {
            let client = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: server.httpFn)
            client.setAppToken("t")
            wallet.apiClient = client
        }
        return Fixture(wallet: wallet, server: server, auth: auth, keystore: keystore, sessionStore: sessionStore, registry: registry)
    }

    private func assertUnchanged(_ f: Fixture, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(f.sessionStore.privateDataJwe, "old-container", "container not replaced", file: file, line: line)
        XCTAssertTrue(f.keystore.committed.isEmpty, "keystore container untouched", file: file, line: line)
        XCTAssertEqual(f.registry.findAccount(accountId: "default:user-1")?.passkeys.map(\.credentialId), ["cGstMQ"], file: file, line: line)
    }

    // MARK: - Success

    func testAddsAPasskeyAuthorisedByAnExistingOneAskingTheAuthorizerFirst() async throws {
        let f = makeFixture()

        let result = try await f.wallet.addPasskey(nickname: "Laptop")

        XCTAssertEqual(result, .added(credentialId: "bmV3LXBr"))
        // The assertion over the backend's options, with user verification,
        // and before the creation.
        XCTAssertEqual(f.auth.order, ["assert", "create"])
        XCTAssertEqual(f.auth.assertions[0].challenge, Data([4, 5, 6]))
        XCTAssertEqual(f.auth.assertions[0].allowCredentials?.map(\.id), [Data("pk-1".utf8)])
        XCTAssertEqual(f.auth.assertions[0].userVerification, "required")
        XCTAssertNil(f.auth.assertions[0].prfSalt)
        // The creation over the creation challenge, asking for PRF.
        XCTAssertEqual(f.auth.registrations.count, 1)
        XCTAssertEqual(f.auth.registrations[0].challenge, Data([1, 2, 3]))
        XCTAssertEqual(f.auth.registrations[0].userId, Data("user".utf8))
        let prfSalt = try XCTUnwrap(f.auth.registrations[0].prfSalt)
        XCTAssertEqual(prfSalt.count, 32)

        // Both ceremonies in the one finish.
        XCTAssertEqual(f.server.calls.map { "\($0.method) \($0.path)" },
                       ["POST /user/session/webauthn/register-begin", "POST /user/session/webauthn/register-finish"])
        let body = try XCTUnwrap(f.server.calls[1].body)
        XCTAssertEqual(body["challengeId"] as? String, "ch-1")
        XCTAssertEqual(body["nickname"] as? String, "Laptop")
        let credential = body["credential"] as? [String: Any]
        XCTAssertEqual(credential?["id"] as? String, SirosWallet.b64UrlEncode(Data("new-pk".utf8)))
        let authorization = body["authorization"] as? [String: Any]
        XCTAssertEqual(authorization?["id"] as? String, SirosWallet.b64UrlEncode(Data("pk-1".utf8)))
        XCTAssertEqual((authorization?["response"] as? [String: Any])?["signature"] as? String, SirosWallet.b64UrlEncode(Data([3])))
        let sent = (body["privateData"] as? [String: Any])?["$b64u"] as? String
        XCTAssertEqual(sent, SirosWallet.b64UrlEncode(Data("container-for-new-pk".utf8)))

        // The new passkey's own PRF entry: its own HKDF salt, the salt it was
        // created with.
        XCTAssertEqual(f.keystore.prepared.count, 1)
        XCTAssertEqual(f.keystore.prepared[0].credentialId, Data("new-pk".utf8))
        XCTAssertEqual(f.keystore.prepared[0].prfOutput, Data(repeating: 0x42, count: 32))
        XCTAssertEqual(f.keystore.prepared[0].prfSalt, prfSalt)
        XCTAssertEqual(f.keystore.prepared[0].hkdfSalt.count, 32)
        XCTAssertNotEqual(f.keystore.prepared[0].hkdfSalt, Self.hkdfSalt, "not the account's first passkey's salt")
        XCTAssertEqual(f.keystore.prepared[0].hkdfInfo, Data("eDiplomas PRF".utf8))

        // Committed, and local state follows the accepted enrolment.
        XCTAssertEqual(f.keystore.committed, [Data("new-pk".utf8)])
        XCTAssertEqual(f.sessionStore.privateDataJwe, "container-for-new-pk")
        let passkeys = f.registry.findAccount(accountId: "default:user-1")?.passkeys
        XCTAssertEqual(passkeys?.map(\.credentialId), ["cGstMQ", SirosWallet.b64UrlEncode(Data("new-pk".utf8))])
        XCTAssertEqual(passkeys?.last?.prfSalt, prfSalt.base64EncodedString())
        XCTAssertEqual(passkeys?.last?.nickname, "Laptop")
    }

    func testTheAuthorizerReplacesTheAuthProviderForTheAssertionOnly() async throws {
        let f = makeFixture()

        let result = try await f.wallet.addPasskey(nickname: "n") { _ in
            AuthenticateResult(credentialId: Data("sk".utf8), authenticatorData: Data(), clientDataJSON: Data(), signature: Data([9]))
        }

        guard case .added = result else { return XCTFail("got \(result)") }
        XCTAssertTrue(f.auth.assertions.isEmpty)
        XCTAssertEqual(f.auth.registrations.count, 1)
        let authorization = f.server.calls[1].body?["authorization"] as? [String: Any]
        XCTAssertEqual(authorization?["id"] as? String, SirosWallet.b64UrlEncode(Data("sk".utf8)))
    }

    func testAnAccountWithoutAPasskeyNeedsNoAuthorization() async throws {
        let f = makeFixture()
        f.server.begin = .success(#"{"username":"alice","challengeId":"ch-1",\#(Server.create)}"#)

        let result = try await f.wallet.addPasskey(nickname: "First")

        guard case .added = result else { return XCTFail("got \(result)") }
        XCTAssertTrue(f.auth.assertions.isEmpty, "nothing to authorise with")
        XCTAssertNil(f.server.calls[1].body?["authorization"])
    }

    func testAnAuthenticatorWithoutPrfInTheCreationUsesASeparateCeremony() async throws {
        let f = makeFixture()
        f.auth.prf = nil
        f.auth.prfCeremony = .success(PrfOutput(first: Data(repeating: 0x55, count: 32)))
        let result = try await f.wallet.addPasskey(nickname: "n")
        guard case .added = result else { return XCTFail("got \(result)") }
        XCTAssertEqual(f.keystore.prepared.first?.prfOutput, Data(repeating: 0x55, count: 32))
    }

    // MARK: - Backend refusals change nothing local

    func testFinishOutcomesAreValuesAndNothingIsCommitted() async throws {
        let cases: [(Int, String, AddPasskeyResult)] = [
            (401, #"{"error":"ENROLLMENT_AUTHORIZATION_REQUIRED","message":"m"}"#, .authorizationRequired(message: "m")),
            (401, #"{"error":"ENROLLMENT_AUTHORIZATION_FAILED","message":"m"}"#, .authorizationFailed(message: "m")),
            (412, "", .privateDataConflict(message: nil)),
            (404, "{}", .retryNeeded(reason: nil)),
            (400, #"{"error":"bad"}"#, .registrationRejected(message: "bad")),
            (403, #"{"error":"Authenticator not allowed"}"#, .registrationRejected(message: "Authenticator not allowed")),
            (401, #"{"error":"Unauthorized"}"#, .sessionRevoked(message: nil)),
        ]
        for (code, body, expected) in cases {
            let f = makeFixture()
            f.server.failFinish(code, body)
            let result = try await f.wallet.addPasskey(nickname: "n")
            XCTAssertEqual(result, expected, "\(code) \(body)")
            XCTAssertTrue(f.keystore.committed.isEmpty, "keystore untouched: \(code)")
            // Regression: the platform credential `authProvider.register`
            // already created must be rolled back on every refusal - not
            // just believed to be, by a test double that can't tell.
            XCTAssertEqual(f.auth.rollbackCalls, 1, "must roll back the created credential: \(code) \(body)")
            assertUnchanged(f)
        }
    }

    func testATransportFailureOnFinishThrowsAndCommitsNothing() async {
        let f = makeFixture()
        f.server.failFinish(500, "")
        do {
            _ = try await f.wallet.addPasskey(nickname: "n")
            XCTFail("a 500 is outside the contract")
        } catch SirosError.backendApi(let code, _, _) {
            XCTAssertEqual(code, 500)
        } catch { XCTFail("\(error)") }
        XCTAssertTrue(f.keystore.committed.isEmpty)
        XCTAssertEqual(f.auth.rollbackCalls, 1, "a transport failure on finish must still roll back the created credential")
        assertUnchanged(f)
    }

    func testBeginRefusalsMapToValuesBeforeAnyCeremony() async throws {
        for (code, expected) in [
            (401, AddPasskeyResult.sessionRevoked(message: nil)),
            (403, .insufficientScope(message: "no scope")),
        ] {
            let f = makeFixture()
            f.server.begin = .failure(SirosError.backendApi(code: code, message: "x", body: #"{"message":"no scope"}"#))
            let result = try await f.wallet.addPasskey(nickname: "n")
            if code == 401 { guard case .sessionRevoked = result else { return XCTFail("\(result)") } } else {
                XCTAssertEqual(result, expected)
            }
            XCTAssertTrue(f.auth.assertions.isEmpty && f.auth.registrations.isEmpty)
            XCTAssertEqual(f.auth.rollbackCalls, 0, "nothing was ever created, so there is nothing to roll back")
            assertUnchanged(f)
        }
    }

    // MARK: - Local failures

    func testADeclinedAssertionCreatesNoPasskeyAndSendsNoFinish() async throws {
        struct Cancelled: Error, LocalizedError { var errorDescription: String? { "user cancelled" } }
        let f = makeFixture()
        f.auth.assertionFailure = Cancelled()
        let result = try await f.wallet.addPasskey(nickname: "n")
        XCTAssertEqual(result, .authorizerUnavailable(message: "user cancelled"))
        XCTAssertTrue(f.auth.registrations.isEmpty, "no stray platform passkey")
        XCTAssertEqual(f.server.calls.count, 1)
        assertUnchanged(f)
    }

    func testADeclinedCreationSendsNoFinish() async throws {
        struct Cancelled: Error, LocalizedError { var errorDescription: String? { "no thanks" } }
        let f = makeFixture()
        f.auth.registerFailure = Cancelled()
        let result = try await f.wallet.addPasskey(nickname: "n")
        XCTAssertEqual(result, .passkeyCreationUnavailable(message: "no thanks"))
        XCTAssertEqual(f.server.calls.count, 1)
        XCTAssertTrue(f.keystore.prepared.isEmpty)
        assertUnchanged(f)
    }

    func testAPasskeyWithoutPrfIsNeverRegistered() async throws {
        let f = makeFixture()
        f.auth.prf = nil
        let result = try await f.wallet.addPasskey(nickname: "n")
        guard case .prfUnsupported = result else { return XCTFail("got \(result)") }
        XCTAssertEqual(f.server.calls.count, 1, "a passkey that cannot unlock the data must not be enrolled")
        XCTAssertTrue(f.keystore.prepared.isEmpty)
        // Regression: the platform credential was already created (the PRF
        // ceremony's own separate assertion retry - `resolvePrfOutput`'s
        // fallback to `getPrfOutput` - is what actually failed here, not the
        // creation itself), so it must be rolled back rather than left
        // orphaned on the device.
        XCTAssertEqual(f.auth.rollbackCalls, 1, "an authenticator that cannot produce PRF must not leave an orphaned credential")
        assertUnchanged(f)
    }

    func testAKeystoreThatCannotPrepareTheKeyBlocksTheEnrolment() async {
        struct Boom: Error {}
        let f = makeFixture()
        f.keystore.prepareError = Boom()
        do {
            _ = try await f.wallet.addPasskey(nickname: "n")
            XCTFail("must throw")
        } catch is Boom {} catch { XCTFail("\(error)") }
        XCTAssertEqual(f.server.calls.count, 1)
        XCTAssertEqual(f.auth.rollbackCalls, 1, "a local keystore failure must still roll back the created credential")
        assertUnchanged(f)
    }

    func testALockedKeystoreIsAValueAndNoSessionOrBlankNicknameThrowBeforeAnyRequest() async throws {
        let f = makeFixture()
        f.keystore.isUnlocked = false
        let locked = try await f.wallet.addPasskey(nickname: "n")
        XCTAssertEqual(locked, .walletLocked(message: nil))
        XCTAssertTrue(f.server.calls.isEmpty)

        let g = makeFixture(loggedIn: false)
        do { _ = try await g.wallet.addPasskey(nickname: "n"); XCTFail("not logged in") } catch {}
        let h = makeFixture()
        do { _ = try await h.wallet.addPasskey(nickname: "  "); XCTFail("blank nickname") } catch {}
        XCTAssertTrue(g.server.calls.isEmpty && h.server.calls.isEmpty)
    }

    // MARK: - A second passkey can log in (own PRF entry's HKDF parameters)

    /// The container as it is after `addPasskey`: one PRF entry per passkey,
    /// each with its own HKDF salt, which is what the keystore picks by.
    private func twoPasskeyContainer(first: Data, second: Data, firstSalt: Data, secondSalt: Data) throws -> Data {
        func entry(_ credentialId: Data, hkdfSalt: Data, hkdfInfo: String) -> PrfKeyInfo {
            let key = EncapsulationKeypairInfo(
                publicKey: EncapsulationPublicKeyInfo(importKey: ImportKeyInfo(
                    format: "raw", keyData: Data([4]), algorithm: EcKeyAlgorithm(name: "ECDH", namedCurve: "P-256"))),
                privateKey: EncapsulationPrivateKeyInfo(unwrapKey: PrivateKeyUnwrapInfo(
                    format: "jwk", wrappedKey: Data([1]), unwrapAlgo: AesGcmAlgo(name: "AES-GCM", iv: Data([2])),
                    unwrappedKeyAlgo: EcKeyAlgorithm(name: "ECDH", namedCurve: "P-256")))
            )
            return PrfKeyInfo(
                credentialId: credentialId, transports: nil, prfSalt: Data([9]), hkdfSalt: hkdfSalt,
                hkdfInfo: Data(hkdfInfo.utf8), algorithm: nil, keypair: key,
                unwrapKey: StaticUnwrapKeyInfo(wrappedKey: Data([3]), unwrappingKey: UnwrappingKeyInfo(
                    deriveKey: DeriveKeyInfo(algorithm: AlgorithmName(name: "ECDH"),
                                             derivedKeyAlgorithm: AesKwAlgorithm(name: "AES-KW", length: 256))))
            )
        }
        let mainKey = MainKeyInfo(
            publicKey: EncapsulationPublicKeyInfo(importKey: ImportKeyInfo(
                format: "raw", keyData: Data([4]), algorithm: EcKeyAlgorithm(name: "ECDH", namedCurve: "P-256"))),
            unwrapKey: MainUnwrapKeyInfo(format: "raw", unwrapAlgo: "AES-KW",
                                         unwrappedKeyAlgo: AesGcmKeyAlgorithm(name: "AES-GCM", length: 256))
        )
        return try EncryptedContainer.serialize(ContainerData(jwe: "a.b.c.d.e", mainKey: mainKey, prfKeys: [
            entry(first, hkdfSalt: firstSalt, hkdfInfo: "first info"),
            entry(second, hkdfSalt: secondSalt, hkdfInfo: "second info"),
        ]))
    }

    func testLoginWithTheSecondPasskeyDerivesWithItsOwnEntrysHkdfParameters() async throws {
        let f = makeFixture()
        let firstSalt = Data(repeating: 0x11, count: 32), secondSalt = Data(repeating: 0x22, count: 32)
        let container = try twoPasskeyContainer(
            first: Data("pk-1".utf8), second: Data("pk-2".utf8), firstSalt: firstSalt, secondSalt: secondSalt
        )
        // The session store holds the FIRST passkey's parameters, as after a
        // registration or an earlier login with it.
        f.sessionStore.hkdfSalt = firstSalt.base64EncodedString()
        f.sessionStore.hkdfInfo = Data("first info".utf8).base64EncodedString()
        let assertion = SirosWallet.PasskeyAssertion(
            challengeId: "c", credential: [:], prfOutput: PrfOutput(first: Data([1])), prfSalt: Data([9]),
            cachedAccount: nil, credentialId: Data("pk-2".utf8)
        )

        let resolved = try await f.wallet.resolveLoginPrf(assertion: assertion, privateData: container, cachedAccount: nil)

        XCTAssertEqual(resolved.hkdfSalt, secondSalt)
        XCTAssertEqual(resolved.hkdfInfo, Data("second info".utf8))

        // And the first passkey still gets its own.
        let first = SirosWallet.PasskeyAssertion(
            challengeId: "c", credential: [:], prfOutput: PrfOutput(first: Data([1])), prfSalt: Data([9]),
            cachedAccount: nil, credentialId: Data("pk-1".utf8)
        )
        let again = try await f.wallet.resolveLoginPrf(assertion: first, privateData: container, cachedAccount: nil)
        XCTAssertEqual(again.hkdfSalt, firstSalt)
    }

    func testUnlockingWithTheSecondPasskeyDerivesWithItsOwnEntrysHkdfParameters() async throws {
        let f = makeFixture()
        let firstSalt = Data(repeating: 0x11, count: 32), secondSalt = Data(repeating: 0x22, count: 32)
        let container = try twoPasskeyContainer(
            first: Data("pk-1".utf8), second: Data("pk-2".utf8), firstSalt: firstSalt, secondSalt: secondSalt
        )
        f.sessionStore.hkdfSalt = firstSalt.base64EncodedString()
        f.sessionStore.hkdfInfo = Data("first info".utf8).base64EncodedString()
        let assertion = SirosWallet.PasskeyAssertion(
            challengeId: "c", credential: [:], prfOutput: PrfOutput(first: Data([1])), prfSalt: Data([9]),
            cachedAccount: nil, credentialId: Data("pk-2".utf8)
        )

        let resolved = try await f.wallet.resolveUnlockKeystorePrf(assertion: assertion, storedContainer: container)

        XCTAssertEqual(resolved.hkdfSalt, secondSalt)
        XCTAssertEqual(resolved.hkdfInfo, Data("second info".utf8))
    }

    // MARK: - The original passkey's entry may be anonymous (review finding)

    /// Regression: `register()` used to leave the ORIGINAL passkey's PRF
    /// entry with an empty credential id (it never called
    /// `keystore.setCredentialId` - see that method's doc comment and
    /// `JweKeystore.setCredentialId`'s). After logging in with a SECOND
    /// (added) passkey, the session caches that passkey's HKDF salt; resuming
    /// and unlocking with the ORIGINAL passkey must still find its own entry
    /// by the verified-anonymous-entry fallback, not silently reuse the
    /// second passkey's salt from the session store and fail to decrypt (or
    /// decrypt with the wrong key).
    func testUnlockingWithTheOriginalPasskeyFindsItsAnonymousEntryRatherThanTheSessionsSecondPasskeySalt() async throws {
        let f = makeFixture()
        let originalCredentialId = Data("pk-1".utf8)
        let secondCredentialId = Data("pk-2".utf8)
        let originalSalt = Data(repeating: 0x11, count: 32)
        let secondSalt = Data(repeating: 0x22, count: 32)
        // Shaped the way a pre-fix `register()` left it: an ANONYMOUS first
        // entry (empty credential id), exactly like `JweKeystore.unlock`'s
        // first-time-setup branch without the follow-up `setCredentialId`.
        let container = try twoPasskeyContainer(
            first: Data(), second: secondCredentialId, firstSalt: originalSalt, secondSalt: secondSalt
        )
        // The registry's FIRST passkey is the original one - what verifies
        // the anonymous entry actually belongs to THIS credential, rather
        // than guessing.
        let account = CachedAccount(
            userId: "user-1", tenantId: "default", displayName: "user-1", backendUrl: "https://wallet.example.invalid",
            passkeys: [
                CachedPasskey(credentialId: SirosWallet.b64UrlEncode(originalCredentialId), prfSalt: originalSalt.base64EncodedString()),
                CachedPasskey(credentialId: SirosWallet.b64UrlEncode(secondCredentialId), prfSalt: secondSalt.base64EncodedString()),
            ]
        )
        // The session caches the SECOND passkey's salt, as after a login
        // with it - what the bug would otherwise silently fall back to.
        f.sessionStore.hkdfSalt = secondSalt.base64EncodedString()
        f.sessionStore.hkdfInfo = Data("second info".utf8).base64EncodedString()
        let assertion = SirosWallet.PasskeyAssertion(
            challengeId: "c", credential: [:], prfOutput: PrfOutput(first: Data([1])), prfSalt: Data([9]),
            cachedAccount: account, credentialId: originalCredentialId
        )

        let resolved = try await f.wallet.resolveUnlockKeystorePrf(assertion: assertion, storedContainer: container)

        XCTAssertEqual(resolved.hkdfSalt, originalSalt, "must use the original passkey's own (anonymous) entry, not the session's second-passkey salt")
        XCTAssertEqual(resolved.hkdfInfo, Data("first info".utf8))
    }

    /// Same fallback, on the login path (`resolveLoginPrf`).
    func testLoginWithTheOriginalPasskeyFindsItsAnonymousEntryRatherThanTheSessionsSecondPasskeySalt() async throws {
        let f = makeFixture()
        let originalCredentialId = Data("pk-1".utf8)
        let secondCredentialId = Data("pk-2".utf8)
        let originalSalt = Data(repeating: 0x11, count: 32)
        let secondSalt = Data(repeating: 0x22, count: 32)
        let container = try twoPasskeyContainer(
            first: Data(), second: secondCredentialId, firstSalt: originalSalt, secondSalt: secondSalt
        )
        let account = CachedAccount(
            userId: "user-1", tenantId: "default", displayName: "user-1", backendUrl: "https://wallet.example.invalid",
            passkeys: [
                CachedPasskey(credentialId: SirosWallet.b64UrlEncode(originalCredentialId), prfSalt: originalSalt.base64EncodedString()),
                CachedPasskey(credentialId: SirosWallet.b64UrlEncode(secondCredentialId), prfSalt: secondSalt.base64EncodedString()),
            ]
        )
        f.sessionStore.hkdfSalt = secondSalt.base64EncodedString()
        f.sessionStore.hkdfInfo = Data("second info".utf8).base64EncodedString()
        let assertion = SirosWallet.PasskeyAssertion(
            challengeId: "c", credential: [:], prfOutput: PrfOutput(first: Data([1])), prfSalt: Data([9]),
            cachedAccount: account, credentialId: originalCredentialId
        )

        let resolved = try await f.wallet.resolveLoginPrf(assertion: assertion, privateData: container, cachedAccount: account)

        XCTAssertEqual(resolved.hkdfSalt, originalSalt)
        XCTAssertEqual(resolved.hkdfInfo, Data("first info".utf8))
    }

    func testAContainerWithoutAnEntryForThePasskeyFallsBackToTheSessionParameters() async throws {
        let f = makeFixture()
        let assertion = SirosWallet.PasskeyAssertion(
            challengeId: "c", credential: [:], prfOutput: PrfOutput(first: Data([1])), prfSalt: Data([9]),
            cachedAccount: nil, credentialId: Data("unknown".utf8)
        )
        let resolved = try await f.wallet.resolveLoginPrf(assertion: assertion, privateData: Data(), cachedAccount: nil)
        XCTAssertEqual(resolved.hkdfSalt, Self.hkdfSalt)
    }

    // MARK: - Concurrency (review findings)

    /// Regression: a concurrent `persistAndSyncKeystore()` (an unrelated
    /// issuance/presentation/deletion) must never export the container
    /// BEFORE an in-flight `addPasskey()`'s accepted enrolment commits its
    /// new PRF entry - otherwise the export reflects the pre-commit state
    /// and, if it then wins the race to the server, silently erases the
    /// entry the backend just accepted.
    func testADelayedFinishDoesNotLetAConcurrentKeystoreSyncExportBeforeCommit() async throws {
        let f = makeFixture()
        let gate = Gate()
        f.server.finishGate = gate

        let addTask = Task { try await f.wallet.addPasskey(nickname: "Laptop") }
        await f.server.finishStarted.wait()

        // Start the concurrent sync while finish is still pending. Without
        // `keystoreContainerLock` there is nothing else for it to wait on,
        // so it would run its export immediately; give it real wall-clock
        // time to do so before releasing finish, so a missing lock shows up
        // deterministically rather than by a timing accident.
        async let syncTask: Void = f.wallet.persistAndSyncKeystore()
        try await Task.sleep(nanoseconds: 100_000_000)
        await gate.open()

        let result = try await addTask.value
        _ = try await syncTask
        guard case .added = result else { return XCTFail("got \(result)") }
        XCTAssertEqual(
            f.keystore.operationOrder.first, "commit",
            "a concurrent sync must not export before the accepted enrolment is committed: \(f.keystore.operationOrder)"
        )
    }

    /// Regression: after a session resume, the `BackendApiClient` is fresh
    /// and has no ETag of its own (see `BackendApiClient.privateDataEtag`'s
    /// doc comment) - `addPasskey` must fall back to the one persisted
    /// alongside the cached container (`sessionStore.privateDataEtag`)
    /// rather than silently omitting `If-Match` and risking a stale-cache
    /// overwrite of another device's changes.
    func testResumeAfterRestartUsesTheStoredPrivateDataEtagAsThePrecondition() async throws {
        let f = makeFixture()
        f.sessionStore.privateDataEtag = "etag-from-before-restart"
        // A fresh client, as `resumeSession()`/`unlockKeystore()` build -
        // it has learnt nothing yet.
        let freshClient = BackendApiClient(baseUrl: "https://wallet.example.invalid", httpFn: f.server.httpFn)
        freshClient.setAppToken("t")
        f.wallet.apiClient = freshClient

        let result = try await f.wallet.addPasskey(nickname: "Laptop")

        guard case .added = result else { return XCTFail("got \(result)") }
        let finishCall = f.server.calls[1]
        XCTAssertEqual(finishCall.headers["X-Private-Data-If-Match"], "etag-from-before-restart")
    }

    /// Regression: if the session moves on (a logout, or a login/re-login -
    /// possibly to a DIFFERENT account) while this enrolment's backend round
    /// trip is still in flight, the accepted response must be discarded
    /// rather than applied to whatever account/keystore happens to be active
    /// when it arrives - otherwise `commitPrfKey` would append the
    /// originating account's entry to the new session's now-unlocked
    /// keystore, and the cache writes would record it under the wrong
    /// identity.
    func testASessionSwitchWhileFinishIsInFlightDiscardsTheResultWithoutCorruptingTheNewSession() async throws {
        let f = makeFixture()
        let gate = Gate()
        f.server.finishGate = gate

        let addTask = Task { try await f.wallet.addPasskey(nickname: "Laptop") }
        await f.server.finishStarted.wait()

        // Simulate a logout (of the account this call started for) while
        // the backend round trip is still pending.
        f.wallet.bumpSessionGeneration()
        await gate.open()

        let result = try await addTask.value
        guard case .sessionChanged = result else { return XCTFail("got \(result)") }
        // The backend DID accept it, but nothing local was touched: the
        // single, reused keystore instance was not mutated, and the
        // account cache still shows only the original passkey.
        XCTAssertTrue(f.keystore.committed.isEmpty, "must not commit into the keystore of a session that moved on")
        assertUnchanged(f)
    }

    // MARK: - excludeCredentials (review finding)

    /// Regression: the backend's `excludeCredentials` must actually reach the
    /// authenticator, so an authenticator that would otherwise replace an
    /// existing discoverable credential for the same RP/user is told not to.
    func testExcludeCredentialsFromTheBeginResponseReachTheRegistrationRequest() async throws {
        let f = makeFixture()
        f.server.begin = .success(
            #"""
            {"username":"alice","challengeId":"ch-1","createOptions":{"publicKey":{
                "rp":{"id":"wallet.example.com","name":"Wallet"},
                "user":{"id":{"$b64u":"dXNlcg"},"name":"alice","displayName":"Alice"},
                "challenge":{"$b64u":"AQID"},
                "excludeCredentials":[{"type":"public-key","id":{"$b64u":"cGstMQ"}}]
            }},\#(Server.authorization)}
            """#
        )

        let result = try await f.wallet.addPasskey(nickname: "Laptop")

        guard case .added = result else { return XCTFail("got \(result)") }
        XCTAssertEqual(f.auth.registrations.count, 1)
        XCTAssertEqual(f.auth.registrations[0].excludeCredentials?.map(\.id), [Data("pk-1".utf8)])
    }
}
