// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
@testable import SirosKeystore
import SirosTransport
@testable import SirosWallet

#if canImport(CryptoKit)
import CryptoKit

private final class NoAuth: AuthProvider, @unchecked Sendable {
    struct E: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw E() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw E() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw E() }
}

/// A `Signer` that signs nothing real: the tests inspect the KB-JWT claims. Its SCA sign runs the
/// production `ScaSignFlow` against a scripted plugin (R2PS, a 6-digit PIN typed, factors reported).
private final class ZeroSigner: Signer, @unchecked Sendable {
    private let key = P256.Signing.PrivateKey()
    var capability = SignerFactorCapability(canReachTwoCategories: true)
    /// Thrown by the SCA sign before anything is signed (the user backing out of the PIN prompt, say).
    var scaError: Error?
    var applied = [AuthenticationFactor(.possession, "key_in_remote_wscd"), AuthenticationFactor(.knowledge, "pin_6_or_more_digits")]
    func authenticationCapability(keyId: String) async throws -> SignerFactorCapability { capability }
    func signForSca(keyId: String, payload: @escaping ([AuthenticationFactor]) throws -> Data) async throws -> SignerScaOutcome {
        try ScaSignFlow.run(
            pluginId: "r2ps", capability: capability, promptPin: { if let e = self.scaError { throw e }; return Data("123456".utf8) }, payload: payload,
            sign: { [applied] _, _ in
                ScaSignReport(signature: Data(repeating: 2, count: 64), factors: applied,
                              satisfiesTwoCategories: Set(applied.map(\.category)).count >= 2, shortfall: nil)
            }
        )
    }
    func generateKey(algorithm: String) async throws -> String { "k1" }
    func sign(keyId: String, data: Data) async throws -> Data { Data(repeating: 1, count: 64) }
    func listKeys() async throws -> [SignerKeyInfo] { [SignerKeyInfo(keyId: "k1", algorithm: "ES256")] }
    func deleteKey(keyId: String) async throws {}
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func exportPublicKey(keyId: String) async throws -> Data {
        let point = key.publicKey.x963Representation
        func enc(_ d: Data) -> String {
            d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        return try JSONSerialization.data(withJSONObject: [
            "kty": "EC", "crv": "P-256", "x": enc(point.subdata(in: 1..<33)), "y": enc(point.subdata(in: 33..<65)),
        ])
    }
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        SignerSecurityProperties(keyStorage: ["remote_hsm"], userAuthentication: ["pin"], amr: ["hwk", "pop", "pin"])
    }
}

/// A shared, ordered record of what happened, to prove consent comes BEFORE signing.
private final class Events: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String] = []
    func add(_ e: String) { lock.lock(); items.append(e); lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return items }
}

/// Wallet keystore whose SD-JWT signing is the real `WscdKeystoreAdapter`
/// (so the KB-JWT under test is the production one) while the wallet itself
/// sees a locked keystore and skips container persistence.
private final class SigningKeystore: KeystoreManager, @unchecked Sendable {
    let adapter: WscdKeystoreAdapter
    let signer = ZeroSigner()
    private(set) var capabilityQueries: [String] = []
    private(set) var plainCalls = 0
    private(set) var scaCalls = 0
    var events: Events?
    var failSigning = false
    var keys: [KeyInfo] = [KeyInfo(keyId: "k1", algorithm: "ES256", pluginId: "r2ps")]
    private(set) var signingKids: [String?] = []
    /// Runs inside the signing call (to cancel the caller while a signer that ignores cancellation works).
    var duringSigning: (@Sendable () -> Void)?
    struct NotImplemented: Error {}
    struct SigningFailed: Error {}

    init() async throws {
        adapter = WscdKeystoreAdapter(signer: signer)
        try await adapter.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())
    }

    var isUnlocked: Bool { true }
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { throw NotImplemented() }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { throw NotImplemented() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { throw NotImplemented() }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { throw NotImplemented() }

    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String {
        plainCalls += 1
        return try await adapter.signVpToken(credential: credential, disclosedClaims: disclosedClaims, nonce: nonce, audience: audience, kid: kid)
    }

    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String,
                     transactionData: TransactionDataBinding?, kid: String?) async throws -> String {
        scaCalls += 1
        events?.add("sign")
        signingKids.append(kid)
        if failSigning { throw SigningFailed() }
        defer { duringSigning?() }
        return try await adapter.signVpToken(credential: credential, disclosedClaims: disclosedClaims, nonce: nonce,
                                             audience: audience, transactionData: transactionData, kid: kid)
    }

    func signMdocPresentationForDCAPI(credentialBytes: Data, disclosedClaims: [String]?, nonce: String, origin: String,
                                      encryptionPublicJwkThumbprint: String?, kid: String?) async throws -> Data { throw NotImplemented() }
    var duringExport: (@Sendable () -> Void)?
    func exportEncryptedContainer() async throws -> Data { duringExport?(); return Data() }
    func scaAuthenticationCapability(keyId: String) async -> SignerFactorCapability {
        capabilityQueries.append(keyId)
        return await adapter.scaAuthenticationCapability(keyId: keyId)
    }
    func listKeys() -> [KeyInfo] { keys }
    func saveCredential(id: Int64, json: String) async throws {}
    func getCredential(id: Int64) async throws -> String? { nil }
    func getAllCredentials() async throws -> [Int64: String] { [:] }
    func deleteCredential(id: Int64) async throws {}
    func clearCredentials() async throws {}
    func savePresentationRecord(id: Int64, json: String) async throws {}
    func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
    func clearPresentationRecords() async throws {}
    func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    func generateKeyProof(keyId: String, typ: String, issuer: String, audience: String, extraClaims: [String: String]) async throws -> String { throw NotImplemented() }
}

private final class Sender: SignResponseSender, @unchecked Sendable {
    private(set) var sent: [SignResponseMessage] = []
    func sendSignResponse(_ message: SignResponseMessage) { sent.append(message) }
}

private final class Consent: TransactionConsentHandler, @unchecked Sendable {
    var answer = true
    var events: Events?
    /// Runs while the user is "deciding" (to change the world under the wallet).
    var whileDeciding: (@Sendable () async -> Void)?
    private(set) var requests: [TransactionConsentRequest] = []
    func confirm(_ request: TransactionConsentRequest) async throws -> Bool {
        requests.append(request)
        events?.add("consent")
        await whileDeciding?()
        return answer
    }
}

private final class ErrorListener: WalletEventListener, @unchecked Sendable {
    private let lock = NSLock()
    private var _errors: [String] = []
    private var _logFailures = 0
    var errors: [String] { lock.lock(); defer { lock.unlock() }; return _errors }
    var logFailures: Int { lock.lock(); defer { lock.unlock() }; return _logFailures }
    func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] { [] }
    func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) { lock.lock(); _errors.append(errorMessage); lock.unlock() }
    func onTransactionLogFailure() { lock.lock(); _logFailures += 1; lock.unlock() }
}

/// A request in, a KB-JWT out, checked against the verifier contract, once
/// per transport adapter (legacy engine, WMP, DC API).
final class TransactionDataEndToEndTests: XCTestCase {
    private let vct = "https://pay.example/card"
    private let audience = "x509_san_dns:shop.example"
    private let payload = #"{"transaction_id":"tx-1","payee":{"name":"Shop AB","id":"SE1"},"currency":"EUR","amount":49.99}"#

    private func b64(_ s: String) -> String {
        Data(s.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private var raw: String {
        b64(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"transaction_data_hashes_alg":["sha-256"],"payload":\#(payload)}"#)
    }

    private var metadata: String {
        let claims = #"[{"path":["payload","amount"],"visualisation":1,"display":[{"lang":"en","label":"Amount"}]},{"path":["payload","currency"],"visualisation":1,"display":[{"lang":"en","label":"Currency"}]},{"path":["payload","payee","name"],"visualisation":2,"display":[{"lang":"en","label":"Payee"}]},{"path":["payload","payee","id"],"display":[{"lang":"en","label":"Payee ID"}]},{"path":["payload","transaction_id"],"visualisation":4,"display":[{"lang":"en","label":"Transaction"}]}]"#
        let labels = #"{"affirmative_action_label":[{"lang":"en","value":"Confirm Payment"}]}"#
        return #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{"urn:eudi:sca:payment:1":{"schema":"urn:eudi:sca:payment:1","claims":\#(claims),"ui_labels":\#(labels)}}}"#
    }

    private struct Fixture {
        let wallet: SirosWallet
        let keystore: SigningKeystore
        let consent: Consent
        let events: Events
        let listener: ErrorListener
        let store: InMemoryCredentialStore
    }

    private func fixture(enabled: Bool = true, handler: Bool = true, format: String = "dc+sd-jwt", metadataDoc: String? = nil) async throws -> Fixture {
        let jwtPayload = b64(#"{"vct":"\#(vct)"}"#)
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(
            id: 1, format: format, raw: "eyJhbGciOiJFUzI1NiJ9.\(jwtPayload).c2ln~", metadata: CredentialMetadata(name: "Visa card", vct: vct, doctype: nil),
            batchId: 1, instanceId: 0
        ))
        let keystore = try await SigningKeystore()
        let wallet = try XCTUnwrap(SirosWallet(
            config: WalletConfig(backendUrl: "https://example.invalid", credentialStore: store, transactionDataEnabled: enabled),
            authProvider: NoAuth(), keystore: keystore
        ))
        let doc = metadataDoc ?? metadata
        wallet.transactionMetadataFetch = { _, _, _ in doc }
        wallet.apiClient = BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, _, _, _ in
            try JSONSerialization.data(withJSONObject: ["decision": true])
        })
        let consent = Consent()
        let events = Events()
        let listener = ErrorListener()
        consent.events = events
        keystore.events = events
        wallet.setEventListener(listener)
        if handler { wallet.transactionConsentHandler = consent }
        wallet.transactionDataLocale = "en-GB"
        wallet.snapshotTransactionDataEnablement()
        wallet.snapshotWmpSessionEnablement()
        return Fixture(wallet: wallet, keystore: keystore, consent: consent, events: events, listener: listener, store: store)
    }

    private func kbClaims(_ vpToken: String) throws -> [String: Any] {
        let kb = try XCTUnwrap(vpToken.split(separator: "~", omittingEmptySubsequences: false).last.map(String.init))
        let part = try XCTUnwrap(kb.split(separator: ".").dropFirst().first.map(String.init))
        var s = part.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        s += String(repeating: "=", count: (4 - s.count % 4) % 4)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(Data(base64Encoded: s))) as? [String: Any])
    }

    /// The verifier contract of TS12 3.6 / OID4VP Appendix B.
    private func assertVerifierContract(_ claims: [String: Any], responseMode: String, nonce: String, aud: String,
                                        file: StaticString = #filePath, line: UInt = #line) throws {
        let expectedHash = try XCTUnwrap(TransactionDataHashing.hash(raw: raw, algorithm: "sha-256"))
        XCTAssertEqual(claims["transaction_data_hashes"] as? [String], [expectedHash], "hash over the raw string", file: file, line: line)
        XCTAssertEqual(claims["transaction_data_hashes_alg"] as? String, "sha-256", "a string", file: file, line: line)
        XCTAssertEqual(claims["response_mode"] as? String, responseMode, file: file, line: line)
        XCTAssertFalse((claims["jti"] as? String ?? "").isEmpty, file: file, line: line)
        let amr = try XCTUnwrap(claims["amr"] as? [[String: String]], "object-form amr", file: file, line: line)
        XCTAssertEqual(Set(amr.flatMap(\.keys)), ["knowledge", "possession"], file: file, line: line)
        XCTAssertEqual(claims["nonce"] as? String, nonce, file: file, line: line)
        XCTAssertEqual(claims["aud"] as? String, aud, file: file, line: line)
        XCTAssertNotNil(claims["iat"], file: file, line: line)
        XCTAssertNotNil(claims["sd_hash"], file: file, line: line)
    }

    // MARK: - Legacy engine

    private func engineMessage(flow: String = "f1", transactionData: String? = nil, refs: String = #"[{"credential_query_id":"pay","credential_id":"1"}]"#, extra: String = "",
                               nonce: String = "n-1", audience audienceOverride: String? = nil) throws -> SignRequestMessage {
        let td = transactionData ?? #"[{"raw":"\#(raw)","type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":\#(payload),"transaction_data_hashes_alg":["sha-256"]}]"#
        let json = #"{"type":"sign_request","flow_id":"\#(flow)","message_id":"m1","action":"sign_presentation","params":{"audience":"\#(audienceOverride ?? audience)","nonce":"\#(nonce)","response_mode":"direct_post.jwt","credentials_to_include":\#(refs),"transaction_data":\#(td)\#(extra)}}"#
        return try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
    }

    func testEngineProducesAContractKbJwt() async throws {
        let f = try await fixture()
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        let token = try XCTUnwrap(sender.sent.first?.vpToken)
        try assertVerifierContract(try kbClaims(token), responseMode: "direct_post.jwt", nonce: "n-1", aud: audience)
        let shown = try XCTUnwrap(f.consent.requests.first)
        XCTAssertEqual(shown.entries.first?.fields.first?.label, "Amount")
        XCTAssertEqual(shown.credentialName, "Visa card")
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.outcome, .consented)
        XCTAssertEqual(log.first?.transactionId, "tx-1")
    }

    func testEngineRefusesWithoutAHandlerAndSignsNothing() async throws {
        let f = try await fixture(handler: false)
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(sender.sent.count, 1, "answered at once with an empty sign_response")
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
    }

    func testEngineRefusesWhenDisabled() async throws {
        let f = try await fixture(enabled: false)
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
        XCTAssertTrue(f.consent.requests.isEmpty)
    }

    func testEngineDeclineSignsNothingAndIsLogged() async throws {
        let f = try await fixture()
        f.consent.answer = false
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls, 0)
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.outcome, .declined)
    }

    func testEngineRefusesAnOrchestratorHintThatDisagreesWithRaw() async throws {
        let f = try await fixture()
        let tampered = payload.replacingOccurrences(of: "Shop AB", with: "Evil Ltd")
        let td = #"[{"raw":"\#(raw)","type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":\#(tampered)}]"#
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(transactionData: td))
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertTrue(f.consent.requests.isEmpty, "the user is not shown a transaction that disagrees with what would be bound")
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.reason, "inconsistentWithOrchestrator")
    }

    func testEngineRefusesTransactionDataWithoutCredentialsToInclude() async throws {
        let f = try await fixture()
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(refs: "[]"))
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
    }

    func testEngineRefusesTwoCredentialsForOneQuery() async throws {
        let f = try await fixture()
        let store = try XCTUnwrap(f.wallet.credentialStore as? InMemoryCredentialStore)
        let jwtPayload = b64(#"{"vct":"\#(vct)"}"#)
        await store.save(StoredCredential(
            id: 2, format: "dc+sd-jwt", raw: "eyJhbGciOiJFUzI1NiJ9.\(jwtPayload).c2ln~", metadata: CredentialMetadata(name: "Second", vct: vct, doctype: nil),
            batchId: 2, instanceId: 0
        ))
        let refs = #"[{"credential_query_id":"pay","credential_id":"1"},{"credential_query_id":"pay","credential_id":"2"}]"#
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(refs: refs))
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls, 0)
    }

    /// Only the transaction-bound query is limited to one credential: an unbound query may have several.
    func testAnUnboundQueryMayAnswerWithSeveralCredentials() async throws {
        let f = try await fixture()
        let jwtPayload = b64(#"{"vct":"\#(vct)"}"#)
        for id in [2, 3] as [Int64] {
            await f.store.save(StoredCredential(
                id: id, format: "dc+sd-jwt", raw: "eyJhbGciOiJFUzI1NiJ9.\(jwtPayload).c2ln~", metadata: CredentialMetadata(name: "Other \(id)", vct: vct, doctype: nil),
                batchId: id, instanceId: 0
            ))
        }
        let refs = #"[{"credential_query_id":"pay","credential_id":"1"},{"credential_query_id":"other","credential_id":"2"},{"credential_query_id":"other","credential_id":"3"}]"#
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(refs: refs))
        XCTAssertNotNil(sender.sent.first?.vpToken, "one bound credential plus two for an unbound query is a valid combined presentation: \(f.listener.errors)")
        XCTAssertEqual(f.keystore.scaCalls, 1, "only the bound credential carries the transaction")
        XCTAssertEqual(f.keystore.plainCalls, 2)
        let shown = try XCTUnwrap(f.consent.requests.first)
        XCTAssertEqual(Set(shown.attributes.map(\.credentialName)), ["Visa card", "Other 2", "Other 3"], "every presented credential is named in the consent")
    }

    /// What the user is shown and what is logged is the evaluated identity, not the protocol audience.
    func testTheShownAndLoggedVerifierIsTheEvaluatedIdentity() async throws {
        let f = try await fixture()
        f.wallet.lock.lock()
        f.wallet.lastTrustResults["f1"] = TrustResult(trusted: true, entityName: "Shop AB (verified)", identifier: audience)
        f.wallet.lock.unlock()
        await f.wallet.handleSignRequest(engine: Sender(), msg: try engineMessage())
        XCTAssertEqual(f.consent.requests.first?.verifier, "Shop AB (verified)")
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.verifier, "Shop AB (verified)")
    }

    func testTheVerifierLabelFallsBackHonestly() {
        let named = TrustResult(trusted: true, entityName: "Shop AB", identifier: "client.example")
        XCTAssertEqual(SirosWallet.transactionVerifierLabel(trust: named, fallback: "o", origin: "https://o.example"), "Shop AB")
        let unnamed = TrustResult(trusted: true, identifier: "client.example")
        XCTAssertEqual(SirosWallet.transactionVerifierLabel(trust: unnamed, fallback: "o", origin: "https://o.example"),
                       "client.example (via https://o.example)", "a verified client_id that differs from the origin names both")
        XCTAssertEqual(SirosWallet.transactionVerifierLabel(trust: TrustResult(trusted: true, identifier: "https://o.example"), fallback: "o", origin: "https://o.example"), "https://o.example")
        XCTAssertEqual(SirosWallet.transactionVerifierLabel(trust: nil, fallback: "aud"), "aud")
    }

    func testEngineRefusesInsufficientFactors() async throws {
        let f = try await fixture()
        f.keystore.signer.capability = .cannot("the plugin has no second factor")
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken, "the key cannot reach two categories")
        XCTAssertEqual(f.keystore.scaCalls, 0)
        XCTAssertTrue(f.consent.requests.isEmpty, "refused before the user was shown anything")
    }

    func testEngineRefusesMdocCredentialForTransactionData() async throws {
        let f = try await fixture(format: "mso_mdoc")
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
    }

    func testEngineRefusesANonScaAttestation() async throws {
        let f = try await fixture(metadataDoc: metadata.replacingOccurrences(of: "urn:eu:europa:ec:eudi:sua:sca", with: "urn:other"))
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
    }

    /// A runtime flip applies to the next flow only.
    func testAFlagFlipAppliesToTheNextFlowOnly() async throws {
        let f = try await fixture()
        f.wallet.transactionDataEnabled = false
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNotNil(sender.sent.first?.vpToken, "the flow in progress finishes under the setting it started with")
        f.wallet.snapshotTransactionDataEnablement()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "f2"))
        XCTAssertNil(sender.sent.last?.vpToken, "the next flow starts disabled")
    }

    /// Two flows in flight keep their own setting: the second one starting
    /// disabled does not change the first.
    func testOverlappingFlowsKeepTheirOwnSnapshot() async throws {
        let f = try await fixture()          // flow A's start: enabled (queue: [true])
        f.wallet.transactionDataEnabled = false
        f.wallet.snapshotTransactionDataEnablement()   // flow B's start: disabled (queue: [true, false])
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "A"))
        XCTAssertNotNil(sender.sent.last?.vpToken, "flow A started enabled")
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "B"))
        XCTAssertNil(sender.sent.last?.vpToken, "flow B started disabled")
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "A"))
        XCTAssertNotNil(sender.sent.last?.vpToken, "flow A still finishes under its own setting")
    }

    func testQueueOrderIsNotAffectedByTheLiveFlagAtProcessingTime() async throws {
        let f = try await fixture()                       // A: enabled
        f.wallet.transactionDataEnabled = false
        f.wallet.snapshotTransactionDataEnablement()      // B: disabled
        f.wallet.transactionDataEnabled = true            // live flag is on again when they are processed
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "A"))
        XCTAssertNotNil(sender.sent.last?.vpToken)
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "B"))
        XCTAssertNil(sender.sent.last?.vpToken, "B started disabled whatever the flag is now")
    }

    func testWmpSessionKeepsItsOwnSetting() async throws {
        let on = try await fixture()                      // session started enabled
        on.wallet.transactionDataEnabled = false
        _ = try await on.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        let off = try await fixture(enabled: false)       // session started disabled
        off.wallet.transactionDataEnabled = true
        do { _ = try await off.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail() }
        catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .disabled) }
    }

    func testReferencedDocumentsGoThroughTheUnauthenticatedGetterEndToEnd() async throws {
        final class Recorder: @unchecked Sendable {
            private let lock = NSLock(); private var urls: [String] = []
            func add(_ u: String) { lock.lock(); urls.append(u); lock.unlock() }
            var all: [String] { lock.lock(); defer { lock.unlock() }; return urls }
        }
        let labelsUrl = "https://registry.example.attacker.test/labels.json"
        let entry = metadata.replacingOccurrences(of: #""ui_labels":{"affirmative_action_label":[{"lang":"en","value":"Confirm Payment"}]}"#, with: #""ui_labels_uri":"\#(labelsUrl)""#)
        let f = try await fixture(metadataDoc: entry)
        let rec = Recorder()
        f.wallet.transactionResourceGet = { url, _ in
            rec.add(url.absoluteString)
            return Data(#"{"affirmative_action_label":[{"lang":"en","value":"Confirm Payment"}]}"#.utf8)
        }
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNotNil(sender.sent.first?.vpToken)
        XCTAssertEqual(rec.all, [labelsUrl])
    }

    /// A sign that applied something other than what the claim says is a refusal, never a token.
    func testASignThatAppliedDifferentFactorsIsARefusalAndIsLogged() async throws {
        let f = try await fixture()
        f.keystore.signer.applied = [AuthenticationFactor(.possession, "key_in_remote_wscd"), AuthenticationFactor(.knowledge, "pin_less_than_6_digits")]
        do { _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail("must not produce a token") }
        catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .insufficientAuthenticationFactors) }
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.outcome, .refused)
        XCTAssertEqual(log.first?.reason, "insufficientAuthenticationFactors")
    }

    /// The user backing out of the PIN prompt declines the transaction: the engine is answered at once and no error is shown.
    func testEngineAnswersAtOnceWhenTheUserCancelsThePin() async throws {
        let f = try await fixture()
        f.keystore.signer.scaError = TransactionDataError(.declined, detail: "the user cancelled the authentication")
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertEqual(sender.sent.count, 1, "one immediate response")
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertTrue(f.listener.errors.isEmpty, "a decline is not presented as an error")
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.outcome, .declined, "cancelling the PIN prompt is logged as a decline")
        XCTAssertNil(log.first?.reason)
    }

    /// The engine is answered at once when the sign itself refuses, not left to wait out its timeout.
    func testEngineAnswersAtOnceWhenTheSignAppliedDifferentFactors() async throws {
        let f = try await fixture()
        f.keystore.signer.applied = [AuthenticationFactor(.possession, "key_in_remote_wscd"), AuthenticationFactor(.knowledge, "pin_less_than_6_digits")]
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertEqual(sender.sent.count, 1, "one immediate response")
        XCTAssertNil(sender.sent.first?.vpToken)
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.first?.outcome, .refused)
        XCTAssertEqual(log.first?.reason, "insufficientAuthenticationFactors", "the real reason, not signingFailed")
    }

    func testTheDefaultLogIsNotCarriedToTheNextAccount() async throws {
        let f = try await fixture()
        _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        let before = await f.wallet.transactionLog()
        XCTAssertEqual(before.count, 1)
        f.wallet.resetDefaultTransactionLogStore()   // what logout and lock do
        let after = await f.wallet.transactionLog()
        XCTAssertTrue(after.isEmpty)
    }

    func testAHostSuppliedLogStoreSurvivesAnAccountBoundary() async throws {
        let f = try await fixture()
        _ = await f.wallet.transactionLog()               // the default store is created first
        let store = InMemoryTransactionLogStore()
        f.wallet.setTransactionLogStore(store)
        _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        f.wallet.resetDefaultTransactionLogStore()
        let kept = await f.wallet.transactionLog()
        XCTAssertEqual(kept.count, 1, "the wallet still reads the host's store after the boundary")
    }

    func testReferencedDocumentsAreFetchedWithoutCredentials() async throws {
        final class Recorder: @unchecked Sendable {
            private let lock = NSLock(); private var urls: [URL] = []
            func add(_ u: URL) { lock.lock(); urls.append(u); lock.unlock() }
            var all: [URL] { lock.lock(); defer { lock.unlock() }; return urls }
        }
        let rec = Recorder()
        let source = WalletTransactionMetadataSource(
            metadataFetch: { _, _, _ in nil },
            resourceGet: { url, _ in rec.add(url); return Data("{}".utf8) }
        )
        // A lookalike of the registry origin gets the unauthenticated getter only.
        let data = await source.fetchResource(uri: "https://registry.example.attacker.test/labels.json", maxBytes: 100)
        XCTAssertEqual(data, Data("{}".utf8))
        XCTAssertEqual(rec.all.map(\.absoluteString), ["https://registry.example.attacker.test/labels.json"])
        for bad in ["http://plain.example/x.json", "file:///etc/passwd", "ftp://x.example/y", "//x.example/y", "not a url"] {
            let none = await source.fetchResource(uri: bad, maxBytes: 100)
            XCTAssertNil(none, bad)
        }
        XCTAssertEqual(rec.all.count, 1, "no non-https reference reached the getter")
    }

    /// The pre-consent probe asks the WSCD about the key that will sign, once per bound credential.
    func testTheCapabilityOfTheSigningKeyIsAskedBeforeConsent() async throws {
        let f = try await fixture()
        _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        XCTAssertEqual(f.keystore.capabilityQueries, ["k1"])
    }

    // MARK: consent comes first, and what is signed is what was shown

    func testConsentHappensBeforeSigningOnEveryTransport() async throws {
        let engine = try await fixture()
        await engine.wallet.handleSignRequest(engine: Sender(), msg: try engineMessage())
        XCTAssertEqual(engine.events.all, ["consent", "sign"], "engine")

        let wmp = try await fixture()
        _ = try await wmp.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        XCTAssertEqual(wmp.events.all, ["consent", "sign"], "WMP")

        let dc = try await fixture()
        _ = try await dc.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: #"["\#(raw)"]"#), origin: "https://shop.example")
        XCTAssertEqual(dc.events.all, ["consent", "sign"], "DC API")
    }

    func testNothingIsSignedAndTheUserIsNotAskedWhenTheKeyCannotReachTwoCategories() async throws {
        for transport in ["engine", "wmp", "dcapi"] {
            let f = try await fixture()
            f.keystore.signer.capability = .cannot("no second factor")
            switch transport {
            case "engine": await f.wallet.handleSignRequest(engine: Sender(), msg: try engineMessage())
            case "wmp": _ = try? await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
            default: _ = try? await f.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: #"["\#(raw)"]"#), origin: "https://shop.example")
            }
            XCTAssertTrue(f.events.all.isEmpty, "\(transport): no consent prompt and no signing: \(f.events.all)")
        }
    }

    func testTheKeyThatWasValidatedIsTheKeyThatSigns() async throws {
        let f = try await fixture()
        f.consent.whileDeciding = { [keystore = f.keystore] in
            // While the user decides, the first key in the keystore changes (a software key appears).
            keystore.keys = [KeyInfo(keyId: "k-software", algorithm: "ES256", pluginId: "softkey"), KeyInfo(keyId: "k1", algorithm: "ES256", pluginId: "r2ps")]
        }
        _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        XCTAssertEqual(f.keystore.signingKids.compactMap { $0 }, ["k1"], "signed with the key whose factors were claimed, not a re-selected one")
    }

    func testACredentialThatChangesWhileTheUserDecidesIsRefused() async throws {
        let f = try await fixture()
        f.consent.whileDeciding = { [store = f.store] in
            await store.save(StoredCredential(id: 1, format: "dc+sd-jwt", raw: "e30.e30.c2ln~", metadata: CredentialMetadata(name: "Other", vct: "urn:other", doctype: nil), batchId: 1, instanceId: 0))
        }
        do { _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail("must refuse") }
        catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .invalidEntry) }
        XCTAssertEqual(f.keystore.scaCalls, 0)
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.count, 1, "one record for one attempt")
        XCTAssertEqual(log.first?.outcome, .refused)
        XCTAssertEqual(log.first?.reason, "invalidEntry", "the real reason, not signingFailed")
    }

    /// The integrity pin covers the downloaded BYTES: a leading BOM must not be dropped before hashing.
    func testTheMetadataPinCoversTheDownloadedBytesIncludingABom() async throws {
        let f = try await fixture()
        let body = Data([0xEF, 0xBB, 0xBF]) + Data(#"{"vct":"https://issuer.example/card"}"#.utf8)
        f.wallet.transactionResourceGet = { _, _ in body }
        func sri(_ d: Data) -> String { "sha256-" + Data(SHA256.hash(data: d)).base64EncodedString() }
        let withoutBom = sri(body.dropFirst(3))
        let withBom = sri(body)
        let rejected = await f.wallet.fetchTypeMetadata(vct: "https://issuer.example/card", expectedIntegrity: withoutBom, maxBytes: 10_000)
        XCTAssertNil(rejected, "a pin over the BOM-less text must not accept the BOM-prefixed download")
        let accepted = await f.wallet.fetchTypeMetadata(vct: "https://issuer.example/card", expectedIntegrity: withBom, maxBytes: 10_000)
        XCTAssertNotNil(accepted)
        XCTAssertEqual(accepted?.unicodeScalars.first, "\u{FEFF}", "the text is returned as downloaded, BOM included, so the pipeline's re-check of the pin holds")
    }

    func testConsentIsLoggedOnlyAfterSigningSucceeds() async throws {
        let ok = try await fixture()
        _ = try await ok.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        let okLog = await ok.wallet.transactionLog()
        XCTAssertEqual(okLog.map(\.outcome), [.consented])

        let failing = try await fixture()
        failing.keystore.failSigning = true
        do { _ = try await failing.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail() } catch {}
        let failLog = await failing.wallet.transactionLog()
        XCTAssertEqual(failLog.map(\.outcome), [.refused])
        XCTAssertEqual(failLog.first?.reason, "signingFailed")
    }

    func testDcApiLogsConsentOnlyOnceThePresentationExists() async throws {
        let f = try await fixture()
        _ = try await f.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: #"["\#(raw)"]"#), origin: "https://shop.example")
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.map(\.outcome), [.consented])
    }

    /// A presentation still in flight when the account changes must not write into the next account's log.
    func testALateRecordIsNotWrittenIntoTheNextAccountsLog() async throws {
        let f = try await fixture()
        f.consent.whileDeciding = { [wallet = f.wallet] in wallet.resetDefaultTransactionLogStore() }   // logout during the decision
        _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        let next = await f.wallet.transactionLog()
        XCTAssertTrue(next.isEmpty, "the previous account's record did not land in the new account's log")
        XCTAssertEqual(f.listener.logFailures, 1, "and the host is told it was not recorded")
    }

    // MARK: start records are retired

    private func plainMessage(flow: String) throws -> SignRequestMessage {
        let json = #"{"type":"sign_request","flow_id":"\#(flow)","message_id":"m","action":"sign_presentation","params":{"audience":"\#(audience)","nonce":"n","credentials_to_include":[{"credential_query_id":"q","credential_id":"1"}]}}"#
        return try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
    }

    /// A presentation without a transaction must not leave its start record for a later flow to claim.
    func testAPlainPresentationConsumesItsOwnStartRecord() async throws {
        let f = try await fixture()                       // start record: enabled
        await f.wallet.handleSignRequest(engine: Sender(), msg: try plainMessage(flow: "plain"))
        f.wallet.transactionDataEnabled = false
        f.wallet.snapshotTransactionDataEnablement()      // the next flow started disabled
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "tx"))
        XCTAssertNil(sender.sent.last?.vpToken, "the transaction flow got its own (disabled) record, not the plain flow's leftover")
    }

    /// A flow that runs while no handler is registered still retires its own start record.
    func testAFlowWithoutAHandlerStillClaimsItsStartRecord() async throws {
        let f = try await fixture(handler: false)
        f.wallet.legacyFlowSnapshotQueue = [(effective: true, at: Date()), (effective: false, at: Date())]
        XCTAssertFalse(f.wallet.transactionDataActive(forFlow: "plain", viaWmp: false), "no handler")
        f.wallet.lock.lock(); let left = f.wallet.legacyFlowSnapshotQueue.count; f.wallet.lock.unlock()
        XCTAssertEqual(left, 1, "the plain flow consumed its record")
        f.wallet.transactionConsentHandler = Consent()
        XCTAssertFalse(f.wallet.transactionDataActive(forFlow: "next", viaWmp: false), "the next flow gets ITS record (disabled), not the leftover")
    }

    /// A flow that ends in error takes its waiting consent task with it; other flows' tasks are untouched.
    func testFlowErrorCancelsThatFlowsConsentTaskOnly() async throws {
        let f = try await fixture()
        let mine = Task<Void, Never> { try? await Task.sleep(nanoseconds: 60_000_000_000) }
        let other = Task<Void, Never> { try? await Task.sleep(nanoseconds: 60_000_000_000) }
        f.wallet.lock.lock()
        f.wallet.transactionTasks[UUID()] = (flowId: "ended", cancel: { mine.cancel() })
        f.wallet.transactionTasks[UUID()] = (flowId: "running", cancel: { other.cancel() })
        f.wallet.lock.unlock()
        let json = #"{"type":"flow_error","flow_id":"ended","error":{"code":"X","message":"m"}}"#
        f.wallet.handleFlowError(msg: try JSONDecoder().decode(FlowErrorMessage.self, from: Data(json.utf8)))
        XCTAssertTrue(mine.isCancelled)
        XCTAssertFalse(other.isCancelled)
        other.cancel()
    }

    /// A completed flow takes its waiting task with it too (the consented record is shielded, see `shielded`).
    func testFlowCompleteCancelsThatFlowsTrackedTask() async throws {
        let f = try await fixture()
        let mine = Task<Void, Never> { try? await Task.sleep(nanoseconds: 60_000_000_000) }
        f.wallet.lock.lock(); f.wallet.transactionTasks[UUID()] = (flowId: "done", cancel: { mine.cancel() }); f.wallet.lock.unlock()
        await f.wallet.handleFlowComplete(msg: try JSONDecoder().decode(FlowCompleteMessage.self, from: Data(#"{"type":"flow_complete","flow_id":"done"}"#.utf8)))
        XCTAssertTrue(mine.isCancelled)
    }

    /// A WMP transaction runs as a tracked task: cancelling the flow cancels the work, whose result is then a cancellation.
    func testATrackedTransactionIsCancelledWithItsFlow() async throws {
        let f = try await fixture()
        let running = Task { () -> String in
            try await f.wallet.trackedTransaction(flowId: "w") { try await Task.sleep(nanoseconds: 60_000_000_000); return "finished" }
        }
        try await Task.sleep(nanoseconds: 100_000_000)
        f.wallet.cancelTransactionTasks(flowId: "w")
        do { _ = try await running.value; XCTFail("expected cancellation") } catch is CancellationError {} catch { XCTFail("\(error)") }
        f.wallet.lock.lock(); let left = f.wallet.transactionTasks.count; f.wallet.lock.unlock()
        XCTAssertEqual(left, 0, "unregistered once finished")
    }

    /// Overlapping persists run one at a time, in order.
    /// A persist queued for an earlier account must not export the next account's container.
    func testAPersistForAnEarlierAccountGenerationIsRefused() async throws {
        let f = try await fixture()
        let stale = f.wallet.currentAccountGeneration()
        f.wallet.resetDefaultTransactionLogStore()      // logout: the generation moves on
        do { try await f.wallet.persistKeystoreOrThrow(generation: stale); XCTFail("expected a refusal") }
        catch let error as TransactionLogError { XCTAssertTrue(error.detail.contains("account changed")) }
    }

    /// A logout and re-login DURING the awaited export must not let the old container reach the new session.
    func testAnAccountChangeDuringTheExportWritesNothing() async throws {
        let f = try await fixture()
        let generation = f.wallet.currentAccountGeneration()
        f.wallet.sessionStore.privateDataJwe = nil
        f.keystore.duringExport = { [weak wallet = f.wallet] in wallet?.resetDefaultTransactionLogStore() }
        do { try await f.wallet.exportAndSyncKeystore(generation: generation); XCTFail("expected a refusal") }
        catch let error as TransactionLogError { XCTAssertTrue(error.detail.contains("while the container was being exported")) }
        XCTAssertNil(f.wallet.sessionStore.privateDataJwe, "the old container was not assigned to the new session")
    }

    func testTheKeystorePersistMutexSerializes() async throws {
        let mutex = AsyncMutex()
        final class Probe: @unchecked Sendable {
            let l = NSLock(); var active = 0; var maxActive = 0
            func enter() { l.lock(); active += 1; maxActive = max(maxActive, active); l.unlock() }
            func leave() { l.lock(); active -= 1; l.unlock() }
        }
        let probe = Probe()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<8 {
                group.addTask { await mutex.withLock { probe.enter(); try? await Task.sleep(nanoseconds: 5_000_000); probe.leave() } }
            }
        }
        XCTAssertEqual(probe.maxActive, 1)
    }

    func testStaleStartRecordsAreDropped() async throws {
        let f = try await fixture(enabled: false)
        f.wallet.legacyFlowSnapshotQueue = [(effective: true, at: Date().addingTimeInterval(-SirosWallet.snapshotLifetime - 60))]
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage(flow: "late"))
        XCTAssertNil(sender.sent.last?.vpToken, "an hours-old record of a flow that never signed is not applied to this one")
    }

    func testAFlowsRecordIsRemovedWhenItEnds() async throws {
        let f = try await fixture(enabled: false)
        await f.wallet.handleSignRequest(engine: Sender(), msg: try engineMessage(flow: "gone"))   // refused: terminal
        f.wallet.lock.lock(); let kept = f.wallet.legacyFlowSnapshots["gone"]; f.wallet.lock.unlock()
        XCTAssertNil(kept)
    }

    /// A sign request cancelled while the user decides (teardown, or the flow ended) exits quietly: no flow error, no signing.
    func testACancelledSignRequestReportsNothing() async throws {
        let f = try await fixture()
        // The consent callback runs in its own task, so cancel the sign request's task through a holder.
        final class Holder: @unchecked Sendable { var task: Task<Void, Never>? }
        let holder = Holder()
        f.consent.whileDeciding = { holder.task?.cancel() }
        let sender = Sender()
        let msg = try engineMessage(flow: "gone")
        let task = Task { await f.wallet.handleSignRequest(engine: sender, msg: msg) }
        holder.task = task
        await task.value
        XCTAssertTrue(f.listener.errors.isEmpty, "no failure reported for a cancelled request: \(f.listener.errors)")
        XCTAssertNil(sender.sent.last?.vpToken, "nothing was signed for a cancelled request")
    }

    /// A signer that ignores cancellation still cannot get a token sent, or a consent recorded, for an ended flow.
    func testACancellationDuringTheFinalSigningSendsNothingAndRecordsNothing() async throws {
        let f = try await fixture()
        final class Holder: @unchecked Sendable { var task: Task<Void, Never>? }
        let holder = Holder()
        f.keystore.duringSigning = { holder.task?.cancel() }
        let sender = Sender()
        let msg = try engineMessage(flow: "ended")
        let task = Task { await f.wallet.handleSignRequest(engine: sender, msg: msg) }
        holder.task = task
        await task.value
        XCTAssertNil(sender.sent.last?.vpToken, "no token for an ended flow")
        let log = await f.wallet.transactionLog()
        XCTAssertTrue(log.isEmpty, "no consent recorded for an ended flow: \(log.map(\.outcome))")
    }

    /// A task whose creation preceded a teardown is cancelled at registration instead of being left running unregistered.
    func testATaskRegisteredAfterATeardownIsCancelledNotLeftRunning() async throws {
        let f = try await fixture()
        let epoch = f.wallet.currentTaskEpoch()
        f.wallet.cancelEngineTasks()                       // logout between the task's creation and its registration
        final class Flag: @unchecked Sendable { let l = NSLock(); var on = false; func set() { l.lock(); on = true; l.unlock() } }
        let cancelled = Flag()
        _ = f.wallet.registerTransactionTask(flowId: "late", epoch: epoch, cancel: { cancelled.set() })
        XCTAssertTrue(cancelled.on)
        f.wallet.lock.lock(); let registered = f.wallet.transactionTasks.count; f.wallet.lock.unlock()
        XCTAssertEqual(registered, 0, "nothing was left registered")
    }

    /// An unbound credential of another format in a combined presentation does not stop the transaction.
    func testAnUnboundMdocCredentialDoesNotRefuseTheTransaction() async throws {
        let f = try await fixture()
        let stored = await f.store.getAll()
        let pay = try XCTUnwrap(stored.first)
        let mdoc = StoredCredential(id: 7, format: "mso_mdoc", raw: "not-an-sd-jwt", metadata: CredentialMetadata(name: nil, vct: nil, doctype: "org.iso.18013.5.1.mDL"), batchId: 7, instanceId: 0)
        await f.store.save(mdoc)       // presented credentials must exist in the store (the post-consent recheck compares them)
        var selection = SirosWallet.ScaSelection()
        selection.credentials = ["pay": pay, "other": mdoc]
        let plan = try await f.wallet.processTransactionData(
            entries: [TransactionDataEntryInput(raw: raw)], responseMode: "direct_post.jwt", selection: selection, verifier: "Shop", requestSigned: nil
        )
        XCTAssertNotNil(plan.bindings["pay"])
        XCTAssertNil(plan.bindings["other"])
        await plan.plan.complete(signed: false)
    }

    /// A read that straddles an account switch returns nothing rather than the next account's records.
    func testALogReadAcrossAnAccountSwitchReturnsNothing() async {
        final class Gen: @unchecked Sendable { let l = NSLock(); var value = 0; func bump() { l.lock(); value += 1; l.unlock() }; var now: Int { l.lock(); defer { l.unlock() }; return value } }
        let gen = Gen()
        struct SwitchingStore: TransactionLogStore {
            let onRead: @Sendable () -> Void
            func append(_ entries: [TransactionLogEntry]) async throws {}
            func entries() async -> [TransactionLogEntry] {
                onRead()   // the account switches during the read
                return [TransactionLogEntry(subject: TransactionLogSubject(transactionId: "NEXT-ACCOUNT", typeName: nil), verifier: "v", credential: "c", outcome: .consented)]
            }
        }
        let bound = GenerationBoundLogStore(SwitchingStore(onRead: { gen.bump() }), generation: 0, current: { gen.now })
        let read = await bound.entries()
        XCTAssertTrue(read.isEmpty)
    }

    /// A refusal raised before the service runs (here a malformed integrity claim) is logged exactly once.
    func testAPreServiceRefusalIsLoggedOnce() async throws {
        let f = try await fixture()
        let badPayload = b64(#"{"vct":"\#(vct)","vct#integrity":5}"#)
        await f.store.save(StoredCredential(
            id: 1, format: "dc+sd-jwt", raw: "eyJhbGciOiJFUzI1NiJ9.\(badPayload).c2ln~", metadata: CredentialMetadata(name: "Visa card", vct: vct, doctype: nil),
            batchId: 1, instanceId: 0
        ))
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.last?.vpToken)
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.count, 1, "one refusal record per request: \(log.map(\.reason))")
        XCTAssertEqual(log.first?.outcome, .refused)
    }

    /// A further credential of an unbound query that is deleted or replaced during consent refuses the transaction too.
    func testAnExtraPresentedCredentialIsRecheckedAfterConsent() async throws {
        let f = try await fixture()
        let stored = await f.store.getAll()
        let pay = try XCTUnwrap(stored.first)
        let extra = StoredCredential(id: 8, format: "dc+sd-jwt", raw: pay.raw, metadata: pay.metadata, batchId: 8, instanceId: 0)
        await f.store.save(extra)
        f.consent.whileDeciding = { await f.store.delete(8) }      // deleted while the user decides
        var selection = SirosWallet.ScaSelection()
        selection.credentials = ["pay": pay]
        selection.extraCredentials = [extra]
        do {
            _ = try await f.wallet.processTransactionData(
                entries: [TransactionDataEntryInput(raw: raw)], responseMode: "direct_post.jwt", selection: selection, verifier: "Shop", requestSigned: nil
            )
            XCTFail("expected a refusal")
        } catch let error as TransactionDataError {
            XCTAssertEqual(error.reason, .invalidEntry)
        } catch SirosError.transactionData(let error) {
            XCTAssertEqual(error.reason, .invalidEntry)
        }
    }

    /// A flow that ends between a task being requested and registered leaves no running task behind.
    func testATaskForAFlowThatEndedBeforeRegistrationIsCancelled() async throws {
        let f = try await fixture()
        let epoch = f.wallet.currentTaskEpoch()
        let seq = f.wallet.currentFlowEndSeq("gone")
        f.wallet.cancelTransactionTasks(flowId: "gone")          // the flow ends: nothing is registered yet, so nothing to cancel
        final class Flag: @unchecked Sendable { let l = NSLock(); var on = false; func set() { l.lock(); on = true; l.unlock() } }
        let cancelled = Flag()
        _ = f.wallet.registerTransactionTask(flowId: "gone", epoch: epoch, flowSeq: seq, cancel: { cancelled.set() })
        XCTAssertTrue(cancelled.on)
        let other = Flag()
        _ = f.wallet.registerTransactionTask(flowId: "alive", epoch: epoch, flowSeq: f.wallet.currentFlowEndSeq("alive"), cancel: { other.set() })
        XCTAssertFalse(other.on, "another flow's task is unaffected")
        f.wallet.lock.lock(); let registered = f.wallet.transactionTasks.count; f.wallet.lock.unlock()
        XCTAssertEqual(registered, 1)
    }

    func testTeardownCancelsConsentFlowsInProgress() async throws {
        let f = try await fixture()
        let task = Task<Void, Never> { try? await Task.sleep(nanoseconds: 60_000_000_000) }
        f.wallet.lock.lock(); f.wallet.transactionTasks[UUID()] = (flowId: "f", cancel: { task.cancel() }); f.wallet.lock.unlock()
        f.wallet.cancelEngineTasks()
        XCTAssertTrue(task.isCancelled)
        f.wallet.lock.lock(); let remaining = f.wallet.transactionTasks.count; f.wallet.lock.unlock()
        XCTAssertEqual(remaining, 0)
    }

    func testAUsersOwnDeclineIsNotReportedAsAnError() async throws {
        let f = try await fixture()
        f.consent.answer = false
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertTrue(f.listener.errors.isEmpty, "a decline is not an error: \(f.listener.errors)")
    }

    func testARefusalReportsOnlyTheVerifierErrorCode() async throws {
        let f = try await fixture(enabled: false)
        await f.wallet.handleSignRequest(engine: Sender(), msg: try engineMessage())
        XCTAssertEqual(f.listener.errors, ["invalid_transaction_data"], "no developer text")
    }

    func testALogWriteFailureIsSurfacedToTheHost() async throws {
        struct Failing: TransactionLogStore {
            func append(_ entries: [TransactionLogEntry]) async throws { throw TransactionLogError("disk full") }
            func entries() async -> [TransactionLogEntry] { [] }
        }
        let f = try await fixture()
        f.wallet.setTransactionLogStore(Failing())
        _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        XCTAssertEqual(f.listener.logFailures, 1)
    }

    func testARefusalBeforeThePipelineIsLoggedOnce() async throws {
        let f = try await fixture(enabled: false)
        await f.wallet.handleSignRequest(engine: Sender(), msg: try engineMessage())
        let log = await f.wallet.transactionLog()
        XCTAssertEqual(log.count, 1)
        XCTAssertEqual(log.first?.reason, "disabled")
        // The DC API's own pre-pipeline refusals too.
        let dc = try await fixture(enabled: false)
        _ = try? await dc.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: #"["\#(raw)"]"#), origin: "https://shop.example")
        let dcLog = await dc.wallet.transactionLog()
        XCTAssertEqual(dcLog.count, 1)
        // A refusal inside the pipeline is logged by the service, not twice.
        let inPipeline = try await fixture()
        let bad = #"[{"raw":"@@@","type":"urn:eudi:sca:payment:1","credential_ids":["pay"]}]"#
        await inPipeline.wallet.handleSignRequest(engine: Sender(), msg: try engineMessage(transactionData: bad))
        let inLog = await inPipeline.wallet.transactionLog()
        XCTAssertEqual(inLog.count, 1)
    }

    func testAMalformedIntegrityClaimRefusesInsteadOfReadingAsNoPin() async throws {
        let f = try await fixture()
        let payload = b64(#"{"vct":"\#(vct)","vct#integrity":null}"#)
        await f.store.save(StoredCredential(id: 1, format: "dc+sd-jwt", raw: "e30.\(payload).c2ln~", metadata: CredentialMetadata(name: "Visa card", vct: vct, doctype: nil), batchId: 1, instanceId: 0))
        let sender = Sender()
        await f.wallet.handleSignRequest(engine: sender, msg: try engineMessage())
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertTrue(f.events.all.isEmpty)
    }

    func testTheDisclosedAttributesAreShownWithTheTransaction() async throws {
        let f = try await fixture()
        let refs = #"[{"credential_query_id":"pay","credential_id":"1","disclosed_claims":["given_name","family_name"]}]"#
        await f.wallet.handleSignRequest(engine: Sender(), msg: try engineMessage(refs: refs))
        XCTAssertEqual(f.consent.requests.first?.attributes, [TransactionConsentAttributes(credentialName: "Visa card", claims: ["given_name", "family_name"])])
    }

    func testNonScaPresentationUsesTheUnchangedPath() async throws {
        let f = try await fixture(enabled: false)
        let sender = Sender()
        let json = #"{"type":"sign_request","flow_id":"f2","message_id":"m2","action":"sign_presentation","params":{"audience":"\#(audience)","nonce":"n","credentials_to_include":[{"credential_query_id":"q","credential_id":"1"}]}}"#
        await f.wallet.handleSignRequest(engine: sender, msg: try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8)))
        XCTAssertEqual(f.keystore.plainCalls, 1)
        XCTAssertEqual(f.keystore.scaCalls, 0)
        let claims = try kbClaims(try XCTUnwrap(sender.sent.first?.vpToken))
        XCTAssertEqual(Set(claims.keys), ["aud", "iat", "nonce", "sd_hash", "amr"], "no TS12 claims on a plain presentation")
        XCTAssertEqual(claims["amr"] as? [String], ["hwk", "pop", "pin"])
    }

    // MARK: - WMP

    private func wmpParams(nonce: String = "n-1", audience audienceOverride: String? = nil, transactionData: String? = nil, refs: String = #"[{"credential_query_id":"pay","credential_id":"1"}]"#) throws -> SignSubFlowParams {
        let td = transactionData ?? #"[{"raw":"\#(raw)","type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":\#(payload),"transaction_data_hashes_alg":["sha-256"]}]"#
        let json = #"{"action":"sign_presentation","nonce":"\#(nonce)","audience":"\#(audienceOverride ?? audience)","response_mode":"direct_post.jwt","credentials_to_include":\#(refs),"transaction_data":\#(td)}"#
        return try JSONDecoder().decode(SignSubFlowParams.self, from: Data(json.utf8))
    }

    /// Without a replay challenge or a verifier binding nothing is signed (engine and WMP).
    func testAnEmptyNonceOrAudienceRefusesTheTransaction() async throws {
        for (extra, msg) in [("nonce", try engineMessage(nonce: "")), ("audience", try engineMessage(audience: ""))] {
            let f = try await fixture()
            let sender = Sender()
            await f.wallet.handleSignRequest(engine: sender, msg: msg)
            XCTAssertNil(sender.sent.last?.vpToken, "engine \(extra)")
            XCTAssertEqual(f.keystore.scaCalls, 0, "engine \(extra)")
            XCTAssertTrue(f.consent.requests.isEmpty, "refused before the user is asked: \(extra)")
        }
        for (nonce, aud) in [("", nil), ("n-1", Optional(""))] as [(String, String?)] {
            let f = try await fixture()
            do { _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams(nonce: nonce, audience: aud)); XCTFail("must refuse") }
            catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .invalidEntry) }
            XCTAssertEqual(f.keystore.scaCalls, 0)
            XCTAssertTrue(f.consent.requests.isEmpty)
        }
    }

    /// A credential that will be presented is never listed in the consent without a name.
    func testEveryCredentialInTheConsentHasAName() {
        func cred(_ md: CredentialMetadata?, format: String = "dc+sd-jwt") -> StoredCredential {
            StoredCredential(id: 9, format: format, raw: "x", metadata: md, batchId: 9, instanceId: 0)
        }
        XCTAssertEqual(SirosWallet.consentDisplayName(cred(CredentialMetadata(name: "Visa card", vct: "v", doctype: nil))), "Visa card")
        XCTAssertEqual(SirosWallet.consentDisplayName(cred(CredentialMetadata(name: nil, vct: "https://v.example/t", doctype: nil))), "https://v.example/t")
        XCTAssertEqual(SirosWallet.consentDisplayName(cred(CredentialMetadata(name: "", vct: nil, doctype: "org.iso.18013.5.1.mDL"), format: "mso_mdoc")), "org.iso.18013.5.1.mDL")
        XCTAssertEqual(SirosWallet.consentDisplayName(cred(nil, format: "mso_mdoc")), "mso_mdoc")
        XCTAssertEqual(SirosWallet.consentDisplayName(cred(CredentialMetadata(name: "A\u{202E}B\nC", vct: nil, doctype: nil))), "A\u{FFFD}B\u{FFFD}C", "neutralised")
    }

    func testWmpProducesAContractKbJwt() async throws {
        let f = try await fixture()
        let result = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams())
        try assertVerifierContract(try kbClaims(try XCTUnwrap(result.vpToken)), responseMode: "direct_post.jwt", nonce: "n-1", aud: audience)
    }

    /// Through the sub-flow handler the profile calls, not just the helper.
    func testWmpSignSubFlowHandlerRoutesTransactionDataToTheScaPath() async throws {
        let f = try await fixture()
        let result = try await f.wallet.handleWmpSignRequest(flowId: "f1", params: try wmpParams())
        try assertVerifierContract(try kbClaims(try XCTUnwrap(result.vpToken)), responseMode: "direct_post.jwt", nonce: "n-1", aud: audience)
        XCTAssertEqual(f.keystore.scaCalls, 1)
    }

    func testWmpRefusesWhenDisabledOrDeclinedOrInconsistent() async throws {
        let disabled = try await fixture(enabled: false)
        do { _ = try await disabled.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail() } catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .disabled) }

        let declined = try await fixture()
        declined.consent.answer = false
        do { _ = try await declined.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams()); XCTFail() } catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .declined) }

        let inconsistent = try await fixture()
        let td = #"[{"raw":"\#(raw)","type":"urn:eudi:sca:login_risk_transaction:1","credential_ids":["pay"]}]"#
        do { _ = try await inconsistent.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams(transactionData: td)); XCTFail() } catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .inconsistentWithOrchestrator) }
        XCTAssertEqual(disabled.keystore.scaCalls + declined.keystore.scaCalls + inconsistent.keystore.scaCalls, 0)
    }

    /// The bound credential is listed FIRST: it must not be signed before the later one is found unbound.
    func testWmpSignsNothingWhenALaterReferenceIsNotBound() async throws {
        let f = try await fixture()
        let store = try XCTUnwrap(f.wallet.credentialStore as? InMemoryCredentialStore)
        await store.save(StoredCredential(id: 2, format: "dc+sd-jwt", raw: "e30.e30.c2ln~", metadata: CredentialMetadata(name: "Age", vct: "urn:age", doctype: nil), batchId: 2, instanceId: 0))
        let refs = #"[{"credential_query_id":"pay","credential_id":"1"},{"credential_query_id":"age","credential_id":"2"}]"#
        do { _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams(refs: refs)); XCTFail() } catch SirosError.transactionData {}
        XCTAssertEqual(f.keystore.scaCalls, 0, "the first credential was not signed before the later guard")
        XCTAssertTrue(f.consent.requests.isEmpty, "refused before the user was asked, not after they consented")
    }

    func testWmpRefusesACombinedPresentation() async throws {
        let f = try await fixture()
        let refs = #"[{"credential_query_id":"pay","credential_id":"1"},{"credential_query_id":"age","credential_id":"2"}]"#
        do { _ = try await f.wallet.wmpTransactionPresentation(flowId: "f1", params: try wmpParams(refs: refs)); XCTFail() } catch SirosError.transactionData {}
        XCTAssertEqual(f.keystore.scaCalls, 0)
        XCTAssertTrue(f.consent.requests.isEmpty, "refused before the user was asked, not after they consented")
    }

    // MARK: - DC API

    private func dcapiRequest(transactionData: String) -> String {
        #"{"requests":[{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"dc-nonce","response_mode":"dc_api","transaction_data":\#(transactionData),"dcql_query":{"credentials":[{"id":"pay","format":"dc+sd-jwt"}]}}}]}"#
    }

    func testDcApiProducesAContractKbJwt() async throws {
        let f = try await fixture()
        let result = try await f.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: #"["\#(raw)"]"#), origin: "https://shop.example")
        let envelope = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(result.responseJson.utf8)) as? [String: Any])
        let vp = try XCTUnwrap((envelope["data"] as? [String: Any])?["vp_token"] as? [String: [String]])
        let claims = try kbClaims(try XCTUnwrap(vp["pay"]?.first))
        try assertVerifierContract(claims, responseMode: "dc_api", nonce: "dc-nonce", aud: "origin:https://shop.example")
        XCTAssertEqual(f.consent.requests.first?.requestSigned, false, "an unsigned DC API request is flagged for the warning")
    }

    func testDcApiStillRefusesWhenNotEffectivelyEnabled() async throws {
        for (enabled, handler) in [(false, true), (true, false), (false, false)] {
            let f = try await fixture(enabled: enabled, handler: handler)
            do {
                _ = try await f.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: #"["\#(raw)"]"#), origin: "https://shop.example")
                XCTFail("must refuse enabled=\(enabled) handler=\(handler)")
            } catch SirosError.transactionData(let e) {
                XCTAssertEqual(e.verifierErrorCode, "invalid_transaction_data")
            }
            XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
        }
    }

    func testDcApiRefusesMalformedTransactionData() async throws {
        let f = try await fixture()
        for bad in ["5", #"[1,2]"#, "[]", #"["!!!"]"#] {
            do {
                _ = try await f.wallet.handleDCAPIRequest(rawRequestJson: dcapiRequest(transactionData: bad), origin: "https://shop.example")
                XCTFail("must refuse \(bad)")
            } catch SirosError.transactionData {}
        }
        XCTAssertEqual(f.keystore.scaCalls + f.keystore.plainCalls, 0)
    }

    func testDcApiRefusesWhenMoreThanOneCredentialAnswersTheBoundQuery() async throws {
        let f = try await fixture()
        let store = try XCTUnwrap(f.wallet.credentialStore as? InMemoryCredentialStore)
        let jwtPayload = b64(#"{"vct":"\#(vct)"}"#)
        await store.save(StoredCredential(
            id: 2, format: "dc+sd-jwt", raw: "eyJhbGciOiJFUzI1NiJ9.\(jwtPayload).c2ln~", metadata: CredentialMetadata(name: "Second card", vct: vct, doctype: nil),
            batchId: 2, instanceId: 0
        ))
        let req = #"{"requests":[{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"n","response_mode":"dc_api","transaction_data":["\#(raw)"],"dcql_query":{"credentials":[{"id":"pay","format":"dc+sd-jwt","multiple":true}]}}}]}"#
        do {
            _ = try await f.wallet.handleDCAPIRequest(rawRequestJson: req, origin: "https://shop.example")
            XCTFail("must refuse")
        } catch SirosError.transactionData(let e) { XCTAssertEqual(e.reason, .invalidEntry) }
        XCTAssertEqual(f.keystore.scaCalls, 0)
    }

    func testDcApiRefusesAnMdocCredential() async throws {
        let f = try await fixture(format: "mso_mdoc")
        let req = #"{"requests":[{"protocol":"openid4vp-v1-unsigned","data":{"nonce":"n","response_mode":"dc_api","transaction_data":["\#(raw)"],"dcql_query":{"credentials":[{"id":"pay","format":"mso_mdoc"}]}}}]}"#
        do { _ = try await f.wallet.handleDCAPIRequest(rawRequestJson: req, origin: "https://shop.example"); XCTFail() } catch SirosError.transactionData {}
    }
}
#endif
