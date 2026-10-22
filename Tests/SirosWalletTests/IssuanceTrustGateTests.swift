// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
@testable import SirosWallet

/// Issuer trust is a gate on issuance (Kotlin SDK #276): a credential is stored
/// only when its issuer's trust was established, and anything short of an
/// affirmative answer - a negative one, no answer, an mdoc whose `issuerAuth`
/// cannot be verified - refuses the whole issuance and leaves nothing behind.
/// Runs on Linux too: the mdoc verification is replaced through
/// `SirosWallet.mdocIssuanceTrustHook`, the rest of the gate is platform-independent.
final class IssuanceTrustGateTests: XCTestCase {
    // MARK: - Fixtures

    private final class NoopAuthProvider: AuthProvider {
        struct NotImplemented: Error {}
        func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
    }

    private final class StubKeystoreManager: KeystoreManager, @unchecked Sendable {
        var isUnlocked: Bool { false }
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
    }

    private final class RecordingNotifier: CredentialNotifier, @unchecked Sendable {
        private let lock = NSLock()
        private var _events: [(notificationId: String, event: String, description: String?)] = []
        var events: [(notificationId: String, event: String, description: String?)] {
            lock.lock(); defer { lock.unlock() }; return _events
        }
        func sendCredentialNotification(flowId: String, notificationId: String, event: String, eventDescription: String?) {
            lock.lock(); _events.append((notificationId, event, eventDescription)); lock.unlock()
        }
    }

    private final class RecordingListener: WalletEventListener, @unchecked Sendable {
        private let lock = NSLock()
        private(set) var untrusted: [(flowId: String, issuer: String?, reason: String)] = []
        private(set) var errors: [String] = []
        private(set) var completed: [String] = []
        private(set) var received = 0
        func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] { [] }
        func onCredentialReceived(credential: StoredCredential) { lock.lock(); received += 1; lock.unlock() }
        func onFlowComplete(flowId: String, redirectUri: String?) { lock.lock(); completed.append(flowId); lock.unlock() }
        func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) { lock.lock(); errors.append(errorMessage); lock.unlock() }
        func onNoMatchingCredential(flowId: String, requestedTypes: [String], reason: String?, redirectUri: String?) {}
        func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String) {}
        func onTxCodeRequired(flowId: String, description: String?) -> String? { nil }
        func onReauthenticationRequired() {}
        func onWalletLifecycleBlocked(reason: SirosError.WalletLifecycleRefusal, message: String?) {}
        func onCredentialRenewedWithAttributeDiff(credential: StoredCredential, diff: CredentialAttributeDiff) {}
        func onCredentialNearExpiry(credential: StoredCredential, eligibleRemaining: Int, threshold: Int) {}
        func onTransactionLogFailure() {}
        func onIssuerNotTrusted(flowId: String, issuer: String?, reason: String) {
            lock.lock(); untrusted.append((flowId, issuer, reason)); lock.unlock()
        }
    }

    private struct Harness {
        let wallet: SirosWallet
        let store: InMemoryCredentialStore
        let notifier: RecordingNotifier
        let listener: RecordingListener
    }

    private func makeHarness() -> Harness {
        let store = InMemoryCredentialStore()
        let config = WalletConfig(backendUrl: "https://example.invalid", credentialStore: store)
        let wallet = SirosWallet(config: config, authProvider: NoopAuthProvider(), keystore: StubKeystoreManager())!
        let notifier = RecordingNotifier()
        let listener = RecordingListener()
        wallet.credentialNotifier = notifier
        wallet.eventListener = listener
        wallet.setState(.ready(userId: "u", displayName: "U", credentials: []))
        return Harness(wallet: wallet, store: store, notifier: notifier, listener: listener)
    }

    /// A JWT-shaped credential; only its second segment is read.
    private func sdJwt() -> String {
        let now = Int64(Date().timeIntervalSince1970)
        let json = try! JSONSerialization.data(withJSONObject: ["exp": now + 3600, "iat": now])
        let b64 = json.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "eyJ.\(b64).sig"
    }

    private func flowComplete(
        flowId: String = "flow-1",
        credentials: [[String: Any]],
        engineTrusted: Bool? = nil
    ) -> FlowCompleteMessage {
        let obj: [String: Any] = ["type": MessageTypes.flowComplete, "flow_id": flowId, "credentials": credentials]
        var msg = try! JSONDecoder().decode(FlowCompleteMessage.self, from: JSONSerialization.data(withJSONObject: obj))
        if let engineTrusted {
            msg.issuerTrust = IssuerTrustReport(
                issuer: "https://issuer.example", trusted: engineTrusted, framework: "etsi-tl",
                reason: engineTrusted ? nil : "issuer not on any trusted list"
            )
        }
        return msg
    }

    private var sdJwtCredential: [String: Any] {
        ["format": "vc+sd-jwt", "credential": sdJwt(), "notification_id": "n-1"]
    }

    private var mdocCredential: [String: Any] {
        ["format": "mso_mdoc", "credential": "not-a-real-mdoc", "notification_id": "n-mdoc"]
    }

    // MARK: - The policy

    private func credentials(_ formats: [String]) -> [CredentialResult] {
        let items = formats.map { ["format": $0, "credential": "x"] }
        let data = try! JSONSerialization.data(withJSONObject: items)
        return try! JSONDecoder().decode([CredentialResult].self, from: data)
    }

    func testAnEngineReportSayingUntrustedRefuses() async {
        let refusal = await issuanceTrustRefusal(
            credentials: credentials(["vc+sd-jwt"]),
            engineTrust: IssuerTrustReport(issuer: "i", trusted: false, reason: "nope"),
            mdocTrust: { _ in XCTFail("not an mdoc"); return nil }
        )
        XCTAssertEqual(refusal, "issuer trust evaluation by the wallet backend was negative: nope")
    }

    func testNoEngineReportIsNotTreatedAsUntrusted() async {
        // The engine emits none in its permissive no-PDP mode.
        let refusal = await issuanceTrustRefusal(
            credentials: credentials(["vc+sd-jwt"]), engineTrust: nil, mdocTrust: { _ in nil }
        )
        XCTAssertNil(refusal)
    }

    func testAnMdocWhoseIssuerAuthCannotBeVerifiedRefuses() async {
        let refusal = await issuanceTrustRefusal(
            credentials: credentials(["mso_mdoc"]), engineTrust: nil, mdocTrust: { _ in nil }
        )
        XCTAssertEqual(refusal, "mdoc issuerAuth is missing or could not be verified")
    }

    func testAnMdocWithANegativeIssuerTrustRefuses() async {
        let refusal = await issuanceTrustRefusal(
            credentials: credentials(["mso_mdoc"]), engineTrust: nil,
            mdocTrust: { _ in TrustResult(trusted: false, reason: "root not configured") }
        )
        XCTAssertEqual(refusal, "mdoc issuer is not trusted: root not configured")
    }

    func testAPositiveMdocIssuerTrustAllowsIssuance() async {
        let refusal = await issuanceTrustRefusal(
            credentials: credentials(["mso_mdoc"]), engineTrust: IssuerTrustReport(issuer: "i", trusted: true),
            mdocTrust: { _ in TrustResult(trusted: true) }
        )
        XCTAssertNil(refusal)
    }

    func testOneUntrustedMdocAmongSeveralRefusesTheWholeIssuance() async {
        var calls = 0
        let refusal = await issuanceTrustRefusal(
            credentials: credentials(["mso_mdoc", "vc+sd-jwt", "mso_mdoc"]), engineTrust: nil,
            mdocTrust: { _ in calls += 1; return TrustResult(trusted: calls == 1) }
        )
        XCTAssertNotNil(refusal)
        XCTAssertEqual(calls, 2, "non-mdoc credentials are not evaluated as mdocs")
    }

    // MARK: - The gate in handleFlowComplete

    func testANegativeEngineReportStoresNothingAndTellsTheIssuer() async {
        let h = makeHarness()
        await h.wallet.handleFlowComplete(msg: flowComplete(credentials: [sdJwtCredential], engineTrusted: false))

        let stored = await h.store.getAll()
        XCTAssertTrue(stored.isEmpty, "no credential from an untrusted issuer is stored")
        XCTAssertEqual(h.notifier.events.map(\.event), [CredentialNotificationEvent.failure])
        XCTAssertEqual(h.notifier.events.first?.notificationId, "n-1")
        XCTAssertEqual(h.notifier.events.first?.description, "issuer_not_trusted", "a fixed code, no detail")
        XCTAssertEqual(h.listener.untrusted.count, 1)
        XCTAssertEqual(h.listener.untrusted.first?.issuer, "https://issuer.example")
        XCTAssertEqual(h.listener.errors, [issuerNotTrustedMessage])
        XCTAssertTrue(h.listener.completed.isEmpty, "the flow did not complete")
        XCTAssertEqual(h.listener.received, 0)
        if case .ready = h.wallet.state {} else { XCTFail("expected .ready, got \(h.wallet.state)") }
    }

    func testAnMdocWithNoVerifiableIssuerAuthIsRefusedBeforeItIsStored() async {
        let h = makeHarness()
        h.wallet.mdocIssuanceTrustHook = { _ in nil }
        await h.wallet.handleFlowComplete(msg: flowComplete(credentials: [mdocCredential]))

        let stored = await h.store.getAll()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertEqual(h.listener.untrusted.first?.reason, "mdoc issuerAuth is missing or could not be verified")
        XCTAssertEqual(h.listener.errors, [issuerNotTrustedMessage])
    }

    func testAnMdocFromAnUntrustedIssuerIsRefusedEvenWhenTheEngineSaidNothing() async {
        let h = makeHarness()
        h.wallet.mdocIssuanceTrustHook = { _ in TrustResult(trusted: false, reason: "not in VICAL") }
        await h.wallet.handleFlowComplete(msg: flowComplete(credentials: [mdocCredential]))

        let stored = await h.store.getAll()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertEqual(h.notifier.events.first?.event, CredentialNotificationEvent.failure)
        XCTAssertEqual(h.listener.untrusted.first?.reason, "mdoc issuer is not trusted: not in VICAL")
    }

    func testATrustedIssuerIsStoredAndAccepted() async {
        let h = makeHarness()
        await h.wallet.handleFlowComplete(msg: flowComplete(credentials: [sdJwtCredential], engineTrusted: true))

        let stored = await h.store.getAll()
        XCTAssertEqual(stored.count, 1)
        XCTAssertEqual(h.notifier.events.map(\.event), [CredentialNotificationEvent.accepted])
        XCTAssertTrue(h.listener.untrusted.isEmpty)
        XCTAssertEqual(h.listener.completed, ["flow-1"])
    }

    func testAnEngineWithNoPdpReportingNothingStillIssues() async {
        let h = makeHarness()
        await h.wallet.handleFlowComplete(msg: flowComplete(credentials: [sdJwtCredential]))
        let stored = await h.store.getAll()
        XCTAssertEqual(stored.count, 1)
    }

    func testACompletionWhoseSessionEndedDuringTheTrustCheckTouchesNothing() async {
        let h = makeHarness()
        let wallet = h.wallet
        wallet.mdocIssuanceTrustHook = { _ in
            // A logout lands while the trust evaluation is awaiting the network.
            wallet.lock.lock(); wallet.sessionGeneration += 1; wallet.lock.unlock()
            return TrustResult(trusted: false)
        }
        await wallet.handleFlowComplete(msg: flowComplete(credentials: [mdocCredential]))

        let stored = await h.store.getAll()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertTrue(h.notifier.events.isEmpty, "the ended session's completion sends nothing")
        XCTAssertTrue(h.listener.untrusted.isEmpty)
        XCTAssertTrue(h.listener.errors.isEmpty)
        XCTAssertTrue(h.listener.completed.isEmpty)
    }

    func testANegativeEngineReportRefusesACompletionWithNoCredentials() async {
        let h = makeHarness()
        h.wallet.issuanceInFlight = true
        var msg = flowComplete(credentials: [])
        msg.credentials = nil
        msg.refreshToken = "rt-must-not-be-captured"
        msg.issuerTrust = IssuerTrustReport(issuer: "https://issuer.example", trusted: false, reason: "no")
        await h.wallet.handleFlowComplete(msg: msg)

        XCTAssertEqual(h.listener.untrusted.count, 1)
        XCTAssertEqual(h.listener.errors, [issuerNotTrustedMessage])
        XCTAssertTrue(h.listener.completed.isEmpty, "the flow is not reported complete")
        XCTAssertFalse(h.wallet.issuanceInFlight)
    }

    func testACancelDuringTheTrustCheckDropsTheCompletionAndSparesANewerRenewal() async {
        let h = makeHarness()
        let wallet = h.wallet
        let old = StoredCredential(id: 7, format: "vc+sd-jwt", raw: sdJwt(), batchId: 100, instanceId: 0)
        await h.store.save(old)
        wallet.mdocIssuanceTrustHook = { _ in
            wallet.cancelCurrentFlow()                     // the user cancels ...
            wallet.lock.lock(); wallet.pendingRenewalSourceBatchId = 100; wallet.issuanceInFlight = true
            wallet.lock.unlock()                           // ... and a newer renewal starts
            return TrustResult(trusted: true)
        }
        await wallet.handleFlowComplete(msg: flowComplete(credentials: [mdocCredential, sdJwtCredential]))

        let stored = await h.store.getAll()
        XCTAssertEqual(stored.map(\.id), [7], "the cancelled flow stored nothing and deleted nothing")
        XCTAssertEqual(wallet.pendingRenewalSourceBatchId, 100, "the newer renewal keeps its source batch")
        XCTAssertTrue(wallet.issuanceInFlight, "and its guard")
        XCTAssertTrue(h.listener.completed.isEmpty && h.listener.errors.isEmpty)
    }

    func testACancelDuringTheTrustCheckDoesNotLetARefusalClearANewerFlowsGuards() async {
        let h = makeHarness()
        let wallet = h.wallet
        wallet.mdocIssuanceTrustHook = { _ in
            wallet.cancelCurrentFlow()
            wallet.lock.lock(); wallet.issuanceInFlight = true; wallet.lock.unlock()
            return TrustResult(trusted: false)
        }
        await wallet.handleFlowComplete(msg: flowComplete(credentials: [mdocCredential]))
        XCTAssertTrue(wallet.issuanceInFlight)
        XCTAssertTrue(h.listener.untrusted.isEmpty)
        XCTAssertTrue(h.notifier.events.isEmpty)
    }

    func testARefusedRenewalKeepsTheOldBatch() async {
        let h = makeHarness()
        let old = StoredCredential(id: 7, format: "vc+sd-jwt", raw: sdJwt(), batchId: 100, instanceId: 0)
        await h.store.save(old)
        h.wallet.pendingRenewalSourceBatchId = 100
        h.wallet.issuanceInFlight = true

        await h.wallet.handleFlowComplete(msg: flowComplete(credentials: [sdJwtCredential], engineTrusted: false))

        let stored = await h.store.getAll()
        XCTAssertEqual(stored.map(\.id), [7], "the user's existing credential survives a refused renewal")
        XCTAssertNil(h.wallet.pendingRenewalSourceBatchId)
        XCTAssertFalse(h.wallet.issuanceInFlight, "the issuance guard is released")
    }

    // MARK: - The evaluation request (go-trust: resource.id == subject.id)

    private final class BodyLog: @unchecked Sendable {
        private let lock = NSLock()
        private var _bodies: [[String: Any]] = []
        var bodies: [[String: Any]] { lock.lock(); defer { lock.unlock() }; return _bodies }
        func record(_ data: Data?) {
            let json = data.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
            lock.lock(); _bodies.append(json); lock.unlock()
        }
    }

    private func walletRecordingEvaluations(_ log: BodyLog) -> SirosWallet {
        let h = makeHarness()
        h.wallet.apiClient = BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, _, _, body in
            log.record(body)
            return try JSONSerialization.data(withJSONObject: ["decision": true])
        })
        return h.wallet
    }

    // The DS certificate the MdocIssuerIdentity tests use: SAN URI:https://issuer.example/tenant.
    private let issuerNamedCertificate = "MIIB9TCCAZugAwIBAgIUc80Zc4cLM+WPQjLSyPL7OMI3+cgwCgYIKoZIzj0EAwIwLzEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxFDASBgNVBAMMC3VyaV9hbmRfZG5zMB4XDTI2MDkwODEyMzczOFoXDTM2MDkwNTEyMzczOFowLzEXMBUGA1UECgwORml4dHVyZSBJc3N1ZXIxFDASBgNVBAMMC3VyaV9hbmRfZG5zMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWoK0HJW6uuWJAiv9G9wXEGuFP3tLEK/grFOUulXBNc3KcLQO4+zxGs72RqU2k/+XtuLlcEMInF2nurcqyC7Gc6OBlDCBkTAdBgNVHQ4EFgQU4/mpLeZz2FTKNEZygy4n2kC2tiAwHwYDVR0jBBgwFoAU4/mpLeZz2FTKNEZygy4n2kC2tiAwDwYDVR0TAQH/BAUwAwEB/zA+BgNVHREENzA1gglsb2NhbGhvc3SCCXZjLWlzc3VlcoYdaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS90ZW5hbnQwCgYIKoZIzj0EAwIDSAAwRQIgKFHtD1d6Y8d33hIX1t2kxofuHdQjRTfB2I3UR5Gq4nACIQCV4HM2cilF7m4QRHfpgzKJROX6VJh5IVMuSnEU76JrkQ=="

    func testTheIssuerTrustRequestNamesTheSameIdAsSubjectAndResource() async {
        let log = BodyLog()
        let wallet = walletRecordingEvaluations(log)
        let der = [UInt8](Data(base64Encoded: issuerNamedCertificate)!)
        let result = await wallet.evaluateIssuerTrust([der], docType: "org.iso.18013.5.1.mDL")
        XCTAssertTrue(result.trusted)

        let body = log.bodies.first
        let subject = body?["subject"] as? [String: Any]
        let resource = body?["resource"] as? [String: Any]
        // The subject is the issuer's URL, NOT the certificate hash, so a resource.id
        // that stayed the hash would differ from it - which go-trust answers with 400.
        XCTAssertEqual(subject?["id"] as? String, "https://issuer.example/tenant")
        XCTAssertEqual(resource?["id"] as? String, "https://issuer.example/tenant")
        XCTAssertEqual((resource?["key"] as? [String])?.count, 1, "the key material stays in resource.key")
    }

    func testTheReaderTrustRequestNamesTheSameIdAsSubjectAndResource() async {
        let log = BodyLog()
        let wallet = walletRecordingEvaluations(log)
        _ = await wallet.evaluateReaderTrust([[1, 2, 3]])
        let body = log.bodies.first
        let subject = body?["subject"] as? [String: Any]
        let resource = body?["resource"] as? [String: Any]
        XCTAssertEqual(resource?["id"] as? String, subject?["id"] as? String)
    }

    // MARK: - Unreachable means unreachable, not "the PDP said no" (Kotlin SDK #276)

    func testAGatewayErrorCountsAsUnreachableOnlyWithoutAnUpstreamErrorBody() {
        let wallet = makeHarness().wallet
        func unreachable(_ code: Int, _ body: String?) -> Bool {
            wallet.isRemoteTrustEvaluationUnreachable(SirosError.backendApi(code: code, message: "m", body: body))
        }
        XCTAssertTrue(unreachable(502, nil))
        XCTAssertTrue(unreachable(502, ""))
        XCTAssertTrue(unreachable(502, "{}"))
        XCTAssertTrue(unreachable(503, "<html>Bad gateway</html>"))
        XCTAssertTrue(unreachable(504, "  "))
        // go-wallet-backend's authzen proxy answers 502 when the PDP refused the request.
        XCTAssertFalse(unreachable(502, #"{"error":"resource.id must equal subject.id"}"#))
        XCTAssertFalse(unreachable(504, #"{"error":"x"}"#))
        XCTAssertFalse(unreachable(500, ""))
        XCTAssertFalse(unreachable(400, ""))
        XCTAssertFalse(unreachable(0, ""))
    }
}
