// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
import SwiftCBOR
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

    private final class LockedFlag: @unchecked Sendable {
        private let lock = NSLock()
        private var _value = false
        var value: Bool { lock.lock(); defer { lock.unlock() }; return _value }
        func set() { lock.lock(); _value = true; lock.unlock() }
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
        engineTrusted: Bool? = nil,
        startTag: Int? = 0
    ) -> FlowCompleteMessage {
        let obj: [String: Any] = ["type": MessageTypes.flowComplete, "flow_id": flowId, "credentials": credentials]
        var msg = try! JSONDecoder().decode(FlowCompleteMessage.self, from: JSONSerialization.data(withJSONObject: obj))
        msg.startTag = startTag
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

    // MARK: - Wallet-encrypted completions: the gate sees the DECRYPTED credentials

    /// A parseable mdoc (`docType`, one name space, an `issuerAuth` shell); trust is decided by the hook.
    private func mdocRaw() -> String {
        let item: CBOR = .tagged(.encodedCBORDataItem, .byteString(CBOR.map([
            .utf8String("digestID"): .unsignedInt(0),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String("given_name"),
            .utf8String("elementValue"): .utf8String("Jane"),
        ]).encode()))
        let mso: CBOR = .map([.utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL")])
        let taggedMso: CBOR = .tagged(.encodedCBORDataItem, .byteString(mso.encode()))
        let issuerAuth: CBOR = .array([
            .byteString([]), .map([:]), .byteString(taggedMso.encode()), .byteString([UInt8](repeating: 0, count: 64)),
        ])
        let bare: CBOR = .map([
            .utf8String("nameSpaces"): .map([.utf8String("org.iso.18013.5.1"): .array([item])]),
            .utf8String("issuerAuth"): issuerAuth,
        ])
        return Data(bare.encode()).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// An encrypted completion's engine entries carry no values; the wallet holds what it decrypted.
    private func encryptedMdocCompletion(_ h: Harness, raw: String) -> FlowCompleteMessage {
        h.wallet.lock.lock()
        h.wallet.decryptedCredentialResponses["flow-1"] = [DecryptedCredentialResponse(credentials: [raw], notificationId: "n-d")]
        h.wallet.lock.unlock()
        let obj: [String: Any] = [
            "type": MessageTypes.flowComplete, "flow_id": "flow-1",
            "credentials": [["format": "mso_mdoc"]], "credential_response_encrypted": true,
        ]
        var msg = try! JSONDecoder().decode(FlowCompleteMessage.self, from: JSONSerialization.data(withJSONObject: obj))
        msg.startTag = 0
        return msg
    }

    func testAnEncryptedMdocWhoseDecryptedCredentialVerifiesIsStored() async {
        let h = makeHarness()
        let raw = mdocRaw()
        // Trusted only when it is evaluated on the decrypted value: an entry without one is not trusted.
        h.wallet.mdocIssuanceTrustHook = { TrustResult(trusted: $0.credential == raw) }
        await h.wallet.handleFlowComplete(msg: encryptedMdocCompletion(h, raw: raw))

        let stored = await h.store.getAll()
        XCTAssertEqual(stored.count, 1)
        XCTAssertEqual(stored.first?.raw, raw)
        XCTAssertTrue(h.listener.untrusted.isEmpty)
        XCTAssertEqual(h.notifier.events.map(\.event), [CredentialNotificationEvent.accepted])
    }

    func testAnEncryptedCompletionWhoseDecryptedCredentialFailsTrustStoresNothing() async {
        let h = makeHarness()
        let raw = mdocRaw()
        // Untrusted only when evaluated on the decrypted value.
        h.wallet.mdocIssuanceTrustHook = { TrustResult(trusted: $0.credential != raw, reason: "not in VICAL") }
        await h.wallet.handleFlowComplete(msg: encryptedMdocCompletion(h, raw: raw))

        let stored = await h.store.getAll()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertEqual(h.listener.untrusted.first?.reason, "mdoc issuer is not trusted: not in VICAL")
        XCTAssertEqual(h.listener.errors, [issuerNotTrustedMessage])
        XCTAssertEqual(h.notifier.events.map(\.event), [CredentialNotificationEvent.failure])
        XCTAssertEqual(h.notifier.events.first?.notificationId, "n-d", "the issuer's id from the decrypted body")
    }

    func testAPlainCompletionStillGoesThroughTheGateOnTheEnginesCredential() async {
        let h = makeHarness()
        let seen = LockedFlag()
        h.wallet.mdocIssuanceTrustHook = { credential in
            if credential.credential == "not-a-real-mdoc" { seen.set() }
            return TrustResult(trusted: false)
        }
        await h.wallet.handleFlowComplete(msg: flowComplete(credentials: [mdocCredential]))
        XCTAssertTrue(seen.value, "a plain completion is evaluated on the credentials the engine delivered")
        let stored = await h.store.getAll()
        XCTAssertTrue(stored.isEmpty)
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

    func testAFlowCancelledBeforeItsFirstProgressCannotAdoptALaterFlowsEpoch() async {
        let h = makeHarness()
        let wallet = h.wallet
        // A is started under epoch 0 (its flow_start carried tag 0) ...
        wallet.lock.lock(); wallet.issuanceInFlight = true; wallet.lock.unlock()
        // ... and cancelled before its first progress message is handled; renewal B then starts.
        wallet.cancelCurrentFlow()
        wallet.lock.lock(); wallet.pendingRenewalSourceBatchId = 100; wallet.issuanceInFlight = true
        let bTag = wallet.issuanceEpoch
        wallet.lock.unlock()
        XCTAssertNotEqual(bTag, 0)
        // A's first progress and negative completion are only now handled: A still carries ITS tag.
        await wallet.handleFlowComplete(msg: flowComplete(flowId: "A", credentials: [sdJwtCredential], engineTrusted: false, startTag: 0))

        XCTAssertTrue(wallet.issuanceInFlight, "B's guard was not cleared by A's refusal")
        XCTAssertEqual(wallet.pendingRenewalSourceBatchId, 100)
        XCTAssertTrue(h.listener.untrusted.isEmpty && h.listener.errors.isEmpty && h.listener.completed.isEmpty)
        XCTAssertTrue(h.notifier.events.isEmpty)
        let stored = await h.store.getAll()
        XCTAssertTrue(stored.isEmpty)
        // B's own completion, carrying B's tag, still works.
        await wallet.handleFlowComplete(msg: flowComplete(flowId: "B", credentials: [sdJwtCredential], engineTrusted: true, startTag: bTag))
        let after = await h.store.getAll()
        XCTAssertEqual(after.count, 1)
    }

    func testACompletionThatCannotProveItsIssuanceIsRefusedNotAdopted() async {
        let h = makeHarness()
        await h.wallet.handleFlowComplete(msg: flowComplete(credentials: [sdJwtCredential], engineTrusted: true, startTag: nil))
        let stored = await h.store.getAll()
        XCTAssertTrue(stored.isEmpty, "no start tag: ownership cannot be established, nothing is stored")
        XCTAssertTrue(h.listener.completed.isEmpty)
        // A completion that stores nothing and refuses nothing (a presentation) needs no proof.
        await h.wallet.handleFlowComplete(msg: try! JSONDecoder().decode(FlowCompleteMessage.self, from: Data(#"{"type":"flow_complete","flow_id":"p"}"#.utf8)))
        XCTAssertEqual(h.listener.completed, ["p"])
    }

    func testAnUntaggedCompletionWithIssuanceMetadataButNoCredentialsIsRefusedToo() async {
        let h = makeHarness()
        h.wallet.issuanceInFlight = true
        h.wallet.pendingRenewalSourceBatchId = 100
        var msg = flowComplete(credentials: [], startTag: nil)
        msg.credentials = nil
        msg.refreshToken = "rt-must-not-be-captured"
        msg.credentialIssuer = "https://issuer.example"
        msg.selectedCredentialConfigurationId = "pid"
        await h.wallet.handleFlowComplete(msg: msg)

        XCTAssertTrue(h.wallet.issuanceInFlight, "a newer renewal's guards are untouched")
        XCTAssertEqual(h.wallet.pendingRenewalSourceBatchId, 100)
        XCTAssertTrue(h.listener.completed.isEmpty, "not reported complete")
    }

    func testAnIssuanceThatWasCancelledWhilePreparingNoLongerOwnsItsStart() {
        let h = makeHarness()
        let wallet = h.wallet
        // A takes the guard and captures its epoch (what startIssuanceByOffer does) ...
        wallet.lock.lock(); wallet.issuanceInFlight = true; let aEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        XCTAssertTrue(wallet.startStillOwned(aEpoch))
        // ... is cancelled during its metadata fetch; B takes the guard.
        wallet.cancelCurrentFlow()
        wallet.lock.lock(); wallet.issuanceInFlight = true; let bEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        XCTAssertNotEqual(aEpoch, bEpoch)
        XCTAssertFalse(wallet.startStillOwned(aEpoch), "A's suspended start unwinds instead of sending a flow nobody owns")
        XCTAssertTrue(wallet.startStillOwned(bEpoch))
    }

    // MARK: - OAuth resume carries the originating issuance's epoch

    private func pendingAuthorization(startEpoch: Int?) -> PendingAuthorization {
        PendingAuthorization(
            offer: "{}", credentialOfferUri: nil, redirectUri: "https://wallet/cb",
            codeVerifier: "v", state: "s", startEpoch: startEpoch
        )
    }

    func testAResumeSendsWithTheOriginatingEpochNotAFreshSample() async throws {
        let h = makeHarness()
        let wallet = h.wallet
        wallet.lock.lock(); wallet.issuanceInFlight = true; let aEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        var sent: [Int] = []
        wallet.authorizationResumeTokenHook = { "tok" }
        wallet.authorizationResumeConnectHook = { _ in }
        wallet.authorizationResumeSendHook = { sent.append($0) }
        try await wallet.resumeAuthorization(
            engine: WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t"),
            pending: pendingAuthorization(startEpoch: aEpoch), code: "c", startEpoch: aEpoch, tokens: nil
        )
        XCTAssertEqual(sent, [aEpoch])
    }

    func testAnAuthorizationCancelledMidAwaitIsNotResumedEvenAfterANewerStart() async throws {
        let h = makeHarness()
        let wallet = h.wallet
        wallet.lock.lock(); wallet.issuanceInFlight = true; let aEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        var sent: [Int] = []
        // A is cancelled while the connection await is still running, and B starts.
        wallet.authorizationResumeTokenHook = { "tok" }
        wallet.authorizationResumeConnectHook = { _ in
            wallet.cancelCurrentFlow()
            wallet.lock.lock(); wallet.issuanceInFlight = true; wallet.lock.unlock()
        }
        wallet.authorizationResumeSendHook = { sent.append($0) }
        try await wallet.resumeAuthorization(
            engine: WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t"),
            pending: pendingAuthorization(startEpoch: aEpoch), code: "c", startEpoch: aEpoch, tokens: nil
        )
        XCTAssertTrue(sent.isEmpty, "A's resume must not be sent, and must not be re-tagged with B's epoch")
        // And if it had gone out, A's completion (A's tag) is refused: B owns the wallet.
        await wallet.handleFlowComplete(msg: flowComplete(flowId: "A", credentials: [sdJwtCredential], engineTrusted: true, startTag: aEpoch))
        let stored = await h.store.getAll()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertTrue(wallet.issuanceInFlight, "B's guard is untouched")
    }

    func testACancelledResumeDoesNotReconnectTheNewerIssuancesSocket() async throws {
        let h = makeHarness()
        let wallet = h.wallet
        wallet.lock.lock(); wallet.issuanceInFlight = true; let aEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        var reconnected = false
        var sent: [Int] = []
        // A is suspended in the token request; the user cancels A and starts B; then the token returns.
        wallet.authorizationResumeTokenHook = {
            wallet.cancelCurrentFlow()
            wallet.lock.lock(); wallet.issuanceInFlight = true; wallet.lock.unlock()
            return "tok"
        }
        wallet.authorizationResumeConnectHook = { _ in reconnected = true } // stands for forceReconnect + awaitConnected
        wallet.authorizationResumeSendHook = { sent.append($0) }
        try await wallet.resumeAuthorization(
            engine: WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t"),
            pending: pendingAuthorization(startEpoch: aEpoch), code: "c", startEpoch: aEpoch, tokens: nil
        )
        XCTAssertFalse(reconnected, "A must not close B's socket before noticing it no longer owns the wallet")
        XCTAssertTrue(sent.isEmpty)
    }

    func testAnAuthorizationPendingAcrossLogoutAndLoginIsRefusedAndNeverUsesTheNewSession() async throws {
        let h = makeHarness()
        let wallet = h.wallet
        wallet.engineSession = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        wallet.lock.lock(); wallet.issuanceInFlight = true; let aEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        wallet.pendingAuthorizations["A"] = pendingAuthorization(startEpoch: aEpoch)
        // The user logs out and logs in as B before A's browser callback returns.
        _ = wallet.bumpSessionGeneration()
        let usedNewSession = LockedFlag()
        wallet.authorizationResumeTokenHook = { usedNewSession.set(); return "tok-of-B" }
        wallet.authorizationResumeConnectHook = { _ in usedNewSession.set() }
        wallet.authorizationResumeSendHook = { _ in usedNewSession.set() }
        wallet.completeAuthorization(flowId: "A", code: "c", state: "s")
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertFalse(usedNewSession.value, "A's callback must not use B's engine or tokens")
        XCTAssertNil(wallet.pendingAuthorizations["A"], "the stale context is consumed, not left to be replayed")
        XCTAssertTrue(h.listener.completed.isEmpty)
    }

    func testAPresentationCompletionDoesNotClearAnIssuanceInFlightBesideIt() async {
        let h = makeHarness()
        let wallet = h.wallet
        wallet.lock.lock(); wallet.issuanceInFlight = true; wallet.pendingRenewalSourceBatchId = 100; let bEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        // P's completion (untagged, no credentials) is handled after B sent its tagged start.
        await wallet.handleFlowComplete(msg: try! JSONDecoder().decode(FlowCompleteMessage.self, from: Data(#"{"type":"flow_complete","flow_id":"P"}"#.utf8)))
        XCTAssertEqual(h.listener.completed, ["P"], "the presentation callback is preserved")
        XCTAssertTrue(wallet.issuanceInFlight, "B's guard survives")
        XCTAssertEqual(wallet.pendingRenewalSourceBatchId, 100)
        wallet.lock.lock(); let after = wallet.issuanceEpoch; wallet.lock.unlock()
        XCTAssertEqual(after, bEpoch, "B's tag is still valid")
        await wallet.handleFlowComplete(msg: flowComplete(flowId: "B", credentials: [sdJwtCredential], engineTrusted: true, startTag: bEpoch))
        let stored = await h.store.getAll()
        XCTAssertEqual(stored.count, 1, "B's own completion still works")
    }

    func testACancelledRenewalNeitherAssignsASourceBatchNorSendsItsStart() {
        let h = makeHarness()
        let wallet = h.wallet
        wallet.lock.lock(); wallet.issuanceInFlight = true; let aEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        wallet.cancelCurrentFlow()                       // A is cancelled ...
        wallet.lock.lock(); wallet.issuanceInFlight = true; let bEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        var sent: [Int] = []
        // ... and B's commit lands first; then A's late commit.
        XCTAssertTrue(wallet.commitRenewalStart(epoch: bEpoch, batchId: 200) { sent.append($0) })
        XCTAssertFalse(wallet.commitRenewalStart(epoch: aEpoch, batchId: 100) { sent.append($0) })
        XCTAssertEqual(sent, [bEpoch], "A's cancelled start was not sent")
        XCTAssertEqual(wallet.pendingRenewalSourceBatchId, 200, "A did not overwrite B's source batch")
    }

    func testACancelledRenewalSuspendedInItsMetadataFetchCannotOverwriteALaterIssuancesOffer() {
        let h = makeHarness()
        let wallet = h.wallet
        func offer(_ issuer: String, _ config: String) -> CredentialOffer {
            CredentialOffer(credentialConfigurationId: config, credentialIssuerIdentifier: issuer, credentialName: config, issuerName: issuer)
        }
        // Renewal A took the guard and is suspended in fetchIssuerMetadata with its offer staged locally.
        wallet.lock.lock(); wallet.issuanceInFlight = true; let aEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        let aOffer = offer("https://issuer-a.example", "type-a")
        wallet.cancelCurrentFlow()
        // Issuance B starts and prepares ITS offer.
        wallet.lock.lock(); wallet.issuanceInFlight = true; wallet.activeOffer = offer("https://issuer-b.example", "type-b"); wallet.lock.unlock()
        // A's fetch returns: its commit is refused and publishes nothing.
        var sent = false
        XCTAssertFalse(wallet.commitRenewalStart(epoch: aEpoch, batchId: 100, offer: aOffer) { _ in sent = true })
        XCTAssertFalse(sent)
        wallet.lock.lock(); let active = wallet.activeOffer; let batch = wallet.pendingRenewalSourceBatchId; wallet.lock.unlock()
        XCTAssertEqual(active?.credentialIssuerIdentifier, "https://issuer-b.example", "B's offer is untouched")
        XCTAssertEqual(active?.credentialConfigurationId, "type-b", "so are the credential type B validates against and the issuer/configuration its refresh token is stored under")
        XCTAssertNil(batch)
        // A renewal that still owns the wallet does publish its offer, with the batch and the send.
        wallet.lock.lock(); let bEpoch = wallet.issuanceEpoch; wallet.lock.unlock()
        XCTAssertTrue(wallet.commitRenewalStart(epoch: bEpoch, batchId: 200, offer: aOffer) { _ in sent = true })
        wallet.lock.lock(); let published = wallet.activeOffer; wallet.lock.unlock()
        XCTAssertEqual(published?.credentialConfigurationId, "type-a")
        XCTAssertTrue(sent)
    }

    func testAStartPreparingAcrossAnAccountReplacementUnwindsInsteadOfDispatching() throws {
        let h = makeHarness()
        let wallet = h.wallet
        let epoch = try wallet.admitIssuanceStart()      // A is preparing (metadata fetches, token refresh)
        _ = wallet.bumpSessionGeneration()               // logout / login as B
        XCTAssertThrowsError(try wallet.advanceIssuanceStart(epoch, "preparing_issuance"),
                             "A must unwind, not commit its old offer under the new session") { error in
            XCTAssertTrue(error is CancellationError)
        }
        XCTAssertThrowsError(try wallet.dispatchIssuanceStart(epoch: epoch) { XCTFail("must not dispatch") })
        // The stale start's own failure path returns early (stale epoch) and releases
        // nothing, so the session change itself must have released the guard ...
        XCTAssertFalse(wallet.failIssuanceStart(epoch, SirosError.wallet(message: "x")) is SirosError)
        wallet.lock.lock(); let held = wallet.issuanceInFlight; wallet.lock.unlock()
        XCTAssertFalse(held, "the in-flight guard was released by the session change")
        // ... so a NEW issuance on the new session can be admitted.
        XCTAssertNoThrow(try wallet.admitIssuanceStart())
    }

    func testAnAuthorizationThatCannotBeTiedToItsIssuanceIsRefused() {
        let h = makeHarness()
        let wallet = h.wallet
        wallet.engineSession = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        wallet.pendingAuthorizations["A"] = pendingAuthorization(startEpoch: nil)
        wallet.completeAuthorization(flowId: "A", code: "c", state: "s")
        XCTAssertEqual(h.listener.errors.count, 1)
        XCTAssertNil(wallet.pendingAuthorizations["A"])
    }

    // MARK: - The signed docType

    private func msoPayload(docType: String?, tagged: Bool = true, bstr: Bool = false) -> [UInt8] {
        var map: [CBOR: CBOR] = ["version": .utf8String("1.0")]
        if let docType { map["docType"] = .utf8String(docType) }
        let mso = CBOR.map(map)
        // bstr: the untagged bstr(MSO) encoding some issuers emit (MdocCbor.decodeMso accepts it).
        if bstr { return CBOR.byteString(mso.encode()).encode() }
        return tagged ? CBOR.tagged(.encodedCBORDataItem, .byteString(mso.encode())).encode() : mso.encode()
    }

    func testAnEnvelopeDocTypeThatDiffersFromTheSignedMsoIsRefused() {
        let signedB = msoPayload(docType: "org.example.B")
        let reason = SirosWallet.issuerAuthDocTypeRefusal(msoPayload: signedB, envelopeDocType: "org.example.A")
        XCTAssertNotNil(reason)
        XCTAssertTrue(reason?.contains("org.example.A") == true && reason?.contains("org.example.B") == true)
    }

    func testMatchingDocTypeIsAcceptedTaggedOrBare() {
        XCTAssertNil(SirosWallet.issuerAuthDocTypeRefusal(msoPayload: msoPayload(docType: "org.example.A"), envelopeDocType: "org.example.A"))
        XCTAssertNil(SirosWallet.issuerAuthDocTypeRefusal(msoPayload: msoPayload(docType: "org.example.A", tagged: false), envelopeDocType: "org.example.A"))
    }

    func testAnUntaggedBstrMsoIsReadLikeMdocCborDoes() {
        let payload = msoPayload(docType: "org.example.A", bstr: true)
        XCTAssertEqual(SirosWallet.signedDocType(msoPayload: payload), "org.example.A")
        XCTAssertNil(SirosWallet.issuerAuthDocTypeRefusal(msoPayload: payload, envelopeDocType: "org.example.A"),
                     "a genuine credential with an untagged bstr(MSO) must not be refused as unreadable")
        XCTAssertNotNil(SirosWallet.issuerAuthDocTypeRefusal(msoPayload: payload, envelopeDocType: "org.example.B"),
                        "and a mismatch is still caught in that encoding")
    }

    func testAMsoWithNoReadableDocTypeCannotBeComparedAndIsRefused() {
        XCTAssertNotNil(SirosWallet.issuerAuthDocTypeRefusal(msoPayload: msoPayload(docType: nil), envelopeDocType: "x"))
        XCTAssertNotNil(SirosWallet.issuerAuthDocTypeRefusal(msoPayload: [0xff, 0x00], envelopeDocType: "x"))
        XCTAssertNotNil(SirosWallet.issuerAuthDocTypeRefusal(msoPayload: [], envelopeDocType: "x"))
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
