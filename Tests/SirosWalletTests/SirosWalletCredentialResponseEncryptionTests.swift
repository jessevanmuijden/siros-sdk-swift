// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosTransport
@testable import SirosCredentials
@testable import SirosWallet
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

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
}

private final class RecordingSender: SignResponseSender, @unchecked Sendable {
    private(set) var sent: [SignResponseMessage] = []
    func sendSignResponse(_ message: SignResponseMessage) { sent.append(message) }
}

private final class RecordingNotifier: CredentialNotifier, @unchecked Sendable {
    private(set) var sent: [(flowId: String, notificationId: String, event: String)] = []
    func sendCredentialNotification(flowId: String, notificationId: String, event: String, eventDescription: String?) {
        sent.append((flowId, notificationId, event))
    }
}

/// An engine socket that goes nowhere: open until cancelled, sends are swallowed, nothing is ever received. The
/// real `URLSession` socket is not used from these tests.
private final class SentTexts: @unchecked Sendable {
    private let lock = NSLock(); private var texts: [String] = []
    func add(_ t: String) { lock.lock(); texts.append(t); lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return texts }
    var signResponses: Int { all.filter { $0.contains("\"sign_response\"") }.count }
}

private final class IdleSocket: EngineSocket, @unchecked Sendable {
    private let lock = NSLock()
    private var running = true
    var recorder: SentTexts?
    var isRunning: Bool { lock.lock(); defer { lock.unlock() }; return running }
    func resume() {}
    func cancel(closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) { lock.lock(); running = false; lock.unlock() }
    func sendText(_ text: String, completion: @escaping @Sendable (Error?) -> Void) { recorder?.add(text); completion(nil) }
    func receiveMessage() async throws -> URLSessionWebSocketTask.Message {
        while isRunning { try await Task.sleep(nanoseconds: 20_000_000) }
        throw CancellationError()
    }
    func sendPing(completion: @escaping @Sendable (Error?) -> Void) { completion(nil) }
}

private func idleEngine(recorder: SentTexts? = nil) -> WalletEngineSession {
    WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t", socketFactory: { _ in
        let socket = IdleSocket(); socket.recorder = recorder; return socket
    })
}

/// A WMP transport that answers `wmp.session.create` and records every message it is asked to send, so a test can
/// see that a session close really went out.
private final class AnsweringTransport: TransportProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var _sent: [Data] = []
    private var _state: TransportState = .disconnected
    private let stateCont: AsyncStream<TransportState>.Continuation
    let stateStream: AsyncStream<TransportState>
    private let incomingCont: AsyncStream<Data>.Continuation
    private let _incoming: AsyncStream<Data>
    var currentState: TransportState { lock.lock(); defer { lock.unlock() }; return _state }
    var sentMethods: [String] {
        lock.lock(); defer { lock.unlock() }
        return _sent.compactMap { (try? JSONSerialization.jsonObject(with: $0) as? [String: Any])?["method"] as? String }
    }
    init() {
        var sc: AsyncStream<TransportState>.Continuation!
        stateStream = AsyncStream { sc = $0 }; stateCont = sc
        var ic: AsyncStream<Data>.Continuation!
        _incoming = AsyncStream { ic = $0 }; incomingCont = ic
    }
    func connect() async throws { lock.lock(); _state = .connected; lock.unlock(); stateCont.yield(.connected) }
    func send(_ message: Data) async throws {
        lock.lock(); _sent.append(message); lock.unlock()
        guard let object = try? JSONSerialization.jsonObject(with: message) as? [String: Any],
              object["method"] as? String == "wmp.session.create", let id = object["id"] as? String else { return }
        incomingCont.yield(Data(#"{"jsonrpc":"2.0","id":"\#(id)","result":{"wmp":{"version":"0.1","session_id":"s-1"},"resumption_token":"rt"}}"#.utf8))
    }
    func receiveFromServer(_ data: Data) { incomingCont.yield(data) }
    func incoming() -> AsyncStream<Data> { _incoming }
    func disconnect() async { lock.lock(); _state = .disconnected; lock.unlock(); stateCont.yield(.disconnected) }
}

/// A notifier whose hand-over takes a while: the failure must be recorded before the rejecting call returns.
private final class SlowAwaitableNotifier: AwaitableCredentialNotifier, @unchecked Sendable {
    private let lock = NSLock()
    private var _sent: [String] = []
    var sent: [String] { lock.lock(); defer { lock.unlock() }; return _sent }
    func sendCredentialNotification(flowId: String, notificationId: String, event: String, eventDescription: String?) {
        Task { await sendCredentialNotificationAndWait(flowId: flowId, notificationId: notificationId, event: event, eventDescription: eventDescription) }
    }
    func sendCredentialNotificationAndWait(flowId: String, notificationId: String, event: String, eventDescription: String?) async {
        try? await Task.sleep(nanoseconds: 80_000_000)
        lock.lock(); _sent.append(event); lock.unlock()
    }
}

private final class Listener: WalletEventListener, @unchecked Sendable {
    var errors: [String] = []
    var completed: [String] = []
    func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] { [] }
    func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) { errors.append(errorMessage) }
    func onFlowComplete(flowId: String, redirectUri: String?) { completed.append(flowId) }
}

/// Engine-blind issuance on the wallet: the response-encryption key, `decrypt_credential_response` on
/// both transports, and the `flow_complete` pairing. The JWE is a go-jose v4.1.6 ECDH-ES+A256KW /
/// A256GCM response (the pair gdc advertises) to a fixed test key.
final class SirosWalletCredentialResponseEncryptionTests: XCTestCase {

    private static let recipientD = "xu-cXXiuASoBEWSss5fOJIil0NepofeuDXqNXB9aHTc"
    private static let jwe = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImN0eSI6IkpXVCIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJNaURZdF95aGt3U3JRZG9MSFF0WmU5ODFMbnNvWFNSV0l5XzBqTGxTRG9VIiwieSI6IjJUTWRWeWd1RWo2TENFdmZKanBOVTNUY21KVlFDTUNfQWV1cUJ5YnZMTFUifX0.guInIfQMmm3JKXiDuEHdJo6EeZEJDVAc27XZbLeQnnKJQoKsThpbnQ.fxSbn2AHhTP7nKa1.oSd7nnmcGXTh1zeSxyVUnkSk3esX_drDrr6Aj0JafLfdznsjIl8etaV0v6ZNCRnstrSIMWJTOmVOmWjuE_BkR-98BV3oTkAxn6QWKSfQDxnemQq9FHjQDTjYe2rsoeaka2xRPFTFgdV_QyKnvoUNCqKmO3esJMv2RYMjpm-EKyvyCi-bdeOACoyIdvTKw51n5BWw19jj0ovjW7FioZCtdMuOJEnVgKQ_CN5NjUYZNs_LGlcbag2Hox7UiEF_DBO2UoAF55HD0VNGM2F_vJVUyaxkfb4OxdVamWSwYRTXI5AcqxlD33pvUk5FMX9XHgtU.pI1hC1eeZeOsA5c5tP9a3Q"
    private static let jweDeferred = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIyb2hzemZSSUJ4ekg0dENOREpWbHExUU9yYk96a0ZGdGlIOWs2dTNVWjVjIiwieSI6Ik1YU3JVLWJGVzBNdGVyRWpLQmY3MFQwcUt1UG1WVTB1YnZxN0lMSm4wbncifX0.kCtw0ue8R0VZtgRXiPoiSkX1uWyzl4F1Us_O0SR45ZWo3mIK3xKBvg.5vICxNjnqA5hjI-f.oSbTeZez3MjbSUXEYKlDRuEjsbp7gH-oZ9cVJ7g2eRpl_GZPVcw.22SeVPINtknkA6ybIkYH3A"
    private static let jweBoth = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiI3RjV6eklmR1BxWXpJeU1lSjhpTUcwTTV6TlA3NS1nS0xaVWdhVWF0ajhrIiwieSI6Ik5rQnVYbG5NZnllcmdxUjhEQzBEcmFQWVR4WlNWY2hzSTM3YTVoOEZQYm8ifX0.4gIiejmyeA61NLD34AYAyzS4d1aV6XKgMNb50djpFN2UydYSs5pOJg.XvLr8wEicHjZq5rX.bdzX2QY89AErIIqPlHkoxoqui75AxJX1xJQJMrHnBAfGovgYWcZFhjeVmlWROVspiPoZWGfc9lB6Zd6y.IrvlN4kLnwztYvamFu3GbA"
    private static let jweBatch = "eyJhbGciOiJFQ0RILUVTK0EyNTZLVyIsImVuYyI6IkEyNTZHQ00iLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJnQlM3N3NhQ0NvSVplQ2RtUThVSjJtRXhXbkdPN0tEN0sxMFVqSEhjOTlnIiwieSI6ImFxLVZOUDRHckF1T1h1V05qa1RCSFNOek94V21ZMlVmRUhqZFoySkRYX1UifX0.5xroyleSTxZturr07WS5QoiHmPr-H_MUJFupCxnEXs4J4eEboTTAxA.1ZAWZI-0JYLuJ33G.IAZQlqX0NHRs4cXgrCwS5D-2ojsvCA7Kadw85ouLUeWR5dkxeFgZ4UIdIZXbZpZy57yJNudT6iFgVoY6li1WldJdxmONV_ehm_6D8NFJQMyeC3eYUA.Iv3yi3MTWOE-2t8EuglsSA"
    private static let credential = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ1cm46ZXVkaTpwaWQ6MSJ9.c2ln~disclosure~"
    private static let seedNamespace = "org.siros.nym_auth"
    private static let seed = "00112233445566778899aabbccddeeff"

    private let pair = CredentialResponseEncryptionParams(alg: "ECDH-ES+A256KW", enc: "A256GCM")
    private let request = CredentialResponseEncryptionRequest(alg: "ECDH-ES+A256KW", enc: "A256GCM", required: true)

    private func wallet(store: InMemoryCredentialStore = InMemoryCredentialStore()) -> SirosWallet {
        let w = SirosWallet(
            config: WalletConfig(backendUrl: "https://example.invalid", credentialStore: store),
            authProvider: StubAuthProvider(), keystore: StubKeystoreManager(), accountRegistry: .inMemory()
        )
        XCTAssertNotNil(w)
        return w!
    }

    /// Install the fixed test key as this flow's response-encryption key.
    private func installKey(_ w: SirosWallet, flowId: String) throws {
        let d = try XCTUnwrap(CredentialResponseJwe.decode(Self.recipientD))
        let key = CredentialResponseKey(params: pair, privateKey: try P256.KeyAgreement.PrivateKey(rawRepresentation: d))
        w.lock.lock(); w.credentialResponseKeys[flowId] = key; w.offeredResponseKeyFlows.insert(flowId); w.lock.unlock()
    }

    private func decryptMessage(flowId: String, jwe: String, deferred: Bool = false) throws -> SignRequestMessage {
        let json = """
        {"type":"sign_request","flow_id":"\(flowId)","message_id":"m1","action":"decrypt_credential_response",
         "params":{"jwe":"\(jwe)","deferred":\(deferred)}}
        """
        return try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
    }

    /// The wallet's initial issuance epoch is 0: a completion carries the tag its flow started under,
    /// and the trust gate drops one that has credentials but no tag.
    private static func decodeFlowComplete(_ object: [String: Any]) throws -> FlowCompleteMessage {
        var msg = try JSONDecoder().decode(FlowCompleteMessage.self, from: try JSONSerialization.data(withJSONObject: object))
        msg.startTag = 0
        return msg
    }

    private func flowComplete(flowId: String, entries: Int, encrypted: Bool = true) throws -> FlowCompleteMessage {
        let credentials = (0..<entries).map { _ in ["format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"] }
        let object: [String: Any] = [
            "type": "flow_complete", "flow_id": flowId, "credentials": credentials, "credential_response_encrypted": encrypted,
        ]
        return try Self.decodeFlowComplete(object)
    }

    // MARK: - Helpers for responses the wallet must reject

    /// Encrypt `body` to the wallet's own key with ECDH-ES / A128GCM (independent of the decryptor under test
    /// only in direction; the KDF is the one the go-jose and RFC vectors pin).
    private func encrypt(_ body: String, to key: CredentialResponseKey) throws -> String {
        let jwk = key.publicJwk
        let x = try XCTUnwrap(jwk["x"].flatMap(CredentialResponseJwe.decode)), y = try XCTUnwrap(jwk["y"].flatMap(CredentialResponseJwe.decode))
        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + x + y)
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let point = ephemeral.publicKey.x963Representation
        let header = ["alg": "ECDH-ES", "enc": "A128GCM", "epk": [
            "kty": "EC", "crv": "P-256", "x": CredentialResponseJwe.encode(point.subdata(in: 1..<33)),
            "y": CredentialResponseJwe.encode(point.subdata(in: 33..<65)),
        ]] as [String: Any]
        let protected = CredentialResponseJwe.encode(try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys]))
        let z = try ephemeral.sharedSecretFromKeyAgreement(with: recipient).withUnsafeBytes { Array($0) }
        let cek = CredentialResponseJwe.concatKdf(z: z, algorithmId: "A128GCM", apu: Data(), apv: Data(), keyBits: 128)
        let box = try AES.GCM.seal(Data(body.utf8), using: SymmetricKey(data: cek), nonce: AES.GCM.Nonce(), authenticating: Data(protected.utf8))
        return [protected, "", CredentialResponseJwe.encode(Data(box.nonce)), CredentialResponseJwe.encode(box.ciphertext), CredentialResponseJwe.encode(box.tag)].joined(separator: ".")
    }

    private func installOwnKey(_ w: SirosWallet, flowId: String) throws -> CredentialResponseKey {
        let key = try XCTUnwrap(CredentialResponseKey(params: CredentialResponseEncryptionParams(alg: "ECDH-ES", enc: "A128GCM")))
        w.lock.lock(); w.credentialResponseKeys[flowId] = key; w.offeredResponseKeyFlows.insert(flowId); w.lock.unlock()
        return key
    }

    // MARK: - Limits on the decrypted credential_metadata (the engine used to enforce them)

    func testAResponseBreakingTheMetadataLimitsIsRefusedAndTheIssuerIsTold() async throws {
        func nested(_ depth: Int) -> String { String(repeating: "[", count: depth) + String(repeating: "]", count: depth) }
        let members = (0..<257).map { "\"m\($0)\":1" }.joined(separator: ",")
        let longName = String(repeating: "n", count: 257)
        let big = String(repeating: "x", count: 1_048_600)
        let bodies: [(String, String)] = [
            ("depth 17", nested(17)),
            ("257 members", "{\(members)}"),
            ("a 257-byte member name", "{\"\(longName)\":1}"),
            ("over 1 MiB", "\"\(big)\""),
            ("a duplicate member", #"{"a":1,"a":2}"#),
        ]
        for (name, metadata) in bodies {
            let w = wallet()
            let notifier = RecordingNotifier()
            w.credentialNotifier = notifier
            let key = try installOwnKey(w, flowId: "l")
            let body = #"{"credentials":[{"credential":"c"}],"notification_id":"n-1","credential_metadata":\#(metadata)}"#
            do {
                _ = try await w.decryptCredentialResponse(flowId: "l", jwe: try encrypt(body, to: key), deferred: false)
                XCTFail("\(name) must be refused")
            } catch { XCTAssertEqual(error as? CredentialResponseError, .malformedResponse, name) }
            XCTAssertEqual(notifier.sent.map(\.event), [CredentialNotificationEvent.failure], name)
            XCTAssertEqual(notifier.sent.first?.notificationId, "n-1", name)
            XCTAssertTrue(w.takeDecryptedCredentialResponses(flowId: "l").isEmpty, name)
        }
    }

    /// The `credential_failure` is handed over BEFORE the rejecting call returns (so before the error answer).
    func testTheFailureNotificationPrecedesTheRejection() async throws {
        let w = wallet()
        let notifier = SlowAwaitableNotifier()
        w.credentialNotifier = notifier
        let key = try installOwnKey(w, flowId: "o")
        do {
            _ = try await w.decryptCredentialResponse(
                flowId: "o", jwe: try encrypt(#"{"credentials":[],"notification_id":"n-o"}"#, to: key), deferred: false
            )
            XCTFail("rejected")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .malformedResponse) }
        XCTAssertEqual(notifier.sent, [CredentialNotificationEvent.failure], "already sent when the call returns")
    }

    /// A cancelled sign request (a WMP child flow) leaves no response behind and reports no success.
    func testACancelledDecryptRequestKeepsNothing() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        let w = wallet()
        try installKey(w, flowId: "cx")
        let gate = Gate()
        w.credentialMetadataReceiver = { _, _, _ in
            while await !gate.isOpen { await Task.yield() }   // ignores cancellation, like a handler that does
        }
        let task = Task { try await w.decryptCredentialResponse(flowId: "cx", jwe: Self.jwe, deferred: false) }
        try await Task.sleep(nanoseconds: 100_000_000)
        task.cancel()
        await gate.release()
        do {
            _ = try await task.value
            XCTFail("a cancelled request must not report success")
        } catch { XCTAssertTrue(error is CancellationError, "\(error)") }
        XCTAssertTrue(w.takeDecryptedCredentialResponses(flowId: "cx").isEmpty)
    }

    /// A key-only proof request that is cancelled installs no key.
    func testACancelledProofRequestInstallsNoKey() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        let w = wallet()
        let gate = Gate()
        let json = """
        {"type":"sign_request","flow_id":"kx","message_id":"m","action":"generate_proof","params":{"audience":"a","nonce":"n",
         "credential_response_encryption":{"alg":"ECDH-ES","enc":"A256GCM","required":true}}}
        """
        let message = try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
        let sender = RecordingSender()
        let task = Task {
            while await !gate.isOpen { await Task.yield() }
            try await w.answerGenerateProof(engine: sender, msg: message)
        }
        try await Task.sleep(nanoseconds: 50_000_000)
        task.cancel()
        await gate.release()
        do { try await task.value; XCTFail("cancelled") } catch { XCTAssertTrue(error is CancellationError) }
        w.lock.lock(); let has = w.credentialResponseKeys["kx"] != nil; w.lock.unlock()
        XCTAssertFalse(has)
        XCTAssertTrue(sender.sent.isEmpty)
    }

    /// A cancelled WMP decrypt child is not a failure of its parent issuance: whichever way its receiver ends
    /// (throwing `CancellationError`, or returning normally) the parent's key, guards and state are untouched,
    /// no `credential_failure` is sent, nothing is buffered, and a retry does not find a duplicate.
    func testACancelledWmpDecryptChildDoesNotFailItsParent() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        for throwing in [true, false] {
            let w = wallet()
            let notifier = RecordingNotifier()
            w.credentialNotifier = notifier
            let listener = Listener()
            w.eventListener = listener
            try installKey(w, flowId: "wp")
            w.lock.lock(); w.issuanceInFlight = true; w.lock.unlock()
            let gate = Gate()
            w.credentialMetadataReceiver = { _, _, _ in
                while await !gate.isOpen { await Task.yield() }
                if throwing { throw CancellationError() }
            }
            let child = Task { try await w.wmpDecryptCredentialResponse(flowId: "wp", params: SignSubFlowParams(action: "decrypt_credential_response", jwe: Self.jwe, deferred: false)) }
            try await Task.sleep(nanoseconds: 80_000_000)
            child.cancel()
            await gate.release()
            do { _ = try await child.value; XCTFail("a cancelled child reports nothing") } catch { /* the profile stays silent */ }
            w.lock.lock()
            let guards = (w.issuanceInFlight, w.credentialResponseKeys["wp"] != nil)
            w.lock.unlock()
            XCTAssertTrue(guards.0, "throwing=\(throwing): the parent's in-flight guard is not reset")
            XCTAssertTrue(guards.1, "throwing=\(throwing): the parent's key is kept")
            XCTAssertTrue(listener.errors.isEmpty, "throwing=\(throwing): the parent is not failed")
            XCTAssertTrue(notifier.sent.isEmpty, "throwing=\(throwing): a cancellation is not a rejection")
            XCTAssertTrue(w.takeDecryptedCredentialResponses(flowId: "wp").isEmpty, "throwing=\(throwing)")
        }
    }

    /// A decrypt whose flow was cancelled while its receiver was suspended fails later, after another issuance has
    /// begun: its failure must not reset the new issuance's guards, key or state.
    func testALateFailureOfACancelledFlowLeavesTheNextIssuanceAlone() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        struct Boom: Error {}
        let w = wallet()
        let listener = Listener()
        w.eventListener = listener
        try installKey(w, flowId: "A")
        let gate = Gate()
        w.credentialMetadataReceiver = { _, _, _ in
            while await !gate.isOpen { await Task.yield() }
            throw Boom()
        }
        let a = Task { try await w.wmpDecryptCredentialResponse(flowId: "A", params: SignSubFlowParams(action: "decrypt_credential_response", jwe: Self.jwe, deferred: false)) }
        try await Task.sleep(nanoseconds: 80_000_000)
        w.cancelCurrentFlow()                       // issuance A is cancelled ...
        w.lock.lock(); w.issuanceInFlight = true; w.lock.unlock()
        try installKey(w, flowId: "B")              // ... and B begins
        await gate.release()
        do { _ = try await a.value; XCTFail("A's decrypt fails") } catch { /* reported to the engine for A only */ }
        w.lock.lock()
        let kept = (w.issuanceInFlight, w.credentialResponseKeys["B"] != nil)
        w.lock.unlock()
        XCTAssertTrue(kept.0, "B's in-flight guard is not reset by A's late failure")
        XCTAssertTrue(kept.1, "B's key is kept")
        XCTAssertTrue(listener.errors.isEmpty, "B is not failed")
    }

    // MARK: - Teardown

    private func connectedPeer() async throws -> (WmpPeer, AnsweringTransport) {
        let transport = AnsweringTransport()
        let peer = WmpPeer(session: WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 2_000)))
        try await peer.connect(authToken: "t")
        return (peer, transport)
    }

    private func keyOnlyProofMessage(flowId: String) throws -> SignRequestMessage {
        let json = """
        {"type":"sign_request","flow_id":"\(flowId)","message_id":"m","action":"generate_proof","params":{"audience":"a","nonce":"n",
         "credential_response_encryption":{"alg":"ECDH-ES","enc":"A256GCM","required":true}}}
        """
        return try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
    }

    /// `destroy()` and the local session end capture the peer BEFORE clearing the reference and close it on a task
    /// that does not depend on the wallet: the session close really goes out.
    func testDestroyAndLocalSessionEndActuallyCloseTheWmpPeer() async throws {
        for how in ["destroy", "endSessionLocally"] {
            let w = wallet()
            let (peer, transport) = try await connectedPeer()
            w.lock.lock(); w.wmpPeer = peer; w.lock.unlock()
            if how == "destroy" { w.destroy() } else { w.endSessionLocally() }
            for _ in 0..<1000 where !transport.sentMethods.contains("wmp.session.close") { try await Task.sleep(nanoseconds: 10_000_000) }
            XCTAssertTrue(transport.sentMethods.contains("wmp.session.close"), "\(how): the close ran")
            XCTAssertEqual(transport.currentState, .disconnected, how)
            w.lock.lock(); XCTAssertNil(w.wmpPeer, how); w.lock.unlock()
        }
    }

    /// A request that reaches a session that has ended is refused before any key is generated, on both transports.
    func testRequestsForAnEndedSessionAllocateNothing() async throws {
        let w = wallet()
        w.markSessionEnded(true)
        let sender = RecordingSender()
        try await w.answerGenerateProof(engine: sender, msg: try keyOnlyProofMessage(flowId: "late"))
        XCTAssertEqual(sender.sent.first?.errorCode, "SESSION_ENDED")
        XCTAssertNil(sender.sent.first?.credentialResponseEncryptionJwk)
        do {
            _ = try await w.wmpGenerateProof(flowId: "late2", params: SignSubFlowParams(
                action: "generate_proof", credentialResponseEncryption: CredentialResponseEncryptionRequest(alg: "ECDH-ES", enc: "A256GCM", required: true)
            ))
            XCTFail("an ended session is not served")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .sessionEnded) }
        w.lock.lock(); XCTAssertTrue(w.credentialResponseKeys.isEmpty, "no key was generated"); w.lock.unlock()
        // A new connection serves requests again.
        w.markSessionEnded(false)
        try await w.answerGenerateProof(engine: sender, msg: try keyOnlyProofMessage(flowId: "again"))
        XCTAssertNotNil(sender.sent.last?.credentialResponseEncryptionJwk)
    }

    /// The regression class: an "ended" check that outlives a normal login would refuse every request after it.
    /// After a session ended, a new connection on EITHER transport (the connect itself need not succeed) clears
    /// the ended state before anything else runs, so requests are served again, and nothing later sets it back.
    func testRequestsAreServedAfterANewConnectionOnBothTransports() async throws {
        for transport in ["engine", "wmp"] {
            let w = SirosWallet(
                config: WalletConfig(backendUrl: "http://127.0.0.1:1", engineUrl: "http://127.0.0.1:1", credentialStore: InMemoryCredentialStore()),
                authProvider: StubAuthProvider(), keystore: StubKeystoreManager(), accountRegistry: .inMemory()
            )!
            let previousFactory = SirosWallet.createEngineSession
            defer { SirosWallet.createEngineSession = previousFactory }
            SirosWallet.createEngineSession = { _, _ in idleEngine() }
            w.endSessionLocally()                       // logout: the session has ended
            XCTAssertTrue(w.sessionHasEnded)
            let connect = Task { () -> Void in
                if transport == "engine" { try? await w.connectEngine(appToken: "t") } else { try? await w.connectViaWmp(appToken: "t") }
            }
            for _ in 0..<200 where w.sessionHasEnded { try await Task.sleep(nanoseconds: 10_000_000) }
            XCTAssertFalse(w.sessionHasEnded, "\(transport): the new connection clears the ended state")
            if transport == "engine" {
                // The flag is cleared at the start of the connect; the session object is installed a moment later.
                for _ in 0..<300 where w.engineSession == nil { try await Task.sleep(nanoseconds: 10_000_000) }
                let engine = try XCTUnwrap(w.engineSession)
                var message = try keyOnlyProofMessage(flowId: "ok-\(transport)")
                message.socketGeneration = engine.socketGeneration       // as the session stamps it on receipt
                try await w.answerGenerateProof(engine: engine, msg: message)
            } else {
                let result = try await w.wmpGenerateProof(flowId: "ok-\(transport)", params: SignSubFlowParams(
                    action: "generate_proof", credentialResponseEncryption: CredentialResponseEncryptionRequest(alg: "ECDH-ES", enc: "A256GCM", required: true)
                ))
                XCTAssertNotNil(result.credentialResponseEncryptionJwk)
            }
            w.lock.lock(); let has = w.credentialResponseKeys["ok-\(transport)"] != nil; w.lock.unlock()
            XCTAssertTrue(has, "\(transport): a request after a normal connection is served")
            connect.cancel()
            w.destroy()
        }
    }

    /// Validate-then-claim is one step: a request that passed the live check, then lost its session to teardown
    /// (interleaved here by hand, no sleeps), must not claim a key; and a claim attempted after teardown is refused.
    func testAClaimAfterTeardownRetainsNoKeyAndALateClaimIsRefused() async throws {
        let w = wallet()
        let request = CredentialResponseEncryptionRequest(alg: "ECDH-ES", enc: "A256GCM", required: true)
        let generation = try w.requireLiveSession(flowId: "x")          // the request is live ...
        w.markSessionEnded(true)                                        // ... teardown lands before it claims ...
        XCTAssertNil(w.credentialResponseEncryptionJwk(flowId: "x", request: request, generation: generation))
        w.lock.lock(); XCTAssertTrue(w.credentialResponseKeys.isEmpty, "no private key is retained"); w.lock.unlock()
        XCTAssertThrowsError(try w.requireLiveSession(flowId: "x"))     // ... and a later request is refused outright
        do {
            _ = try await w.decryptCredentialResponse(flowId: "x", jwe: Self.jwe, deferred: false)
            XCTFail("decrypt on an ended session")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .sessionEnded) }
    }

    /// A pending (deferred) response that carries the delivered seed is refused, and the issuer is told, whether or
    /// not a metadata receiver is installed; it is not dropped as an ordinary pending answer.
    func testAPendingResponseCarryingTheSeedIsRefusedAndTheIssuerTold() async throws {
        let w = wallet()
        let notifier = RecordingNotifier()
        w.credentialNotifier = notifier
        let key = try installOwnKey(w, flowId: "ds")
        let body = #"{"transaction_id":"tx","interval":1,"notification_id":"n-seed","credential_metadata":{"org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"}}}"#
        do {
            _ = try await w.decryptCredentialResponse(flowId: "ds", jwe: try encrypt(body, to: key), deferred: true)
            XCTFail("a pending response must not carry the seed")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .deferredSeed) }
        XCTAssertEqual(notifier.sent.map(\.event), [CredentialNotificationEvent.failure])
        XCTAssertEqual(notifier.sent.first?.notificationId, "n-seed")
        // An ordinary pending response is still accepted.
        let plain = #"{"transaction_id":"tx","interval":1}"#
        let control = try await w.decryptCredentialResponse(flowId: "ds", jwe: try encrypt(plain, to: key), deferred: true)
        XCTAssertEqual(control.transactionId, "tx")
    }

    /// A proof that finishes after its flow was cancelled must not write the old flow's key ids into the issuance
    /// that runs now.
    func testAStaleProofResultDoesNotWriteAttestedKeyIds() throws {
        let w = wallet()
        let generation = w.credentialResponseGeneration(flowId: "A")
        w.cancelCurrentFlow()                                         // A is cancelled ...
        w.lock.lock(); w.activeAttestedKeyIds = ["new"]; w.lock.unlock()   // ... and the next issuance has its ids
        XCTAssertThrowsError(try w.applyProofResult(["old"], flowId: "A", generation: generation))
        w.lock.lock(); XCTAssertEqual(w.activeAttestedKeyIds, ["new"]); w.lock.unlock()
        XCTAssertNoThrow(try w.applyProofResult(["fresh"], flowId: "A", generation: w.credentialResponseGeneration(flowId: "A")))
    }

    /// `cancelCurrentFlow()` on WMP stops the parent's children before it returns: a child suspended in its handler
    /// that then returns normally answers nothing, and the cancel goes out on the peer.
    func testCancelCurrentFlowStopsWmpChildrenAndSendsTheCancel() async throws {
        final class Gate: @unchecked Sendable {
            private let lock = NSLock(); private var c: CheckedContinuation<Void, Never>?; private var opened = false; private var _in = false
            var entered: Bool { lock.lock(); defer { lock.unlock() }; return _in }
            func wait() async { await withCheckedContinuation { (k: CheckedContinuation<Void, Never>) in lock.lock(); _in = true; if opened { lock.unlock(); k.resume() } else { c = k; lock.unlock() } } }
            func open() { lock.lock(); opened = true; let k = c; c = nil; lock.unlock(); k?.resume() }
        }
        let w = wallet()
        let (peer, transport) = try await connectedPeer()
        let gate = Gate()
        peer.use(OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
            await gate.wait()
            return SignSubFlowResult(proofs: [ProofObject(proofType: "jwt", jwt: "a.b.c")])
        })))
        w.lock.lock(); w.wmpPeer = peer; w.lock.unlock()
        // The wallet is `.ready`: nothing on the WMP path sets `.flowActive`, so the cancel must not depend on it.
        transport.receiveFromServer(Data(#"{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"p1","flow_type":"oid4vci"}}"#.utf8))
        try await Task.sleep(nanoseconds: 100_000_000)
        transport.receiveFromServer(Data(#"{"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"c1","flow_type":"sign","params":{"action":"generate_proof","nonce":"n","audience":"a","parent_flow_id":"p1"}}}"#.utf8))
        for _ in 0..<300 where !gate.entered { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertTrue(gate.entered, "the child is suspended in its handler")
        w.cancelCurrentFlow()
        gate.open()                                   // the handler now returns normally
        try await Task.sleep(nanoseconds: 300_000_000)
        let methods = transport.sentMethods
        XCTAssertTrue(methods.contains("wmp.flow.cancel"), "the cancel went out on the peer: \(methods)")
        XCTAssertFalse(methods.contains("wmp.flow.complete"), "the cancelled child answered nothing: \(methods)")
    }

    /// A request buffered behind a suspended handler across a SAME-object reconnect carries the old socket
    /// generation: it allocates nothing and is not answered, while one stamped with the current generation is served.
    func testARequestBufferedAcrossAReconnectOfTheSameSessionIsDropped() async throws {
        let w = wallet()
        let engine = idleEngine()
        w.engineSession = engine
        engine.connect(appToken: "t1")                                   // socket generation 1
        var buffered = try keyOnlyProofMessage(flowId: "old")
        buffered.socketGeneration = engine.socketGeneration
        engine.forceReconnect(appToken: "t2")                            // generation 2: the buffered one is obsolete
        let sender = RecordingSender()
        try await w.answerGenerateProof(engine: engine, msg: buffered)
        w.lock.lock(); XCTAssertTrue(w.credentialResponseKeys.isEmpty, "no key for the old socket's flow"); w.lock.unlock()
        _ = sender
        var fresh = try keyOnlyProofMessage(flowId: "new")
        fresh.socketGeneration = engine.socketGeneration
        try await w.answerGenerateProof(engine: engine, msg: fresh)
        w.lock.lock(); XCTAssertNotNil(w.credentialResponseKeys["new"]); w.lock.unlock()
        engine.disconnect()
    }

    /// After a local failure (`reportSignFailure`) or `cancelCurrentFlow()` a buffered key-only proof request for that
    /// flow is refused: no key and no reply.
    func testABufferedProofRequestAfterAFailureOrACancelIsRefused() async throws {
        for how in ["failure", "cancel"] {
            let w = wallet()
            let sender = RecordingSender()
            if how == "failure" {
                w.reportSignFailure(flowId: "bf", message: "decrypt failed", notifyError: false)
            } else {
                w.setState(.flowActive(userId: "u", displayName: nil, flowId: "bf", flowType: "oid4vci", status: "active", credentials: []))
                w.cancelCurrentFlow()
            }
            try await w.answerGenerateProof(engine: sender, msg: try keyOnlyProofMessage(flowId: "bf"))
            XCTAssertTrue(sender.sent.isEmpty, "\(how): no reply")
            w.lock.lock(); XCTAssertTrue(w.credentialResponseKeys.isEmpty, "\(how): no key"); w.lock.unlock()
        }
    }

    /// Cancelling while the wallet is still `.ready` (before any progress named a flow): a request the engine session had
    /// already received is obsolete, so it creates no key and gets no reply.
    func testACancelBeforeAnyProgressRefusesTheBufferedProofRequest() async throws {
        let w = wallet()
        let engine = idleEngine()
        w.engineSession = engine
        engine.connect(appToken: "t")                                      // a real (if unreachable) socket to answer on
        var buffered = try keyOnlyProofMessage(flowId: "pending")
        buffered.socketGeneration = engine.socketGeneration
        buffered.requestEpoch = engine.requestEpoch
        w.cancelCurrentFlow()                                              // `.ready`: no flow id yet
        try await w.answerGenerateProof(engine: engine, msg: buffered)
        w.lock.lock(); XCTAssertTrue(w.credentialResponseKeys.isEmpty, "no key for the cancelled attempt"); w.lock.unlock()
        // A request received after the cancel is served.
        var later = try keyOnlyProofMessage(flowId: "next")
        later.socketGeneration = engine.socketGeneration
        later.requestEpoch = engine.requestEpoch
        try await w.answerGenerateProof(engine: engine, msg: later)
        w.lock.lock(); XCTAssertNotNil(w.credentialResponseKeys["next"]); w.lock.unlock()
        engine.disconnect()
    }

    /// The same encrypted response delivered again (the engine retrying a child whose answer was lost or cancelled) is
    /// retained once, so the parent's completion still pairs by count.
    func testTheSameEncryptedResponseIsNotRetainedTwice() async throws {
        let w = wallet()
        let key = try installOwnKey(w, flowId: "dup")
        let jwe = try encrypt(#"{"credentials":[{"credential":"one"}]}"#, to: key)
        for _ in 0..<3 { _ = try await w.decryptCredentialResponse(flowId: "dup", jwe: jwe, deferred: false) }
        XCTAssertEqual(w.takeDecryptedCredentialResponses(flowId: "dup").flatMap(\.credentials), ["one"])
    }

    /// A buffered `generate_proof` for a flow that already ended is rejected: no key, no reply.
    func testABufferedProofRequestForAnEndedFlowIsRejected() async throws {
        let w = wallet()
        w.cancelTransactionTasks(flowId: "gone")                         // the flow's terminal cleanup ran first
        let sender = RecordingSender()
        try await w.answerGenerateProof(engine: sender, msg: try keyOnlyProofMessage(flowId: "gone"))
        XCTAssertTrue(sender.sent.isEmpty)
        w.lock.lock(); XCTAssertTrue(w.credentialResponseKeys.isEmpty); w.lock.unlock()
        XCTAssertThrowsError(try w.requireLiveSession(flowId: "gone")) { XCTAssertEqual($0 as? CredentialResponseError, .flowEnded) }
        // Another flow is unaffected.
        try await w.answerGenerateProof(engine: sender, msg: try keyOnlyProofMessage(flowId: "alive"))
        XCTAssertNotNil(sender.sent.first?.credentialResponseEncryptionJwk)
    }

    /// A request that arrives on a superseded engine session is dropped: no key, no answer.
    func testARequestFromASupersededEngineSessionIsDropped() async throws {
        let w = wallet()
        w.engineSession = idleEngine()
        let stale = RecordingSender()
        try await w.answerGenerateProof(engine: stale, msg: try keyOnlyProofMessage(flowId: "old"))
        XCTAssertTrue(stale.sent.isEmpty, "nothing is answered to the old socket")
        w.lock.lock(); XCTAssertTrue(w.credentialResponseKeys.isEmpty); w.lock.unlock()
        await w.answerDecryptCredentialResponse(engine: stale, msg: try decryptMessage(flowId: "old", jwe: Self.jwe))
        XCTAssertTrue(stale.sent.isEmpty)
    }

    /// Repeated deferred polls do not pile up a metadata tree each: only a response that carries credentials is
    /// kept, and never more than 256 credentials for the flow.
    func testDeferredPollsAreNotRetainedAndTheCredentialCountIsBounded() async throws {
        let w = wallet()
        let notifier = RecordingNotifier()
        w.credentialNotifier = notifier
        let key = try installOwnKey(w, flowId: "rp")
        for _ in 0..<10 {
            let body = #"{"transaction_id":"tx","interval":1,"credential_metadata":{"x":"\#(String(repeating: "m", count: 1000))"}}"#
            _ = try await w.decryptCredentialResponse(flowId: "rp", jwe: try encrypt(body, to: key), deferred: true)
        }
        w.lock.lock(); let held = w.decryptedCredentialResponses["rp"]?.count ?? 0; w.lock.unlock()
        XCTAssertEqual(held, 0, "ten polls retain nothing")
        func batch(_ n: Int, notification: String? = nil) -> String {
            #"{"credentials":["# + (0..<n).map { _ in #"{"credential":"c"}"# }.joined(separator: ",") + "]"
                + (notification.map { #","notification_id":"\#($0)""# } ?? "") + "}"
        }
        _ = try await w.decryptCredentialResponse(flowId: "rp", jwe: try encrypt(batch(200), to: key), deferred: false)
        do {
            _ = try await w.decryptCredentialResponse(flowId: "rp", jwe: try encrypt(batch(100, notification: "n-over"), to: key), deferred: true)
            XCTFail("more than 256 credentials for one flow")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .malformedResponse) }
        XCTAssertEqual(notifier.sent.map(\.event), [CredentialNotificationEvent.failure], "the issuer is told of the rejection")
        XCTAssertEqual(notifier.sent.first?.notificationId, "n-over")
        XCTAssertEqual(w.takeDecryptedCredentialResponses(flowId: "rp").flatMap(\.credentials).count, 200)
    }

    /// A request cancelled while the receiver is suspended is not a rejection even if the receiver then throws an
    /// ordinary error: no `credential_failure` for the parent issuance.
    func testACancelledRequestWhoseReceiverThrowsAnOrdinaryErrorSendsNoFailure() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        struct Boom: Error {}
        let w = wallet()
        let notifier = RecordingNotifier()
        w.credentialNotifier = notifier
        try installKey(w, flowId: "ce")
        let gate = Gate()
        w.credentialMetadataReceiver = { _, _, _ in
            while await !gate.isOpen { await Task.yield() }
            throw Boom()
        }
        let task = Task { try await w.decryptCredentialResponse(flowId: "ce", jwe: Self.jwe, deferred: false) }
        try await Task.sleep(nanoseconds: 80_000_000)
        task.cancel()
        await gate.release()
        do { _ = try await task.value; XCTFail("cancelled") } catch { XCTAssertTrue(error is CancellationError, "\(error)") }
        XCTAssertTrue(notifier.sent.isEmpty)
    }

    /// The WMP session ending (the profile's shutdown) clears what blind issuance holds.
    func testShuttingTheSessionDownClearsBlindIssuanceState() async throws {
        let w = wallet()
        try installKey(w, flowId: "sd")
        _ = try await w.decryptCredentialResponse(flowId: "sd", jwe: Self.jwe, deferred: false)
        try installKey(w, flowId: "sd2")
        w.clearBlindIssuanceState()
        w.lock.lock(); let n = (w.credentialResponseKeys.count, w.decryptedCredentialResponses.count); w.lock.unlock()
        XCTAssertEqual(n.0, 0)
        XCTAssertEqual(n.1, 0)
    }

    /// A completion the wallet cannot read ends the issuance and leaves the wallet ready, not flow-active.
    func testAnUnreadableEncryptedCompletionLeavesTheWalletReady() async throws {
        let w = wallet()
        let listener = Listener()
        w.eventListener = listener
        w.setState(.flowActive(userId: "u", displayName: "U", flowId: "uf", flowType: "oid4vci", status: "x", credentials: []))
        await w.failIssuanceLocally(flowId: "uf", message: "The completion could not be read")
        if case .ready = w.state {} else { XCTFail("\(w.state)") }
        XCTAssertEqual(listener.errors.count, 1)
    }

    func testAnEncryptedCompletionWithNoEntriesIsNotASuccess() {
        let decrypted = DecryptedCredentialResponse(credentials: [], transactionId: "tx")   // only a deferred answer
        XCTAssertNil(SirosWallet.pairEncryptedCredentials(entries: [], decrypted: [decrypted]))
        XCTAssertNil(SirosWallet.pairEncryptedCredentials(entries: [], decrypted: []))
    }

    /// Duplicate member names are refused wherever they hide, including behind escapes and inside the seed member.
    func testDuplicateMembersAreRefusedAtEveryLevelAndBehindEscapes() async throws {
        let bodies = [
            #"{"a":1,"a":2}"#,
            #"{"a":1,"\u0061":2}"#,
            #"{"org.siros.secret_seed":{"ns":"00112233445566778899aabbccddeeff","ns":"00112233445566778899aabbccddeeff"}}"#,
            #"{"org.siros.secret_seed":{"n\u0073":"00112233445566778899aabbccddeeff","ns":"00112233445566778899aabbccddeeff"}}"#,
        ]
        for metadata in bodies {
            let w = wallet()
            let key = try installOwnKey(w, flowId: "d")
            let body = #"{"credentials":[{"credential":"c"}],"credential_metadata":\#(metadata)}"#
            do {
                _ = try await w.decryptCredentialResponse(flowId: "d", jwe: try encrypt(body, to: key), deferred: false)
                XCTFail("\(metadata) must be refused")
            } catch { XCTAssertEqual(error as? CredentialResponseError, .malformedResponse, metadata) }
        }
    }

    func testMetadataAtTheLimitsIsAccepted() async throws {
        let w = wallet()
        let key = try installOwnKey(w, flowId: "ok")
        let members = (0..<256).map { "\"m\($0)\":1" }.joined(separator: ",")
        let name = String(repeating: "n", count: 256)
        let nested = String(repeating: "[", count: 15) + String(repeating: "]", count: 15)   // depth 16 with the member holding it
        let body = #"{"credentials":[{"credential":"c"}],"credential_metadata":{"deep":\#(nested),"\#(name)":1,"many":{\#(members)}}}"#
        let control = try await w.decryptCredentialResponse(flowId: "ok", jwe: try encrypt(body, to: key), deferred: false)
        XCTAssertEqual(control.credentialCount, 1)
    }

    func testARejectedResponseWithoutANotificationIdSendsNothing() async throws {
        let w = wallet()
        let notifier = RecordingNotifier()
        w.credentialNotifier = notifier
        let key = try installOwnKey(w, flowId: "q")
        do {
            _ = try await w.decryptCredentialResponse(flowId: "q", jwe: try encrypt(#"{"credentials":[]}"#, to: key), deferred: false)
            XCTFail("neither credentials nor a transaction_id")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .malformedResponse) }
        XCTAssertTrue(notifier.sent.isEmpty)
    }

    // MARK: - Locking and an unsupported pair

    func testNothingOfBlindIssuanceSurvivesLockingTheWallet() async throws {
        let w = wallet()
        try installKey(w, flowId: "z")
        _ = try await w.decryptCredentialResponse(flowId: "z", jwe: Self.jwe, deferred: false)
        try installKey(w, flowId: "z2")
        w.clearBlindIssuanceState()
        w.lock.lock()
        let left = (w.credentialResponseKeys.count, w.decryptedCredentialResponses.count)
        w.lock.unlock()
        XCTAssertEqual(left.0, 0)
        XCTAssertEqual(left.1, 0)
    }

    /// A required pair this build cannot open still gets an ANSWER (declined), so the engine fails the
    /// issuance at once instead of waiting out its sign timeout.
    func testARequiredButUnsupportedPairIsAnsweredNotLeftHanging() async throws {
        let w = wallet()
        let sender = RecordingSender()
        let json = """
        {"type":"sign_request","flow_id":"u1","message_id":"m","action":"generate_proof","params":{"audience":"a","nonce":"n",
         "credential_response_encryption":{"alg":"ECDH-ES+A512KW","enc":"A256GCM","required":true}}}
        """
        try await w.answerGenerateProof(engine: sender, msg: try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8)))
        XCTAssertEqual(sender.sent.count, 1)
        XCTAssertNil(sender.sent.first?.credentialResponseEncryptionJwk)
        XCTAssertEqual(sender.sent.first?.errorCode, "UNSUPPORTED_RESPONSE_ENCRYPTION", "an error answer, with the original message id")
        XCTAssertNotNil(sender.sent.first?.error)
        XCTAssertNil(sender.sent.first?.proofs)
        XCTAssertEqual(sender.sent.first?.messageId, "m")
        // Over WMP the same is a refusal with that code.
        do {
            _ = try await w.wmpGenerateProof(flowId: "u2", params: SignSubFlowParams(
                action: "generate_proof", credentialResponseEncryption: CredentialResponseEncryptionRequest(alg: "ECDH-ES+A512KW", enc: "A256GCM", required: true)
            ))
            XCTFail("required and unsupported")
        } catch { XCTAssertEqual((error as? WmpErrorCodeProviding)?.wmpErrorCode, "UNSUPPORTED_RESPONSE_ENCRYPTION") }
        // Not required: declined quietly, the issuance goes on in the clear.
        let optional = RecordingSender()
        let optionalJson = json.replacingOccurrences(of: "\"required\":true", with: "\"required\":false")
        try await w.answerGenerateProof(engine: optional, msg: try JSONDecoder().decode(SignRequestMessage.self, from: Data(optionalJson.utf8)))
        XCTAssertNil(optional.sent.first?.errorCode)
        XCTAssertNil(optional.sent.first?.credentialResponseEncryptionJwk)
    }

    // MARK: - generate_proof

    func testEachProofRequestGetsAFreshPublicJwkAndOnlyThePublicHalfLeaves() throws {
        let w = wallet()
        let first = try XCTUnwrap(w.credentialResponseEncryptionJwk(flowId: "f", request: request))
        let second = try XCTUnwrap(w.credentialResponseEncryptionJwk(flowId: "f", request: request))
        XCTAssertNotEqual(first["x"], second["x"], "a c_nonce retry gets a new key")
        XCTAssertEqual(Set(second.keys), ["kty", "crv", "x", "y", "use", "alg"], "no d, no kid")
        XCTAssertEqual(second["kty"], "EC")
        XCTAssertEqual(second["crv"], "P-256")
        XCTAssertEqual(second["use"], "enc")
        XCTAssertEqual(second["alg"], "ECDH-ES+A256KW", "the negotiated alg")
        // Distinct flows hold distinct keys.
        let other = try XCTUnwrap(w.credentialResponseEncryptionJwk(flowId: "g", request: request))
        XCTAssertNotEqual(other["x"], second["x"])
    }

    func testNoRequestOrAPairItCannotOpenIsADeclineAndDropsAnyEarlierKey() async throws {
        let w = wallet()
        _ = w.credentialResponseEncryptionJwk(flowId: "f", request: request)
        XCTAssertNil(w.credentialResponseEncryptionJwk(flowId: "f", request: nil))
        do {
            _ = try await w.decryptCredentialResponse(flowId: "f", jwe: Self.jwe, deferred: false)
            XCTFail("the earlier key must be gone")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .noKey) }
        for unsupported in [
            CredentialResponseEncryptionRequest(alg: "RSA-OAEP", enc: "A256GCM"),
            CredentialResponseEncryptionRequest(alg: "ECDH-ES", enc: "A192GCM"),
        ] {
            XCTAssertNil(w.credentialResponseEncryptionJwk(flowId: "f", request: unsupported))
        }
    }

    func testEveryPairTheContractNamesIsAdvertised() {
        let w = wallet()
        for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"] {
            for enc in ["A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512"] {
                let jwk = w.credentialResponseEncryptionJwk(flowId: "f", request: .init(alg: alg, enc: enc, required: false))
                XCTAssertEqual(jwk?["alg"], alg, "\(alg) \(enc)")
            }
        }
    }

    // MARK: - decrypt_credential_response, engine WebSocket

    func testTheEngineOnlyEverSeesControlFields() async throws {
        let w = wallet()
        try installKey(w, flowId: "f1")
        let sender = RecordingSender()
        await w.handleSignRequest(engine: sender, msg: try decryptMessage(flowId: "f1", jwe: Self.jwe))
        XCTAssertEqual(sender.sent.count, 1)
        let reply = try XCTUnwrap(sender.sent.first)
        XCTAssertEqual(reply.messageId, "m1")
        XCTAssertNil(reply.error)
        XCTAssertEqual(reply.credentialCount, 1, "exactly one of credential_count, transaction_id + interval, error")
        XCTAssertNil(reply.transactionId)
        XCTAssertNil(reply.interval)
        let wire = String(decoding: try JSONEncoder().encode(reply), as: UTF8.self)
        for secret in [Self.credential, Self.seed, "3fwe98js", "credential_metadata", "secret_seed"] {
            XCTAssertFalse(wire.contains(secret), "the sign_response must not carry \(secret)")
        }
        let held = w.takeDecryptedCredentialResponses(flowId: "f1")
        XCTAssertEqual(held.first?.credentials, [Self.credential])
        XCTAssertEqual(held.first?.notificationId, "3fwe98js")
        XCTAssertEqual(held.first?.credentialMetadata?["org.siros.secret_seed"]?[Self.seedNamespace]?.stringValue, Self.seed)
    }

    func testAnUndecryptableResponseAnswersWithAnErrorThatCarriesNothingAndDropsTheFlow() async throws {
        let w = wallet()
        try installKey(w, flowId: "f2")
        let listener = Listener()
        w.eventListener = listener
        let sender = RecordingSender()
        var parts = Self.jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        parts[3] = String(parts[3].dropLast(2)) + "AA"
        await w.handleSignRequest(engine: sender, msg: try decryptMessage(flowId: "f2", jwe: parts.joined(separator: ".")))
        let reply = try XCTUnwrap(sender.sent.first)
        XCTAssertEqual(reply.errorCode, "DECRYPT_FAILED")
        XCTAssertNotNil(reply.error)
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(reply), as: UTF8.self).contains(Self.seed))
        XCTAssertTrue(w.takeDecryptedCredentialResponses(flowId: "f2").isEmpty)
        // The flow's key is gone: a second attempt has nothing to decrypt with.
        let again = RecordingSender()
        await w.handleSignRequest(engine: again, msg: try decryptMessage(flowId: "f2", jwe: Self.jwe))
        XCTAssertEqual(again.sent.first?.errorCode, "NO_RESPONSE_KEY")
    }

    func testAResponseEncryptedToSomeOtherKeyIsRefused() async throws {
        let w = wallet()
        let key = try XCTUnwrap(CredentialResponseKey(params: pair))   // not the key the JWE was made for
        w.lock.lock(); w.credentialResponseKeys["f3"] = key; w.lock.unlock()
        let sender = RecordingSender()
        await w.handleSignRequest(engine: sender, msg: try decryptMessage(flowId: "f3", jwe: Self.jwe))
        XCTAssertEqual(sender.sent.first?.errorCode, "DECRYPT_FAILED")
    }

    // MARK: - decrypt_credential_response, WMP

    func testWmpAnswersTheSameActionWithControlFieldsAndThrowsACodeOnFailure() async throws {
        let w = wallet()
        try installKey(w, flowId: "f4")
        let result = try await w.handleWmpSignRequest(
            flowId: "f4", params: SignSubFlowParams(action: "decrypt_credential_response", jwe: Self.jwe, deferred: false)
        )
        XCTAssertEqual(result.credentialCount, 1)
        XCTAssertNil(result.transactionId)
        XCTAssertNil(result.proofs)
        XCTAssertNil(result.vpToken)
        XCTAssertEqual(w.takeDecryptedCredentialResponses(flowId: "f4").first?.credentials, [Self.credential])

        do {
            _ = try await w.handleWmpSignRequest(
                flowId: "nokey", params: SignSubFlowParams(action: "decrypt_credential_response", jwe: Self.jwe)
            )
            XCTFail("no key, no decryption")
        } catch {
            XCTAssertEqual((error as? WmpErrorCodeProviding)?.wmpErrorCode, "NO_RESPONSE_KEY", "a failure reports one code and no detail")
        }
    }

    // MARK: - Delivered-secret receipt seam

    func testTheMetadataReceiverGetsTheWholeResponseAndRefusingTellsTheIssuer() async throws {
        let w = wallet()
        let notifier = RecordingNotifier()
        w.credentialNotifier = notifier
        try installKey(w, flowId: "f5")
        actor Seen { var value: (DecryptedCredentialResponse, Bool)?; func set(_ v: (DecryptedCredentialResponse, Bool)) { value = v } }
        let seen = Seen()
        w.credentialMetadataReceiver = { _, response, deferred in
            await seen.set((response, deferred))
            throw CredentialResponseError.refused
        }
        do {
            _ = try await w.decryptCredentialResponse(flowId: "f5", jwe: Self.jwe, deferred: true)
            XCTFail("a refused response must not be accepted")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .refused) }
        let facts = await seen.value
        // The credentials are there, so a commitment can be checked against each one of a batch.
        XCTAssertEqual(facts?.0.credentials, [Self.credential])
        XCTAssertEqual(facts?.0.notificationId, "3fwe98js")
        XCTAssertEqual(facts?.0.credentialMetadata?["org.siros.secret_seed"]?[Self.seedNamespace]?.stringValue, Self.seed)
        XCTAssertEqual(facts?.1, true, "the caller said deferred")
        XCTAssertTrue(w.takeDecryptedCredentialResponses(flowId: "f5").isEmpty, "nothing from a refused response is kept")
        // The issuer is told: the engine registered the notification context before relaying the JWE.
        XCTAssertEqual(notifier.sent.count, 1)
        XCTAssertEqual(notifier.sent.first?.notificationId, "3fwe98js")
        XCTAssertEqual(notifier.sent.first?.event, CredentialNotificationEvent.failure)
    }

    /// A pending response carrying the seed is refused on EVERY poll, and one response's metadata is never carried
    /// into the next: each receiver call sees only its own response's metadata.
    func testSeedInAPendingResponseIsRefusedOnEveryPollAndMetadataIsNotCarriedOver() async throws {
        let w = wallet()
        let notifier = RecordingNotifier()
        w.credentialNotifier = notifier
        let key = try installOwnKey(w, flowId: "pp")
        let seeded = #"{"transaction_id":"tx","interval":1,"notification_id":"n-s","credential_metadata":{"org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"}}}"#
        for _ in 0..<2 {
            do { _ = try await w.decryptCredentialResponse(flowId: "pp", jwe: try encrypt(seeded, to: key), deferred: true); XCTFail("refused") }
            catch { XCTAssertEqual(error as? CredentialResponseError, .deferredSeed) }
        }
        XCTAssertEqual(notifier.sent.count, 2, "the issuer is told on every poll")
        actor Seen { var metadata: [JSONValue?] = []; func add(_ m: JSONValue?) { metadata.append(m) } }
        let seen = Seen()
        w.credentialMetadataReceiver = { _, response, _ in await seen.add(response.credentialMetadata) }
        _ = try await w.decryptCredentialResponse(flowId: "pp", jwe: try encrypt(#"{"credentials":[{"credential":"a"}],"credential_metadata":{"k":"v"}}"#, to: key), deferred: false)
        _ = try await w.decryptCredentialResponse(flowId: "pp", jwe: try encrypt(#"{"credentials":[{"credential":"b"}]}"#, to: key), deferred: false)
        let metadata = await seen.metadata
        XCTAssertEqual(metadata.count, 2)
        XCTAssertNotNil(metadata[0])
        XCTAssertNil(metadata[1] as JSONValue?, "the second response has no metadata of its own, and none from the first")
    }

    // MARK: - A plain completion after the wallet offered a key

    /// The wallet offered a response-encryption key, but the completion does not say the response was encrypted: the
    /// engine held the credentials. Refused on both transports, nothing stored, the issuer told per notification id.
    func testAPlainCompletionAfterAnOfferedKeyIsRefused() async throws {
        for transport in ["engine", "wmp"] {
            let w = wallet()
            let notifier = RecordingNotifier()
            w.credentialNotifier = notifier
            let listener = Listener()
            w.eventListener = listener
            try installKey(w, flowId: "pk")
            if transport == "engine" {
                let object: [String: Any] = ["type": "flow_complete", "flow_id": "pk", "credentials": [["format": "dc+sd-jwt", "credential": "a.b.c", "notification_id": "n-1"]]]
                await w.handleFlowComplete(msg: try Self.decodeFlowComplete(object))
            } else {
                await w.handleWmpFlowComplete(flowId: "pk", result: .object_(["credentials": .array([.object_(["format": .string("dc+sd-jwt"), "credential": .string("a.b.c"), "notification_id": .string("n-1")])])]))
            }
            XCTAssertEqual(listener.errors.count, 1, transport)
            XCTAssertTrue(listener.completed.isEmpty, transport)
            XCTAssertEqual(notifier.sent.map(\.notificationId), ["n-1"], transport)
            XCTAssertEqual(notifier.sent.first?.event, CredentialNotificationEvent.failure, transport)
            let stored = await w.credentialStore.getAll()
            XCTAssertTrue(stored.isEmpty, "\(transport): nothing is stored")
        }
    }

    // MARK: - Socket replacement, superseded keys, late completions

    /// Replacing the engine socket from inside the issuance start's epoch-checked commit (the wallet lock is held there)
    /// completes: the cleanup runs on its own task, not inside the callback, and removes only the keys that EARLIER
    /// sockets created: a key the replacement socket's request advertised is left alone.
    func testReplacingTheSocketUnderTheWalletLockDoesNotDeadlockAndKeepsTheNewSocketsKey() async throws {
        let w = wallet()
        let engine = idleEngine()
        w.engineSession = engine
        w.installSocketReplacedHook(on: engine)
        engine.connect(appToken: "t")
        var old = try keyOnlyProofMessage(flowId: "old")
        old.socketGeneration = engine.socketGeneration
        old.requestEpoch = engine.requestEpoch
        try await w.answerGenerateProof(engine: engine, msg: old)
        w.lock.lock(); XCTAssertNotNil(w.credentialResponseKeys["old"]); w.lock.unlock()
        let epoch = w.issuanceStartEpoch.begin()
        w.setState(.flowActive(userId: "u", displayName: nil, flowId: "", flowType: "oid4vci", status: "x", credentials: []))
        let finished = Task { () -> Bool in
            do { try w.replaceEngineSocketForIssuance(epoch: epoch) { engine.forceReconnect(appToken: "t2") }; return true } catch { return true }
        }
        let completed = await withTaskGroup(of: Bool.self) { group -> Bool in
            group.addTask { await finished.value }
            group.addTask { try? await Task.sleep(nanoseconds: 3_000_000_000); return false }
            let first = await group.next() ?? false
            group.cancelAll()
            return first
        }
        XCTAssertTrue(completed, "the socket replacement under the wallet lock did not deadlock")
        // The replacement socket's own request creates a key before the cleanup may have run.
        var fresh = try keyOnlyProofMessage(flowId: "new")
        fresh.socketGeneration = engine.socketGeneration
        fresh.requestEpoch = engine.requestEpoch
        try await w.answerGenerateProof(engine: engine, msg: fresh)
        for _ in 0..<200 {
            w.lock.lock(); let gone = w.credentialResponseKeys["old"] == nil; w.lock.unlock()
            if gone { break }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        w.cleanupAfterSocketReplacement(of: engine)       // a cleanup that runs AFTER the new key exists, whatever the task's timing
        w.lock.lock()
        XCTAssertNil(w.credentialResponseKeys["old"], "the departed socket's key is cleaned up")
        XCTAssertNotNil(w.credentialResponseKeys["new"], "the replacement socket's key is not")
        w.lock.unlock()
        engine.disconnect()
    }

    /// The plaintext-downgrade check survives a lost socket's cleanup: the cleanup removes the response key, but the fact
    /// that a key was OFFERED stays until the flow ends, so a plain `flow_complete` that was already queued is refused
    /// rather than processed as an ordinary plaintext issuance.
    func testAQueuedPlainCompletionIsStillRefusedAfterTheLostSocketsCleanup() async throws {
        let store = InMemoryCredentialStore()
        let w = wallet(store: store)
        let listener = Listener()
        w.eventListener = listener
        let engine = idleEngine()
        w.engineSession = engine
        engine.connect(appToken: "t")
        var offer = try keyOnlyProofMessage(flowId: "dg")
        offer.socketGeneration = engine.socketGeneration
        offer.requestEpoch = engine.requestEpoch
        try await w.answerGenerateProof(engine: engine, msg: offer)                  // the key is offered
        engine.forceReconnect(appToken: "t2")                                        // the socket is replaced ...
        w.cleanupAfterSocketReplacement(of: engine)                                  // ... and its cleanup removes the key
        w.lock.lock(); XCTAssertNil(w.credentialResponseKeys["dg"], "the cleanup removed the key"); w.lock.unlock()
        let now = Int64(Date().timeIntervalSince1970)
        let jwt = "eyJ.\(Data(#"{"exp":\#(now + 3600),"iat":\#(now)}"#.utf8).base64EncodedString().replacingOccurrences(of: "=", with: "")).sig"
        let object: [String: Any] = ["type": "flow_complete", "flow_id": "dg", "credentials": [["format": "vc+sd-jwt", "credential": jwt]]]
        await w.handleFlowComplete(msg: try Self.decodeFlowComplete(object))
        let stored = await store.getAll()
        XCTAssertTrue(stored.isEmpty, "the queued plaintext completion is a downgrade, not an issuance")
        XCTAssertEqual(listener.errors.count, 1)
        XCTAssertTrue(listener.completed.isEmpty)
        engine.disconnect()
    }

    /// A late report from an engine that logout and a new login replaced touches nothing of the new engine's state.
    func testALateSocketReportFromAReplacedEngineLeavesTheNewEnginesKeysAlone() async throws {
        let w = wallet()
        let oldEngine = idleEngine(), newEngine = idleEngine()
        w.engineSession = newEngine
        try installKey(w, flowId: "k")
        w.lock.lock(); w.responseKeyOrigin["k"] = (ObjectIdentifier(newEngine), 0); w.lock.unlock()
        w.cleanupAfterSocketReplacement(of: oldEngine)
        w.lock.lock(); XCTAssertNotNil(w.credentialResponseKeys["k"]); w.lock.unlock()
    }

    /// A decrypt whose receiver was suspended while the socket was replaced does not send its reply on the NEW connection.
    func testALateDecryptReplyIsNotSentOnTheReplacementSocket() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        let w = wallet()
        let sent = SentTexts()
        let engine = idleEngine(recorder: sent)
        w.engineSession = engine
        engine.connect(appToken: "t")
        try installKey(w, flowId: "late")
        let gate = Gate()
        w.credentialMetadataReceiver = { _, _, _ in while await !gate.isOpen { await Task.yield() } }
        var message = try decryptMessage(flowId: "late", jwe: Self.jwe)
        message.socketGeneration = engine.socketGeneration
        message.requestEpoch = engine.requestEpoch
        let decrypting = Task { await w.answerDecryptCredentialResponse(engine: engine, msg: message) }
        try await Task.sleep(nanoseconds: 80_000_000)
        engine.forceReconnect(appToken: "t2")                              // the connection the request came on is gone
        await gate.release()
        await decrypting.value
        XCTAssertEqual(sent.signResponses, 0, "nothing is answered on the replacement connection")
        engine.disconnect()
    }

    /// A key replaced by a newer `generate_proof` while an older decrypt was suspended: the old decrypt's failure is
    /// stale, so it neither deletes the new key nor fails the issuance, on both transports.
    func testASupersededKeyIsAStaleOperationNotATerminalFailure() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        for transport in ["engine", "wmp"] {
            let w = wallet()
            let listener = Listener()
            w.eventListener = listener
            try installKey(w, flowId: "sk")
            let gate = Gate()
            w.credentialMetadataReceiver = { _, _, _ in while await !gate.isOpen { await Task.yield() } }
            let sender = RecordingSender()
            let decrypting = Task { () -> Void in
                if transport == "engine" {
                    await w.answerDecryptCredentialResponse(engine: sender, msg: try! decryptMessage(flowId: "sk", jwe: Self.jwe))
                } else {
                    _ = try? await w.wmpDecryptCredentialResponse(flowId: "sk", params: SignSubFlowParams(action: "decrypt_credential_response", jwe: Self.jwe, deferred: false))
                }
            }
            try await Task.sleep(nanoseconds: 80_000_000)
            let replacement = w.credentialResponseEncryptionJwk(flowId: "sk", request: request)    // a newer generate_proof
            XCTAssertNotNil(replacement)
            await gate.release()
            await decrypting.value
            w.lock.lock(); let kept = w.credentialResponseKeys["sk"] != nil; w.lock.unlock()
            XCTAssertTrue(kept, "\(transport): the newer key survives the older decrypt's failure")
            XCTAssertTrue(listener.errors.isEmpty, "\(transport): the issuance is not failed by it")
        }
    }

    /// Decrypted credentials the engine's completion cannot be paired with (a count mismatch, or a completion that does
    /// not read) are reported to the issuer: one `credential_failure` per distinct decrypted notification id.
    func testAnUnpairableEncryptedCompletionTellsTheIssuer() async throws {
        for variant in ["count mismatch", "unreadable wmp completion"] {
            let w = wallet()
            let notifier = RecordingNotifier()
            w.credentialNotifier = notifier
            try installKey(w, flowId: "up")
            _ = try await w.decryptCredentialResponse(flowId: "up", jwe: Self.jwe, deferred: false)     // notification_id 3fwe98js
            if variant == "count mismatch" {
                await w.handleFlowComplete(msg: try flowComplete(flowId: "up", entries: 2))
            } else {
                await w.handleWmpFlowComplete(flowId: "up", result: .object_([
                    "credential_response_encrypted": .bool(true), "credentials": .array([.object_([:])]),
                ]))
            }
            XCTAssertEqual(notifier.sent.map(\.notificationId), ["3fwe98js"], variant)
            XCTAssertEqual(notifier.sent.first?.event, CredentialNotificationEvent.failure, variant)
        }
    }

    /// A late plain completion does not revive a flow that already failed or was cancelled.
    func testALateCompletionDoesNotReviveAnEndedFlow() async throws {
        let store = InMemoryCredentialStore()
        let w = wallet(store: store)
        let listener = Listener()
        w.eventListener = listener
        try installKey(w, flowId: "end")
        w.reportSignFailure(flowId: "end", message: "decrypt failed", notifyError: false)           // key removed, flow ended
        let now = Int64(Date().timeIntervalSince1970)
        let jwt = "eyJ.\(Data(#"{"exp":\#(now + 3600),"iat":\#(now)}"#.utf8).base64EncodedString().replacingOccurrences(of: "=", with: "")).sig"
        let object: [String: Any] = ["type": "flow_complete", "flow_id": "end", "credentials": [["format": "vc+sd-jwt", "credential": jwt]]]
        await w.handleFlowComplete(msg: try Self.decodeFlowComplete(object))
        await w.handleWmpFlowComplete(flowId: "end", result: .object_(["credentials": .array([.object_(["format": .string("vc+sd-jwt"), "credential": .string(jwt)])])]))
        let stored = await store.getAll()
        XCTAssertTrue(stored.isEmpty, "nothing is stored for an ended flow")
        XCTAssertTrue(listener.completed.isEmpty)
    }

    /// Cancelling an `oid4vp` parent does not reset the guards of an unrelated issuance in progress.
    func testCancellingAPresentationParentLeavesAnIssuancesGuardsAlone() {
        let w = wallet()
        w.lock.lock(); w.issuanceInFlight = true; w.activeAttestedKeyIds = ["kid-1"]; w.lock.unlock()
        w.handleWmpFlowCancel(flowId: "v1", flowType: "oid4vp")
        w.lock.lock(); XCTAssertTrue(w.issuanceInFlight); XCTAssertEqual(w.activeAttestedKeyIds, ["kid-1"]); w.lock.unlock()
        w.handleWmpFlowCancel(flowId: "i1", flowType: "oid4vci")                      // an issuance's own cancel still resets
        w.lock.lock(); XCTAssertFalse(w.issuanceInFlight); XCTAssertNil(w.activeAttestedKeyIds); w.lock.unlock()
    }

    // MARK: - WMP completion carries its issuance epoch

    private func encryptedWmpResult() -> AnyCodable {
        .object_(["credential_response_encrypted": .bool(true), "credentials": .array([.object_(["format": .string("dc+sd-jwt")])])])
    }

    /// The real WMP path end to end, without a hand-set start tag: the epoch captured when the flow's key was
    /// created travels with the completion into the trust gate, so the credential is stored and the listener told.
    func testAnEncryptedWmpCompletionIsStoredAndReportedUnderItsFlowsOriginalEpoch() async throws {
        let store = InMemoryCredentialStore()
        let w = wallet(store: store)
        let listener = Listener()
        w.eventListener = listener
        // The key request as the WMP generate_proof makes it (records the flow's epoch) ...
        _ = w.credentialResponseEncryptionJwk(flowId: "wmp-ok", request: request)
        // ... then the fixture's known key stands in for the random one so the sample JWE opens.
        try installKey(w, flowId: "wmp-ok")
        _ = try await w.decryptCredentialResponse(flowId: "wmp-ok", jwe: Self.jwe, deferred: false)

        await w.handleWmpFlowComplete(flowId: "wmp-ok", result: encryptedWmpResult())

        let stored = await store.getAll()
        XCTAssertEqual(stored.count, 1, "the paired credential reaches the store")
        XCTAssertEqual(listener.completed, ["wmp-ok"])
        XCTAssertTrue(listener.errors.isEmpty)
    }

    /// No recorded epoch means the issuance cannot be established: refused with an error, not dropped silently.
    func testAnEncryptedWmpCompletionWithoutAnEpochIsRefusedNotDropped() async throws {
        let store = InMemoryCredentialStore()
        let w = wallet(store: store)
        let listener = Listener()
        w.eventListener = listener
        try installKey(w, flowId: "wmp-none")          // a key with no recorded epoch
        _ = try await w.decryptCredentialResponse(flowId: "wmp-none", jwe: Self.jwe, deferred: false)

        await w.handleWmpFlowComplete(flowId: "wmp-none", result: encryptedWmpResult())

        let stored = await store.getAll()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertEqual(listener.errors.count, 1, "the failure reaches the listener")
        XCTAssertTrue(listener.completed.isEmpty)
    }

    // MARK: - flow_complete pairing

    func testFlowCompletePairsEntriesWithDecryptedCredentialsAndTakesTheNotificationIdFromTheBody() async throws {
        let store = InMemoryCredentialStore()
        let w = wallet(store: store)
        try installKey(w, flowId: "f6")
        _ = try await w.decryptCredentialResponse(flowId: "f6", jwe: Self.jwe, deferred: false)
        await w.handleFlowComplete(msg: try flowComplete(flowId: "f6", entries: 1))
        let stored = await store.getAll()
        XCTAssertEqual(stored.count, 1)
        XCTAssertEqual(stored.first?.raw, Self.credential)
        XCTAssertEqual(stored.first?.format, "dc+sd-jwt")
        XCTAssertEqual(stored.first?.notificationId, "3fwe98js")
        w.lock.lock(); let leftovers = (w.credentialResponseKeys.count, w.decryptedCredentialResponses.count); w.lock.unlock()
        XCTAssertEqual(leftovers.0, 0, "the key is discarded when the flow ends")
        XCTAssertEqual(leftovers.1, 0)
    }

    /// The engine registers its notification context with an empty id and sees none; an id on the engine's
    /// entry is not the issuer's, so it is never used.
    func testAnIdOnTheEnginesEntryIsNeverUsedInPlaceOfTheDecryptedOne() throws {
        let entry = try JSONDecoder().decode(
            CredentialResult.self, from: Data(#"{"format":"dc+sd-jwt","notification_id":"from-engine"}"#.utf8)
        )
        let withId = DecryptedCredentialResponse(credentials: ["c"], notificationId: "from-body")
        let without = DecryptedCredentialResponse(credentials: ["c"], notificationId: nil)
        XCTAssertEqual(SirosWallet.pairEncryptedCredentials(entries: [entry], decrypted: [withId])?.first?.notificationId, "from-body")
        XCTAssertNil(SirosWallet.pairEncryptedCredentials(entries: [entry], decrypted: [without])?.first?.notificationId)
    }

    func testACountMismatchIsAnErrorAndStoresNothing() async throws {
        let store = InMemoryCredentialStore()
        let w = wallet(store: store)
        let listener = Listener()
        w.eventListener = listener
        w.setState(.flowActive(userId: "u", displayName: "U", flowId: "f7", flowType: "oid4vci", status: "x", credentials: []))
        try installKey(w, flowId: "f7")
        _ = try await w.decryptCredentialResponse(flowId: "f7", jwe: Self.jwe, deferred: false)   // one credential
        await w.handleFlowComplete(msg: try flowComplete(flowId: "f7", entries: 2))
        let stored = await store.getAll()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertEqual(listener.errors.count, 1)
        XCTAssertTrue(listener.completed.isEmpty)
        if case .ready = w.state {} else { XCTFail("a failed issuance leaves the wallet ready, not flow-active: \(w.state)") }
    }

    func testAnEncryptedFlowCompleteWithNothingDecryptedIsAnError() async throws {
        let store = InMemoryCredentialStore()
        let w = wallet(store: store)
        let listener = Listener()
        w.eventListener = listener
        await w.handleFlowComplete(msg: try flowComplete(flowId: "f8", entries: 1))
        let stored = await store.getAll()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertEqual(listener.errors.count, 1)
    }

    func testWmpFlowCompleteIsRoutedOnlyWhenTheResponseWasEncrypted() throws {
        let encrypted: AnyCodable = .object_([
            "credential_response_encrypted": .bool(true),
            "credentials": .array([.object_(["format": .string("dc+sd-jwt")])]),
        ])
        let message = SirosWallet.encryptedFlowComplete(flowId: "wmp-1", result: encrypted)
        XCTAssertEqual(message?.flowId, "wmp-1")
        XCTAssertEqual(message?.credentials?.count, 1)
        XCTAssertNil(message?.credentials?.first?.credential)
        XCTAssertNil(SirosWallet.encryptedFlowComplete(flowId: "wmp-1", result: .object_(["credentials": .array([])])))
        XCTAssertNil(SirosWallet.encryptedFlowComplete(flowId: "wmp-1", result: nil))
    }

    // MARK: - The three answers

    func testExactlyOneOfCountDeferredOrError() async throws {
        let w = wallet()
        try installKey(w, flowId: "x")
        // Deferred: transaction_id and interval, no count.
        let deferred = try await w.decryptCredentialResponse(flowId: "x", jwe: Self.jweDeferred, deferred: false)
        XCTAssertEqual(deferred, CredentialResponseControl(credentialCount: nil, transactionId: "tx-1", interval: 5))
        // A batch: the number of credentials, nothing else.
        let batch = try await w.decryptCredentialResponse(flowId: "x", jwe: Self.jweBatch, deferred: true)
        XCTAssertEqual(batch, CredentialResponseControl(credentialCount: 2, transactionId: nil, interval: nil))
        XCTAssertEqual(w.takeDecryptedCredentialResponses(flowId: "x").flatMap(\.credentials), ["c1", "c2"])
        // Credentials AND a transaction_id is both: refused, never answered with either.
        try installKey(w, flowId: "y")
        do {
            _ = try await w.decryptCredentialResponse(flowId: "y", jwe: Self.jweBoth, deferred: false)
            XCTFail("both is not an answer")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .malformedResponse) }
    }

    // MARK: - Key-only requests and flows that end meanwhile

    func testARequestWithoutProofTypesIsForTheKeyAlone() {
        XCTAssertTrue(SirosWallet.isKeyOnlyProofRequest(request: request, proofTypesSupported: nil))
        XCTAssertTrue(SirosWallet.isKeyOnlyProofRequest(request: request, proofTypesSupported: [:]))
        XCTAssertFalse(SirosWallet.isKeyOnlyProofRequest(request: request, proofTypesSupported: ["jwt": .object_([:])]))
        // A named proof_type still wants a proof (over either transport).
        XCTAssertFalse(SirosWallet.isKeyOnlyProofRequest(request: request, proofTypesSupported: nil, proofType: "jwt"))
        XCTAssertFalse(SirosWallet.isKeyOnlyProofRequest(request: request, proofTypesSupported: [:], proofType: "attestation"))
        // Without response encryption it is an ordinary proof request, whatever it lists.
        XCTAssertFalse(SirosWallet.isKeyOnlyProofRequest(request: nil, proofTypesSupported: nil))
    }

    func testAKeyOnlyRequestAnswersWithTheJwkAndNoProofsOverBothTransports() async throws {
        let w = wallet()
        let sender = RecordingSender()
        let json = """
        {"type":"sign_request","flow_id":"k1","message_id":"m","action":"generate_proof","params":{"audience":"a","nonce":"n",
         "credential_response_encryption":{"alg":"ECDH-ES+A256KW","enc":"A256GCM","required":true}}}
        """
        try await w.answerGenerateProof(engine: sender, msg: try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8)))
        let reply = try XCTUnwrap(sender.sent.first)
        XCTAssertNil(reply.proofs)
        XCTAssertEqual(reply.credentialResponseEncryptionJwk?["alg"], "ECDH-ES+A256KW")

        // Over WMP too, whether `proof_types_supported` is empty or omitted.
        for supported in [[:], nil] as [[String: AnyCodable]?] {
            let wmp = try await w.wmpGenerateProof(flowId: "k2", params: SignSubFlowParams(
                action: "generate_proof", credentialResponseEncryption: request, proofTypesSupported: supported
            ))
            XCTAssertNil(wmp.proofs)
            XCTAssertEqual(wmp.credentialResponseEncryptionJwk?["use"], "enc")
        }
    }

    /// A late generate_proof result must not recreate a key for a flow that ended, or one cancelled, while
    /// proofs were being generated.
    func testAKeyIsNotCreatedForAFlowThatEndedMeanwhile() {
        let w = wallet()
        let before = w.credentialResponseGeneration(flowId: "late")
        w.cancelTransactionTasks(flowId: "late")                       // the flow ends
        XCTAssertNil(w.credentialResponseEncryptionJwk(flowId: "late", request: request, generation: before))
        let beforeCancel = w.credentialResponseGeneration(flowId: "other")
        w.cancelCurrentFlow()                                          // or the issuance is cancelled
        XCTAssertNil(w.credentialResponseEncryptionJwk(flowId: "other", request: request, generation: beforeCancel))
        let fresh = w.credentialResponseGeneration(flowId: "other")
        XCTAssertNotNil(w.credentialResponseEncryptionJwk(flowId: "other", request: request, generation: fresh))
    }

    // MARK: - decrypt_credential_response answers

    func testEncryptedKeyOfTheWrongLengthIsRefusedBeforeUnwrapping() throws {
        let d = try XCTUnwrap(CredentialResponseJwe.decode(Self.recipientD))
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: d)
        var parts = Self.jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        parts[1] = CredentialResponseJwe.encode(Data(repeating: 7, count: 64 * 1024))
        XCTAssertThrowsError(try CredentialResponseJwe.decrypt(parts.joined(separator: "."), recipient: key)) { error in
            guard case CredentialResponseJweError.malformed = error else { return XCTFail("\(error)") }
        }
    }

    /// Flow errors after a decryption drop the plaintext too, not only the key.
    func testAFlowErrorDropsWhatWasDecrypted() async throws {
        let w = wallet()
        try installKey(w, flowId: "e1")
        _ = try await w.decryptCredentialResponse(flowId: "e1", jwe: Self.jwe, deferred: false)
        w.handleFlowError(msg: try JSONDecoder().decode(
            FlowErrorMessage.self, from: Data(#"{"type":"flow_error","flow_id":"e1","error":{"code":"x","message":"y"}}"#.utf8)
        ))
        XCTAssertTrue(w.takeDecryptedCredentialResponses(flowId: "e1").isEmpty)
    }

    /// A cancel while the metadata receiver is suspended makes the response stale: nothing is kept and no
    /// success (count or transaction id) is reported.
    func testACancelWhileTheReceiverIsSuspendedYieldsNoSuccess() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        let w = wallet()
        try installKey(w, flowId: "s1")
        let gate = Gate()
        w.credentialMetadataReceiver = { _, _, _ in
            while await !gate.isOpen { try await Task.sleep(nanoseconds: 10_000_000) }
        }
        let pending = Task { try await w.decryptCredentialResponse(flowId: "s1", jwe: Self.jwe, deferred: false) }
        try await Task.sleep(nanoseconds: 100_000_000)
        w.cancelCurrentFlow()
        await gate.release()
        do {
            _ = try await pending.value
            XCTFail("a stale response must not be reported as taken")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .noKey) }
        XCTAssertTrue(w.takeDecryptedCredentialResponses(flowId: "s1").isEmpty)
    }

    // MARK: - Lifecycle

    /// A presentation ending (it also calls `resetIssuanceGuards`) must not take an issuance's key.
    func testAnotherFlowEndingDoesNotDropAnIssuancesKey() async throws {
        let w = wallet()
        try installKey(w, flowId: "issuance")
        w.resetIssuanceGuards()
        w.cancelTransactionTasks(flowId: "a-presentation")
        w.reportSignFailure(flowId: "another", message: "x")
        let held = (try? await w.decryptCredentialResponse(flowId: "issuance", jwe: Self.jwe, deferred: false)) != nil
        XCTAssertTrue(held)
    }

    func testWmpCancelDropsTheFlowsStateAndAnEncryptedCompletionThatDoesNotReadIsAnError() async throws {
        let w = wallet()
        let listener = Listener()
        w.eventListener = listener
        _ = w.credentialResponseEncryptionJwk(flowId: "c1", request: request)
        // The profile reaches the wallet through the same callback `connectViaWmp` installs.
        let profile = OpenID4xProfile(config: OpenID4xConfig(onCancel: { [weak w] flowId, flowType in
            w?.handleWmpFlowCancel(flowId: flowId, flowType: flowType)
        }))
        await profile.handleCancel(params: FlowCancelParams(flowId: "c1"))
        w.lock.lock(); let has = w.credentialResponseKeys["c1"] != nil; w.lock.unlock()
        XCTAssertFalse(has)

        XCTAssertTrue(SirosWallet.claimsEncryptedResponse(.object_(["credential_response_encrypted": .bool(true)])))
        XCTAssertNil(SirosWallet.encryptedFlowComplete(flowId: "c2", result: .object_([
            "credential_response_encrypted": .bool(true), "credentials": .array([.object_([:])]),
        ])), "an entry without a format does not decode")
        XCTAssertFalse(SirosWallet.claimsEncryptedResponse(nil))
    }

    // MARK: - Lifecycle

    func testEveryTerminalPathOfTheFlowDropsItsKey() async throws {
        let w = wallet()
        func has(_ flow: String) -> Bool { w.lock.lock(); defer { w.lock.unlock() }; return w.credentialResponseKeys[flow] != nil }
        _ = w.credentialResponseEncryptionJwk(flowId: "a", request: request)
        w.cancelTransactionTasks(flowId: "a")                       // flow_complete / flow_error / WMP complete
        XCTAssertFalse(has("a"))
        _ = w.credentialResponseEncryptionJwk(flowId: "b", request: request)
        w.cancelCurrentFlow()                                       // the user cancels the issuance
        XCTAssertFalse(has("b"))
        _ = w.credentialResponseEncryptionJwk(flowId: "c", request: request)
        w.handleFlowError(msg: try JSONDecoder().decode(
            FlowErrorMessage.self,
            from: Data(#"{"type":"flow_error","flow_id":"c","error":{"code":"x","message":"y"}}"#.utf8)
        ))
        XCTAssertFalse(has("c"))
    }
}
