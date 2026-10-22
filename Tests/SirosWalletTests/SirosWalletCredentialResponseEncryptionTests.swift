// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
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
        w.lock.lock(); w.credentialResponseKeys[flowId] = key; w.lock.unlock()
    }

    private func decryptMessage(flowId: String, jwe: String, deferred: Bool = false) throws -> SignRequestMessage {
        let json = """
        {"type":"sign_request","flow_id":"\(flowId)","message_id":"m1","action":"decrypt_credential_response",
         "params":{"jwe":"\(jwe)","deferred":\(deferred)}}
        """
        return try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
    }

    private func flowComplete(flowId: String, entries: Int, encrypted: Bool = true) throws -> FlowCompleteMessage {
        let credentials = (0..<entries).map { _ in ["format": "dc+sd-jwt", "vct": "urn:eudi:pid:1"] }
        let object: [String: Any] = [
            "type": "flow_complete", "flow_id": flowId, "credentials": credentials, "credential_response_encrypted": encrypted,
        ]
        return try JSONDecoder().decode(FlowCompleteMessage.self, from: try JSONSerialization.data(withJSONObject: object))
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
        w.lock.lock(); w.credentialResponseKeys[flowId] = key; w.lock.unlock()
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

    /// Repeated deferred polls do not pile up a metadata tree each: only a response that carries credentials is
    /// kept, and never more than 256 credentials for the flow.
    func testDeferredPollsAreNotRetainedAndTheCredentialCountIsBounded() async throws {
        let w = wallet()
        let key = try installOwnKey(w, flowId: "rp")
        for _ in 0..<10 {
            let body = #"{"transaction_id":"tx","interval":1,"credential_metadata":{"x":"\#(String(repeating: "m", count: 1000))"}}"#
            _ = try await w.decryptCredentialResponse(flowId: "rp", jwe: try encrypt(body, to: key), deferred: true)
        }
        w.lock.lock(); let held = w.decryptedCredentialResponses["rp"]?.count ?? 0; w.lock.unlock()
        XCTAssertEqual(held, 0, "ten polls retain nothing")
        func batch(_ n: Int) -> String {
            #"{"credentials":["# + (0..<n).map { _ in #"{"credential":"c"}"# }.joined(separator: ",") + "]}"
        }
        _ = try await w.decryptCredentialResponse(flowId: "rp", jwe: try encrypt(batch(200), to: key), deferred: false)
        do {
            _ = try await w.decryptCredentialResponse(flowId: "rp", jwe: try encrypt(batch(100), to: key), deferred: true)
            XCTFail("more than 256 credentials for one flow")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .malformedResponse) }
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
         "credential_response_encryption":{"alg":"ECDH-ES+A192KW","enc":"A256GCM","required":true}}}
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
                action: "generate_proof", credentialResponseEncryption: CredentialResponseEncryptionRequest(alg: "ECDH-ES+A192KW", enc: "A256GCM", required: true)
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
        for alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"] {
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
        let profile = OpenID4xProfile(config: OpenID4xConfig(onCancel: { [weak w] flowId in
            w?.cancelTransactionTasks(flowId: flowId)
            w?.discardCredentialResponseState(flowId: flowId)
            w?.resetIssuanceGuards()
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
