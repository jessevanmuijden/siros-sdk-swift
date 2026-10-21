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
        XCTAssertNil(reply.transactionId)
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

    func testTheMetadataReceiverSeesTheFactsAndCanRefuseTheWholeResponse() async throws {
        let w = wallet()
        try installKey(w, flowId: "f5")
        actor Seen { var value: (JSONValue?, Bool, Bool, Bool)?; func set(_ v: (JSONValue?, Bool, Bool, Bool)) { value = v } }
        let seen = Seen()
        w.credentialMetadataReceiver = { _, metadata, encrypted, deferred, hasNotification in
            await seen.set((metadata, encrypted, deferred, hasNotification))
            throw CredentialResponseError.refused
        }
        do {
            _ = try await w.decryptCredentialResponse(flowId: "f5", jwe: Self.jwe, deferred: true)
            XCTFail("a refused response must not be accepted")
        } catch { XCTAssertEqual(error as? CredentialResponseError, .refused) }
        let facts = await seen.value
        XCTAssertEqual(facts?.0?["org.siros.secret_seed"]?[Self.seedNamespace]?.stringValue, Self.seed)
        XCTAssertEqual(facts?.1, true, "it was encrypted")
        XCTAssertEqual(facts?.2, true, "the caller said deferred")
        XCTAssertEqual(facts?.3, true, "the body has a notification_id")
        XCTAssertTrue(w.takeDecryptedCredentialResponses(flowId: "f5").isEmpty, "nothing from a refused response is kept")
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

    func testACountMismatchIsAnErrorAndStoresNothing() async throws {
        let store = InMemoryCredentialStore()
        let w = wallet(store: store)
        let listener = Listener()
        w.eventListener = listener
        try installKey(w, flowId: "f7")
        _ = try await w.decryptCredentialResponse(flowId: "f7", jwe: Self.jwe, deferred: false)   // one credential
        await w.handleFlowComplete(msg: try flowComplete(flowId: "f7", entries: 2))
        let stored = await store.getAll()
        XCTAssertTrue(stored.isEmpty)
        XCTAssertEqual(listener.errors.count, 1)
        XCTAssertTrue(listener.completed.isEmpty)
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

    // MARK: - Lifecycle

    func testEveryTerminalPathDropsTheKey() async throws {
        let w = wallet()
        func has(_ flow: String) -> Bool { w.lock.lock(); defer { w.lock.unlock() }; return w.credentialResponseKeys[flow] != nil }
        _ = w.credentialResponseEncryptionJwk(flowId: "a", request: request)
        w.cancelTransactionTasks(flowId: "a")                       // flow_complete / flow_error / WMP complete
        XCTAssertFalse(has("a"))
        _ = w.credentialResponseEncryptionJwk(flowId: "b", request: request)
        w.resetIssuanceGuards()                                     // cancel, failure, completion
        XCTAssertFalse(has("b"))
        _ = w.credentialResponseEncryptionJwk(flowId: "c", request: request)
        w.handleFlowError(msg: try JSONDecoder().decode(
            FlowErrorMessage.self,
            from: Data(#"{"type":"flow_error","flow_id":"c","error":{"code":"x","message":"y"}}"#.utf8)
        ))
        XCTAssertFalse(has("c"))
    }
}
