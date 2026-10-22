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
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "vp-token" }
    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String {
        "vp:\(credential)"
    }
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
    func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] { [] }
    func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) { errors.append(errorMessage) }
}

/// Engine-blind presentation: for `direct_post.jwt` the wallet answers `sign_presentation` with
/// `response_jwe` (a JWE it built around the vp_token) and no `vp_token`.
final class SirosWalletPresentationResponseEncryptionTests: XCTestCase {

    private let verifier = P256.KeyAgreement.PrivateKey()

    private func wallet(store: InMemoryCredentialStore = InMemoryCredentialStore()) -> SirosWallet {
        let w = SirosWallet(
            config: WalletConfig(backendUrl: "https://example.invalid", credentialStore: store),
            authProvider: StubAuthProvider(), keystore: StubKeystoreManager(), accountRegistry: .inMemory()
        )
        XCTAssertNotNil(w)
        return w!
    }

    private var verifierJwk: [String: Any] {
        let p = verifier.publicKey.x963Representation
        return [
            "kty": "EC", "crv": "P-256", "kid": "verifier-key-1", "use": "enc",
            "x": CredentialResponseJwe.encode(p.subdata(in: 1..<33)), "y": CredentialResponseJwe.encode(p.subdata(in: 33..<65)),
        ]
    }

    private func signRequest(
        encrypted: Bool = true, clientId: String? = "x509_san_dns:verifier.example", state: String? = "st-1",
        responseMode: String = "direct_post.jwt",
        credentials: [[String: Any]]? = nil
    ) throws -> SignRequestMessage {
        var params: [String: Any] = ["audience": "x509_san_dns:verifier.example", "nonce": "n-1"]
        if encrypted { params["response_encryption"] = ["jwk": verifierJwk, "alg": "ECDH-ES", "enc": "A128GCM"] as [String: Any] }
        if let state { params["state"] = state }
        if let clientId { params["verified_request"] = [
            "client_id": clientId, "response_mode": responseMode, "response_uri": "https://verifier.example/cb",
        ] }
        if let credentials { params["credentials_to_include"] = credentials }
        let object: [String: Any] = ["type": "sign_request", "flow_id": "p1", "message_id": "m1", "action": "sign_presentation", "params": params]
        return try JSONDecoder().decode(SignRequestMessage.self, from: try JSONSerialization.data(withJSONObject: object))
    }

    private func claims(_ jwe: String) throws -> [String: Any] {
        let plaintext = try CredentialResponseJwe.decrypt(
            jwe, recipient: verifier, expected: CredentialResponseEncryptionParams(alg: "ECDH-ES", enc: "A128GCM")
        )
        return try XCTUnwrap(JSONSerialization.jsonObject(with: plaintext) as? [String: Any])
    }

    // MARK: - Engine WebSocket

    func testTheAnswerIsAResponseJweAndNoVpToken() async throws {
        let w = wallet()
        let sender = RecordingSender()
        await w.handleSignRequest(engine: sender, msg: try signRequest())
        let reply = try XCTUnwrap(sender.sent.first)
        XCTAssertNil(reply.vpToken, "the engine must never see the vp_token")
        XCTAssertNil(reply.error)
        let jwe = try XCTUnwrap(reply.responseJwe)
        let c = try claims(jwe)
        XCTAssertEqual(c["aud"] as? String, "x509_san_dns:verifier.example", "aud is verified_request.client_id")
        XCTAssertEqual(c["state"] as? String, "st-1")
        XCTAssertEqual(c["vp_token"] as? String, "vp-token")
        let wire = String(decoding: try JSONEncoder().encode(reply), as: UTF8.self)
        XCTAssertFalse(wire.contains("vp-token"))
        XCTAssertTrue(wire.contains("response_jwe"))
    }

    func testWithoutResponseEncryptionTheVpTokenIsReturnedAsBefore() async throws {
        let w = wallet()
        let sender = RecordingSender()
        await w.handleSignRequest(engine: sender, msg: try signRequest(encrypted: false))
        XCTAssertEqual(sender.sent.first?.vpToken, "vp-token")
        XCTAssertNil(sender.sent.first?.responseJwe)
    }

    func testWithoutAValidatedClientIdNothingIsAnsweredAndTheFlowFails() async throws {
        let w = wallet()
        let listener = Listener()
        w.eventListener = listener
        let sender = RecordingSender()
        await w.handleSignRequest(engine: sender, msg: try signRequest(clientId: nil))
        XCTAssertTrue(
            sender.sent.allSatisfy { $0.responseJwe == nil && $0.vpToken == nil },
            "neither a response_jwe nor a vp_token for the engine to post in clear"
        )
        XCTAssertEqual(listener.errors.count, 1)
    }

    /// `response_encryption: null` on the WebSocket is an error, never a plain vp_token for the engine to post.
    func testANullOrMalformedResponseEncryptionOnTheWebSocketIsNeverAnsweredInTheClear() async throws {
        for member in ["null", #"{"alg":"ECDH-ES"}"#, "7"] {
            let json = """
            {"type":"sign_request","flow_id":"n1","message_id":"m","action":"sign_presentation",
             "params":{"audience":"a","nonce":"n","response_encryption":\(member),
                       "verified_request":{"client_id":"c","response_mode":"direct_post.jwt"}}}
            """
            let msg = try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
            let w = wallet()
            let sender = RecordingSender()
            await w.handleSignRequest(engine: sender, msg: msg)
            XCTAssertTrue(sender.sent.allSatisfy { $0.vpToken == nil && $0.responseJwe == nil }, member)
        }
    }

    func testOnlyAVerifiedDirectPostJwtRequestIsEncrypted() async throws {
        let w = wallet()
        for mode in ["direct_post", "fragment", "query"] {
            let sender = RecordingSender()
            await w.handleSignRequest(engine: sender, msg: try signRequest(responseMode: mode))
            XCTAssertTrue(sender.sent.allSatisfy { $0.responseJwe == nil && $0.vpToken == nil }, mode)
        }
    }

    func testDcqlTokensAreBuiltByTheWalletPerQuery() async throws {
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(id: 1, format: "dc+sd-jwt", raw: "cred-1", kid: nil, batchId: 1, instanceId: 0))
        await store.save(StoredCredential(id: 2, format: "dc+sd-jwt", raw: "cred-2", kid: nil, batchId: 2, instanceId: 0))
        let w = wallet(store: store)
        let sender = RecordingSender()
        let refs: [[String: Any]] = [
            ["credential_id": "1", "credential_query_id": "pid"], ["credential_id": "2", "credential_query_id": "mdl"],
        ]
        await w.handleSignRequest(engine: sender, msg: try signRequest(credentials: refs))
        let jwe = try XCTUnwrap(sender.sent.first?.responseJwe)
        let token = try XCTUnwrap(try claims(jwe)["vp_token"] as? [String: [String]])
        XCTAssertEqual(token, ["pid": ["vp:cred-1"], "mdl": ["vp:cred-2"]])
    }

    // MARK: - WMP

    func testWmpAnswersTheSameWay() async throws {
        let w = wallet()
        let encrypted = try await w.handleWmpSignRequest(flowId: "p2", params: SignSubFlowParams(
            action: "sign_presentation", nonce: "n", audience: "x509_san_dns:verifier.example",
            responseEncryption: ResponseEncryptionRequest(
                jwk: verifierJwk.mapValues { .string($0 as? String ?? "") }, alg: "ECDH-ES", enc: "A128GCM"
            ),
            state: "st-2", verifiedRequest: VerifiedRequest(clientId: "client-2", responseMode: "direct_post.jwt")
        ))
        XCTAssertNil(encrypted.vpToken)
        let c = try claims(try XCTUnwrap(encrypted.responseJwe))
        XCTAssertEqual(c["aud"] as? String, "client-2")
        XCTAssertEqual(c["state"] as? String, "st-2")

        let plain = try await w.handleWmpSignRequest(flowId: "p3", params: SignSubFlowParams(
            action: "sign_presentation", nonce: "n", audience: "x509_san_dns:verifier.example"
        ))
        XCTAssertEqual(plain.vpToken, "vp-token")
        XCTAssertNil(plain.responseJwe)

        // The WMP path has no selection step: an encrypted response for a request that names credentials is
        // refused, not built around a credential-less token.
        do {
            _ = try await w.handleWmpSignRequest(flowId: "p5", params: SignSubFlowParams(
                action: "sign_presentation", nonce: "n", audience: "x509_san_dns:verifier.example",
                credentialsToInclude: [try JSONDecoder().decode(CredentialRef.self, from: Data(#"{"credential_id":"1","credential_query_id":"pid"}"#.utf8))],
                responseEncryption: ResponseEncryptionRequest(
                    jwk: verifierJwk.mapValues { .string($0 as? String ?? "") }, alg: "ECDH-ES", enc: "A128GCM"
                ),
                verifiedRequest: VerifiedRequest(clientId: "client-5", responseMode: "direct_post.jwt")
            ))
            XCTFail("no selection step, no presentation")
        } catch { /* expected */ }

        do {
            _ = try await w.handleWmpSignRequest(flowId: "p4", params: SignSubFlowParams(
                action: "sign_presentation", nonce: "n", audience: "x509_san_dns:verifier.example",
                responseEncryption: ResponseEncryptionRequest(jwk: [:], alg: "ECDH-ES", enc: "A128GCM")
            ))
            XCTFail("an unusable key is not answered")
        } catch { /* expected */ }
    }
}
