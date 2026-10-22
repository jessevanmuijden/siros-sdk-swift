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
        await w.handleSignRequest(engine: sender, msg: try signRequest(encrypted: false, responseMode: "direct_post"))
        XCTAssertEqual(sender.sent.first?.vpToken, "vp-token")
        XCTAssertNil(sender.sent.first?.responseJwe)
    }

    /// A verified `direct_post.jwt` request that arrives without `response_encryption` is refused on both transports:
    /// neither a `vp_token` nor a `response_jwe` goes to the engine.
    func testADirectPostJwtRequestWithoutEncryptionParametersIsRefused() async throws {
        let w = wallet()
        let sender = RecordingSender()
        await w.handleSignRequest(engine: sender, msg: try signRequest(encrypted: false))
        XCTAssertEqual(sender.sent.count, 1)
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertNil(sender.sent.first?.responseJwe)
        XCTAssertEqual(sender.sent.first?.errorCode, "RESPONSE_ENCRYPTION_FAILED")
        do {
            _ = try await w.handleWmpSignRequest(flowId: "p9", params: SignSubFlowParams(
                action: "sign_presentation", nonce: "n", audience: "x509_san_dns:verifier.example",
                verifiedRequest: VerifiedRequest(clientId: "client-9", responseMode: "direct_post.jwt")
            ))
            XCTFail("a plain vp_token for a direct_post.jwt request")
        } catch { XCTAssertEqual((error as? WmpErrorCodeProviding)?.wmpErrorCode, "RESPONSE_ENCRYPTION_FAILED") }
    }

    /// The mdoc handover binds the thumbprint of the key the response is ENCRYPTED to, never the engine's
    /// `verifier_jwk_thumbprint`, on both transports; without encryption the engine's value is untouched.
    func testTheHandoverThumbprintIsThatOfTheResponseEncryptionKey() throws {
        let jwk = ["kty": "EC", "crv": "P-256", "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"]
        let expected = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
        let subflow = SignSubFlowParams(
            action: "sign_presentation", nonce: "n", audience: "a",
            responseEncryption: ResponseEncryptionRequest(jwk: jwk.mapValues { .string($0) }, alg: "ECDH-ES", enc: "A128GCM"),
            verifierJwkThumbprint: "ENGINE-VALUE"
        )
        XCTAssertEqual(SignPresentationContext(subflow).verifierJwkThumbprint, expected)
        let ws = try JSONDecoder().decode(SignRequestParams.self, from: Data(#"""
        {"audience":"a","nonce":"n","verifier_jwk_thumbprint":"ENGINE-VALUE",
         "response_encryption":{"jwk":{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"},"alg":"ECDH-ES","enc":"A128GCM"}}
        """#.utf8))
        XCTAssertEqual(SignPresentationContext(ws).verifierJwkThumbprint, expected)
        let plain = SignSubFlowParams(action: "sign_presentation", nonce: "n", audience: "a", verifierJwkThumbprint: "ENGINE-VALUE")
        XCTAssertEqual(SignPresentationContext(plain).verifierJwkThumbprint, "ENGINE-VALUE")
        // An encryption key with no thumbprint never falls back to the engine's.
        let broken = SignSubFlowParams(
            action: "sign_presentation", nonce: "n", audience: "a",
            responseEncryption: ResponseEncryptionRequest(jwk: ["kty": .string("EC")], alg: "ECDH-ES", enc: "A128GCM"),
            verifierJwkThumbprint: "ENGINE-VALUE"
        )
        XCTAssertNil(SignPresentationContext(broken).verifierJwkThumbprint)
    }

    /// The top-level `response_mode` counts too: `direct_post.jwt` there, with neither `verified_request` nor
    /// `response_encryption`, is refused on both transports instead of answered with a plaintext vp_token.
    func testATopLevelDirectPostJwtModeWithoutEncryptionIsRefused() async throws {
        let w = wallet()
        let sender = RecordingSender()
        let json = #"{"type":"sign_request","flow_id":"p1","message_id":"m1","action":"sign_presentation","params":{"audience":"a","nonce":"n","response_mode":"direct_post.jwt"}}"#
        await w.handleSignRequest(engine: sender, msg: try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8)))
        XCTAssertEqual(sender.sent.count, 1)
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(sender.sent.first?.errorCode, "RESPONSE_ENCRYPTION_FAILED")
        do {
            _ = try await w.handleWmpSignRequest(flowId: "p2", params: SignSubFlowParams(
                action: "sign_presentation", nonce: "n", audience: "a", responseMode: "direct_post.jwt"
            ))
            XCTFail("a plaintext vp_token for a direct_post.jwt request")
        } catch { XCTAssertEqual((error as? WmpErrorCodeProviding)?.wmpErrorCode, "RESPONSE_ENCRYPTION_FAILED") }
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
        // And the engine is told, with the original message id, instead of waiting out its sign timeout.
        XCTAssertEqual(sender.sent.count, 1)
        XCTAssertEqual(sender.sent.first?.errorCode, "RESPONSE_ENCRYPTION_FAILED")
        XCTAssertEqual(sender.sent.first?.messageId, "m1")
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

    /// A malformed JWK member is a bad key, not something to drop: a private `d` of ANY type, or `use` that is
    /// not a string, must not be filtered away before the key checks.
    func testMalformedJwkMembersAreRefusedNotDropped() throws {
        let w = wallet()
        let good = verifierJwk.mapValues { AnyCodable.string($0 as? String ?? "") }
        func attempt(_ extra: [String: AnyCodable]) throws {
            _ = try w.encryptedPresentationResponse(
                parts: [(nil, "t")],
                encryption: ResponseEncryptionRequest(jwk: good.merging(extra) { _, new in new }, alg: "ECDH-ES", enc: "A128GCM"),
                state: nil, verifiedRequest: VerifiedRequest(clientId: "c", responseMode: "direct_post.jwt")
            )
        }
        XCTAssertNoThrow(try attempt([:]))
        XCTAssertNoThrow(try attempt(["key_ops": .array([.string("deriveKey")])]), "unrelated members are not judged")
        XCTAssertThrowsError(try attempt(["d": .int(1)]), "a private key of any type")
        XCTAssertThrowsError(try attempt(["d": .string("AAAA")]))
        XCTAssertThrowsError(try attempt(["use": .array([.string("enc")])]), "use must be a string")
        XCTAssertThrowsError(try attempt(["crv": .int(256)]))
        XCTAssertThrowsError(try attempt(["kid": .object_([:])]))
    }

    func testOnlyAVerifiedDirectPostJwtRequestIsEncrypted() async throws {
        let w = wallet()
        for mode in ["direct_post", "fragment", "query"] {
            let sender = RecordingSender()
            await w.handleSignRequest(engine: sender, msg: try signRequest(responseMode: mode))
            XCTAssertTrue(sender.sent.allSatisfy { $0.responseJwe == nil && $0.vpToken == nil }, mode)
        }
    }

    /// A selected credential that vanished from the store is a refusal, not a shorter presentation.
    func testASelectedCredentialThatIsGoneIsARefusalNotAPartialPresentation() async throws {
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(id: 1, format: "dc+sd-jwt", raw: "cred-1", kid: nil, batchId: 1, instanceId: 0))
        let w = wallet(store: store)
        let sender = RecordingSender()
        let refs: [[String: Any]] = [
            ["credential_id": "1", "credential_query_id": "pid"], ["credential_id": "2", "credential_query_id": "mdl"],
        ]
        await w.handleSignRequest(engine: sender, msg: try signRequest(credentials: refs))
        XCTAssertTrue(sender.sent.allSatisfy { $0.responseJwe == nil && $0.vpToken == nil }, "no partial presentation")
        XCTAssertEqual(sender.sent.first?.errorCode, "SIGN_ERROR")
        XCTAssertEqual(sender.sent.first?.messageId, "m1")
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
