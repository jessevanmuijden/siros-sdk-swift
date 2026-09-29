// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
@testable import SirosWallet

#if canImport(CryptoKit)
import CryptoKit

/// Minimal `AuthProvider` stub - `handleTrustEvaluation` never invokes the
/// authenticator, so all methods simply throw. Duplicated from
/// `SirosWalletDCAPITests` (each test file keeps its own `private` copy;
/// see that file's identical fixture).
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// A `KeystoreManager` test double - `handleTrustEvaluation` never touches
/// the keystore, so every method simply throws or returns an empty/no-op
/// result. Duplicated from `SirosWalletDCAPITests` for the same reason as
/// `StubAuthProvider` above.
private final class FakeKeystoreManager: KeystoreManager, @unchecked Sendable {
    struct NotImplemented: Error {}
    var isUnlocked: Bool = false
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { throw NotImplemented() }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { throw NotImplemented() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { throw NotImplemented() }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        throw NotImplemented()
    }
    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String {
        throw NotImplemented()
    }
    func signMdocPresentationForDCAPI(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        throw NotImplemented()
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
    func generateKeyProof(keyId: String, typ: String, issuer: String, audience: String, extraClaims: [String: String]) async throws -> String {
        throw NotImplemented()
    }
}

/// Covers the `requires_resolution`/`request_jwt` path in
/// `handleTrustEvaluation` (go-wallet-backend#396/#401, this SDK's #168):
/// when the engine could not resolve a `did:`-scheme verifier's key material
/// itself, it defers to the frontend/SDK, which must call `POST /v1/resolve`
/// and verify `request_jwt` against the resolved DID document before
/// proceeding to `/v1/evaluate`.
final class SirosWalletTrustResolutionTests: XCTestCase {

    /// Records every HTTP call a fake `BackendApiClient` makes, keyed by
    /// path, so tests can assert both which endpoints were hit and in what
    /// order - in particular that a resolution/signature failure never
    /// reaches `/v1/evaluate`.
    private final class RequestLog: @unchecked Sendable {
        private let lock = NSLock()
        private var _calls: [(path: String, body: [String: Any])] = []
        var calls: [(path: String, body: [String: Any])] {
            lock.lock(); defer { lock.unlock() }; return _calls
        }
        func record(path: String, body: Data?) {
            let json = body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
            lock.lock(); _calls.append((path, json)); lock.unlock()
        }
    }

    private func makeWallet(
        log: RequestLog,
        resolveResponse: [String: Any],
        evaluateResponse: [String: Any] = ["decision": true]
    ) -> SirosWallet {
        let store = InMemoryCredentialStore()
        let config = WalletConfig(backendUrl: "https://example.invalid", credentialStore: store)
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: FakeKeystoreManager())!
        wallet.apiClient = BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, url, _, body in
            log.record(path: url.path, body: body)
            if url.path.hasSuffix("/v1/resolve") {
                return try JSONSerialization.data(withJSONObject: resolveResponse)
            }
            return try JSONSerialization.data(withJSONObject: evaluateResponse)
        })
        return wallet
    }

    private func base64UrlEncode(_ data: some ContiguousBytes) -> String {
        let d = data.withUnsafeBytes { Data($0) }
        return d.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func jwk(for publicKey: P256.Signing.PublicKey) -> [String: Any] {
        let x963 = publicKey.x963Representation
        return [
            "kty": "EC",
            "crv": "P-256",
            "x": base64UrlEncode(x963[1..<33]),
            "y": base64UrlEncode(x963[33..<65]),
        ]
    }

    /// Build a compact JWS with a `kid`-bearing header (the DID document
    /// verificationMethod fragment), signed by `privateKey`.
    private func signRequestJwt(privateKey: P256.Signing.PrivateKey, kid: String?) throws -> String {
        var header: [String: Any] = ["alg": "ES256"]
        if let kid { header["kid"] = kid }
        let headerB64 = base64UrlEncode(try JSONSerialization.data(withJSONObject: header))
        let payloadB64 = base64UrlEncode(try JSONSerialization.data(withJSONObject: ["client_id": "did:web:verifier.example.com"]))
        let signingInput = Data("\(headerB64).\(payloadB64)".utf8)
        let signature = try privateKey.signature(for: signingInput)
        let sigB64 = base64UrlEncode(signature.rawRepresentation)
        return "\(headerB64).\(payloadB64).\(sigB64)"
    }

    func testHandleTrustEvaluationResolvesDidKeyMaterialWhenRequiresResolution() async throws {
        let verifierKey = P256.Signing.PrivateKey()
        let jwt = try signRequestJwt(privateKey: verifierKey, kid: "did:web:verifier.example.com#key-1")

        let didDocument: [String: Any] = [
            "context": [
                "trust_metadata": [
                    "verificationMethod": [
                        ["id": "did:web:verifier.example.com#key-1", "publicKeyJwk": jwk(for: verifierKey.publicKey)],
                    ],
                ],
            ],
        ]
        let log = RequestLog()
        let wallet = makeWallet(log: log, resolveResponse: didDocument)
        let engine = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-did", payload: [
            "request": [
                "subject_id": "did:web:verifier.example.com",
                "subject_type": "credential_verifier",
                "requires_resolution": true,
                "request_jwt": jwt,
            ],
        ])

        let calls = log.calls
        XCTAssertEqual(calls.map(\.path), ["/v1/resolve", "/v1/evaluate"], "must resolve before evaluating, and must evaluate once resolution succeeds")
        XCTAssertEqual(calls[0].body["subject_type"] as? String, "key")
        let resource = calls[1].body["resource"] as? [String: Any]
        XCTAssertEqual(resource?["type"] as? String, "jwk", "resolved key material must be passed through as a jwk resource")
    }

    /// The JWT header advertises a `did:web:verifier.example.com#key-1` kid,
    /// but that verification method's key never actually signed the JWT (an
    /// attacker key did) - the resolved key material must NOT be accepted,
    /// and evaluateTrust must never be reached.
    func testHandleTrustEvaluationFailsClosedWhenResolvedKeyDoesNotVerifyRequestJwt() async throws {
        let legitKey = P256.Signing.PrivateKey()
        let attackerKey = P256.Signing.PrivateKey()
        let jwt = try signRequestJwt(privateKey: attackerKey, kid: "did:web:verifier.example.com#key-1")

        let didDocument: [String: Any] = [
            "context": [
                "trust_metadata": [
                    "verificationMethod": [
                        ["id": "did:web:verifier.example.com#key-1", "publicKeyJwk": jwk(for: legitKey.publicKey)],
                    ],
                ],
            ],
        ]
        let log = RequestLog()
        let wallet = makeWallet(log: log, resolveResponse: didDocument)
        let engine = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-did-attacker", payload: [
            "request": [
                "subject_id": "did:web:verifier.example.com",
                "subject_type": "credential_verifier",
                "requires_resolution": true,
                "request_jwt": jwt,
            ],
        ])

        XCTAssertEqual(log.calls.map(\.path), ["/v1/resolve"], "a resolution/signature failure must never reach /v1/evaluate")
    }

    func testHandleTrustEvaluationFailsClosedWhenRequiresResolutionButNoRequestJwt() async throws {
        let log = RequestLog()
        let wallet = makeWallet(log: log, resolveResponse: [:])
        let engine = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-no-jwt", payload: [
            "request": [
                "subject_id": "did:web:verifier.example.com",
                "subject_type": "credential_verifier",
                "requires_resolution": true,
            ],
        ])

        XCTAssertTrue(log.calls.isEmpty, "must not call resolve or evaluate without a request_jwt to verify")
    }
}
#endif
