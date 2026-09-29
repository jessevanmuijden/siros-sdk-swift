// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
@testable import SirosWallet

#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1 - see
// SirosWallet+Engine.swift's identical fallback, which is what makes
// resolveDidKeyMaterial (the code under test here) work on Linux at all.
// Gating this whole test file on CryptoKit alone (an earlier version of
// this fix did) silently excluded it - and so never actually ran the
// verification logic below - on Linux.
import Crypto
#endif

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

    private func jwk(for publicKey: Curve25519.Signing.PublicKey) -> [String: Any] {
        ["kty": "OKP", "crv": "Ed25519", "x": base64UrlEncode(publicKey.rawRepresentation)]
    }

    /// Same shape as `signRequestJwt`, but `alg: "EdDSA"` signed by an
    /// Ed25519 key - Ed25519 signatures are already the raw 64-byte form
    /// JWS expects, no ASN.1 unwrapping needed (unlike P-256's
    /// `ECDSASignature.rawRepresentation`, which already does its own
    /// conversion).
    private func signRequestJwtEdDSA(privateKey: Curve25519.Signing.PrivateKey, kid: String?) throws -> String {
        var header: [String: Any] = ["alg": "EdDSA"]
        if let kid { header["kid"] = kid }
        let headerB64 = base64UrlEncode(try JSONSerialization.data(withJSONObject: header))
        let payloadB64 = base64UrlEncode(try JSONSerialization.data(withJSONObject: ["client_id": "did:key:verifier"]))
        let signingInput = Data("\(headerB64).\(payloadB64)".utf8)
        let signature = try privateKey.signature(for: signingInput)
        let sigB64 = base64UrlEncode(signature)
        return "\(headerB64).\(payloadB64).\(sigB64)"
    }

    /// Regression (review finding): the verification primitive must be
    /// selected by the JWS's OWN declared `alg`, never merely by the
    /// candidate key's `kty` - an EC key's real, validly-computed P-256
    /// signature must still be REJECTED if the header falsely declares
    /// `alg: "EdDSA"` (a classic JOSE algorithm-confusion shape), even
    /// though the resolved DID document's only verification method is that
    /// same EC key.
    func testHandleTrustEvaluationFailsClosedWhenAlgDoesNotMatchKeyType() async throws {
        let verifierKey = P256.Signing.PrivateKey()
        let header: [String: Any] = ["alg": "EdDSA", "kid": "did:web:verifier.example.com#key-1"]
        let headerB64 = base64UrlEncode(try JSONSerialization.data(withJSONObject: header))
        let payloadB64 = base64UrlEncode(try JSONSerialization.data(withJSONObject: ["client_id": "did:web:verifier.example.com"]))
        let signingInput = Data("\(headerB64).\(payloadB64)".utf8)
        let signature = try verifierKey.signature(for: signingInput)
        let jwt = "\(headerB64).\(payloadB64).\(base64UrlEncode(signature.rawRepresentation))"

        let didDocument: [String: Any] = [
            "decision": true,
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

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-alg-confusion", payload: [
            "request": [
                "subject_id": "did:web:verifier.example.com",
                "subject_type": "credential_verifier",
                "requires_resolution": true,
                "request_jwt": jwt,
                "resolution_subject_id": "did:web:verifier.example.com",
            ],
        ])

        XCTAssertEqual(log.calls.map(\.path), ["/v1/resolve"], "an EC key tried under a mismatched EdDSA alg must never reach /v1/evaluate")
    }

    /// Regression (review finding): `handleWmpTrustEvaluation` (the
    /// `WalletConfig.useWmpProtocol` transport's trust-evaluation path) is a
    /// separate code path from the legacy engine's `handleTrustEvaluation`,
    /// and ignored `requires_resolution`/`request_jwt`/`resolution_subject_id`
    /// entirely, evaluating trust with no key material at all for a
    /// did:-scheme verifier over WMP.
    func testHandleWmpTrustEvaluationResolvesDidKeyMaterialWhenRequiresResolution() async throws {
        let verifierKey = P256.Signing.PrivateKey()
        let jwt = try signRequestJwt(privateKey: verifierKey, kid: "did:web:verifier.example.com#key-1")

        let didDocument: [String: Any] = [
            "decision": true,
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

        let payload = AnyCodable.object_([
            "request": .object_([
                "subject_id": .string("did:web:verifier.example.com"),
                "subject_type": .string("credential_verifier"),
                "requires_resolution": .bool(true),
                "request_jwt": .string(jwt),
                "resolution_subject_id": .string("did:web:verifier.example.com"),
            ]),
        ])

        let result = await wallet.handleWmpTrustEvaluation(flowId: "flow-wmp-did", payload: payload)

        XCTAssertEqual(log.calls.map(\.path), ["/v1/resolve", "/v1/evaluate"], "must resolve before evaluating, and must evaluate once resolution succeeds")
        let resource = log.calls[1].body["resource"] as? [String: Any]
        XCTAssertEqual(resource?["type"] as? String, "jwk", "resolved key material must be passed through as a jwk resource")
        XCTAssertTrue(result.trusted)
    }

    /// Regression (review finding): a DID ISSUER's requires_resolution
    /// carries no request_jwt at all - OID4VCI issuance has no signed
    /// request object to verify one against. Unconditionally requiring
    /// request_jwt (as an earlier version of this fix did) rejected every
    /// DID issuer over WMP before ever calling /v1/resolve.
    func testHandleWmpTrustEvaluationResolvesIssuerDidKeyMaterialWithoutRequestJwt() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let didDocument: [String: Any] = [
            "decision": true,
            "context": [
                "trust_metadata": [
                    "verificationMethod": [
                        ["id": "did:web:issuer.example.com#key-1", "publicKeyJwk": jwk(for: issuerKey.publicKey)],
                    ],
                ],
            ],
        ]
        let log = RequestLog()
        let wallet = makeWallet(log: log, resolveResponse: didDocument)

        let payload = AnyCodable.object_([
            "request": .object_([
                "subject_id": .string("did:web:issuer.example.com"),
                "subject_type": .string("credential_issuer"),
                "requires_resolution": .bool(true),
                "resolution_subject_id": .string("did:web:issuer.example.com"),
            ]),
        ])

        let result = await wallet.handleWmpTrustEvaluation(flowId: "flow-wmp-issuer", payload: payload)

        XCTAssertEqual(log.calls.map(\.path), ["/v1/resolve", "/v1/evaluate"], "an issuer resolution with no request_jwt must still resolve and evaluate")
        let resource = log.calls[1].body["resource"] as? [String: Any]
        XCTAssertEqual(resource?["type"] as? String, "jwk")
        XCTAssertEqual((resource?["key"] as? [[String: Any]])?.count, 1, "the resolved verification method's jwk must be forwarded")
        XCTAssertTrue(result.trusted)
    }

    func testHandleTrustEvaluationResolvesDidKeyMaterialWhenRequiresResolution() async throws {
        let verifierKey = P256.Signing.PrivateKey()
        let jwt = try signRequestJwt(privateKey: verifierKey, kid: "did:web:verifier.example.com#key-1")

        let didDocument: [String: Any] = [
            "decision": true,
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
                "resolution_subject_id": "did:web:verifier.example.com",
            ],
        ])

        let calls = log.calls
        XCTAssertEqual(calls.map(\.path), ["/v1/resolve", "/v1/evaluate"], "must resolve before evaluating, and must evaluate once resolution succeeds")
        XCTAssertEqual(calls[0].body["subject_type"] as? String, "key")
        let resource = calls[1].body["resource"] as? [String: Any]
        XCTAssertEqual(resource?["type"] as? String, "jwk", "resolved key material must be passed through as a jwk resource")
    }

    /// Regression (review finding): a DID ISSUER's requires_resolution
    /// carries no request_jwt at all - OID4VCI issuance has no signed
    /// request object to verify one against. Unconditionally requiring
    /// request_jwt (as an earlier version of this fix did) rejected every
    /// DID issuer over the legacy engine path before ever calling
    /// /v1/resolve.
    func testHandleTrustEvaluationResolvesIssuerDidKeyMaterialWithoutRequestJwt() async throws {
        let issuerKey = P256.Signing.PrivateKey()
        let didDocument: [String: Any] = [
            "decision": true,
            "context": [
                "trust_metadata": [
                    "verificationMethod": [
                        ["id": "did:web:issuer.example.com#key-1", "publicKeyJwk": jwk(for: issuerKey.publicKey)],
                    ],
                ],
            ],
        ]
        let log = RequestLog()
        let wallet = makeWallet(log: log, resolveResponse: didDocument)
        let engine = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-issuer", payload: [
            "request": [
                "subject_id": "did:web:issuer.example.com",
                "subject_type": "credential_issuer",
                "requires_resolution": true,
                "resolution_subject_id": "did:web:issuer.example.com",
            ],
        ])

        let calls = log.calls
        XCTAssertEqual(calls.map(\.path), ["/v1/resolve", "/v1/evaluate"], "an issuer resolution with no request_jwt must still resolve and evaluate")
        let resource = calls[1].body["resource"] as? [String: Any]
        XCTAssertEqual(resource?["type"] as? String, "jwk")
        XCTAssertEqual((resource?["key"] as? [[String: Any]])?.count, 1, "the resolved verification method's jwk must be forwarded")
    }

    func testHandleTrustEvaluationResolvesEd25519KeyMaterial() async throws {
        let verifierKey = Curve25519.Signing.PrivateKey()
        let jwt = try signRequestJwtEdDSA(privateKey: verifierKey, kid: "did:key:verifier#key-1")

        let didDocument: [String: Any] = [
            "decision": true,
            "context": [
                "trust_metadata": [
                    "verificationMethod": [
                        ["id": "did:key:verifier#key-1", "publicKeyJwk": jwk(for: verifierKey.publicKey)],
                    ],
                ],
            ],
        ]
        let log = RequestLog()
        let wallet = makeWallet(log: log, resolveResponse: didDocument)
        let engine = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-ed25519", payload: [
            "request": [
                "subject_id": "did:key:verifier",
                "subject_type": "credential_verifier",
                "requires_resolution": true,
                "request_jwt": jwt,
                "resolution_subject_id": "did:key:verifier",
            ],
        ])

        XCTAssertEqual(log.calls.map(\.path), ["/v1/resolve", "/v1/evaluate"], "an Ed25519-signed request_jwt must verify and reach /v1/evaluate")
    }

    /// go-wallet-backend#401's `resolution_subject_id` carries the bare DID
    /// for `/v1/resolve`, distinct from `subject_id` - which, for an
    /// OpenID4VP 1.0 `decentralized_identifier:`-prefixed client_id, is NOT
    /// itself a resolvable DID. Passing `subject_id` to `/v1/resolve` here
    /// would send the still-prefixed value and fail to resolve.
    func testHandleTrustEvaluationUsesResolutionSubjectIdNotSubjectId() async throws {
        let verifierKey = P256.Signing.PrivateKey()
        let jwt = try signRequestJwt(privateKey: verifierKey, kid: "did:web:verifier.example.com#key-1")

        let didDocument: [String: Any] = [
            "decision": true,
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

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-prefixed", payload: [
            "request": [
                "subject_id": "decentralized_identifier:did:web:verifier.example.com",
                "subject_type": "credential_verifier",
                "requires_resolution": true,
                "request_jwt": jwt,
                "resolution_subject_id": "did:web:verifier.example.com",
            ],
        ])

        let calls = log.calls
        XCTAssertEqual(calls.map(\.path), ["/v1/resolve", "/v1/evaluate"])
        XCTAssertEqual(calls[0].body["subject_id"] as? String, "did:web:verifier.example.com", "/v1/resolve must get the bare DID, not the prefixed subject_id")
        let evaluateSubject = calls[1].body["subject"] as? [String: Any]
        XCTAssertEqual(evaluateSubject?["id"] as? String, "decentralized_identifier:did:web:verifier.example.com", "/v1/evaluate must keep seeing the original, unstripped client_id")
    }

    /// Regression (review finding): `/v1/resolve` is itself an AuthZEN
    /// evaluation - a denied response (`decision: false`) can still carry
    /// `trust_metadata` (populated independently of the decision), so a
    /// genuinely-verifying signature must NOT be enough on its own; the
    /// decision must be explicit `true` too, mirroring go-wallet-backend's
    /// own `ResolveDID` path.
    func testHandleTrustEvaluationFailsClosedWhenResolveDecisionIsNotTrue() async throws {
        let verifierKey = P256.Signing.PrivateKey()
        let jwt = try signRequestJwt(privateKey: verifierKey, kid: "did:web:verifier.example.com#key-1")

        let deniedDidDocument: [String: Any] = [
            "decision": false,
            "context": [
                "trust_metadata": [
                    "verificationMethod": [
                        ["id": "did:web:verifier.example.com#key-1", "publicKeyJwk": jwk(for: verifierKey.publicKey)],
                    ],
                ],
            ],
        ]
        let log = RequestLog()
        let wallet = makeWallet(log: log, resolveResponse: deniedDidDocument)
        let engine = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-denied", payload: [
            "request": [
                "subject_id": "did:web:verifier.example.com",
                "subject_type": "credential_verifier",
                "requires_resolution": true,
                "request_jwt": jwt,
                "resolution_subject_id": "did:web:verifier.example.com",
            ],
        ])

        XCTAssertEqual(log.calls.map(\.path), ["/v1/resolve"], "a denied resolution must never reach /v1/evaluate, even with a validly-signed request_jwt and usable trust_metadata")
    }

    /// Regression (review finding): a JWK's `kty` alone must not select the
    /// reconstruction path - `P256.Signing.PublicKey` only ever reconstructs
    /// a P-256 key regardless of what curve the JWK claims, so a JWK
    /// declaring `kty: "EC"` but a DIFFERENT curve (not "P-256") must be
    /// rejected rather than silently reinterpreted as P-256.
    func testHandleTrustEvaluationFailsClosedWhenJwkCurveIsNotP256() async throws {
        let verifierKey = P256.Signing.PrivateKey()
        let jwt = try signRequestJwt(privateKey: verifierKey, kid: "did:web:verifier.example.com#key-1")

        var mismatchedCurveJwk = jwk(for: verifierKey.publicKey)
        mismatchedCurveJwk["crv"] = "P-384"

        let didDocument: [String: Any] = [
            "decision": true,
            "context": [
                "trust_metadata": [
                    "verificationMethod": [
                        ["id": "did:web:verifier.example.com#key-1", "publicKeyJwk": mismatchedCurveJwk],
                    ],
                ],
            ],
        ]
        let log = RequestLog()
        let wallet = makeWallet(log: log, resolveResponse: didDocument)
        let engine = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-wrong-curve", payload: [
            "request": [
                "subject_id": "did:web:verifier.example.com",
                "subject_type": "credential_verifier",
                "requires_resolution": true,
                "request_jwt": jwt,
                "resolution_subject_id": "did:web:verifier.example.com",
            ],
        ])

        XCTAssertEqual(log.calls.map(\.path), ["/v1/resolve"], "a JWK claiming a non-P-256 curve must never reach /v1/evaluate")
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
            "decision": true,
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
                "resolution_subject_id": "did:web:verifier.example.com",
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

    /// go-wallet-backend#401's TrustEvaluationRequest.Validate() makes
    /// resolution_subject_id mandatory whenever requires_resolution is
    /// true - an engine that omits it is non-conformant, and this must fail
    /// closed rather than silently falling back to (possibly prefixed)
    /// subject_id for the resolution call.
    func testHandleTrustEvaluationFailsClosedWhenRequiresResolutionButNoResolutionSubjectId() async throws {
        let log = RequestLog()
        let wallet = makeWallet(log: log, resolveResponse: [:])
        let engine = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")

        await wallet.handleTrustEvaluation(engine: engine, flowId: "flow-no-resolution-subject-id", payload: [
            "request": [
                "subject_id": "did:web:verifier.example.com",
                "subject_type": "credential_verifier",
                "requires_resolution": true,
                "request_jwt": "header.payload.sig",
            ],
        ])

        XCTAssertTrue(log.calls.isEmpty, "must not call resolve or evaluate without resolution_subject_id")
    }
}
