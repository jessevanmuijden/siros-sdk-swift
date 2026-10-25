// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
@testable import SirosWallet

/// Minimal `AuthProvider` stub - never invoked by the sign-request dispatcher.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// `KeystoreManager` double whose `generateKeyProof` mints an UNSIGNED but
/// structurally valid JWT (`header.payload.sig`) carrying the `iss`/`aud`/
/// `typ` it was asked for, so tests can decode the PoP and assert on the
/// claims the real keystore would have signed. Records every call.
private final class RecordingKeystoreManager: KeystoreManager, @unchecked Sendable {
    struct NotImplemented: Error {}
    struct Refused: Error {}

    var isUnlocked: Bool = false
    var refuseKeyProof = false
    private(set) var keyProofCalls: [(keyId: String, typ: String, issuer: String, audience: String, extraClaims: [String: String])] = []
    private(set) var dpopProofCalls: [(keyId: String, htm: String, htu: String, nonce: String?, accessTokenHash: String?)] = []

    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { "instance-key-1" }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { throw NotImplemented() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { throw NotImplemented() }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        throw NotImplemented()
    }
    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String {
        throw NotImplemented()
    }
    func signMdocPresentationForDCAPI(
        credentialBytes: Data, disclosedClaims: [String]?, nonce: String, origin: String,
        encryptionPublicJwkThumbprint: String?, kid: String?
    ) async throws -> Data { throw NotImplemented() }
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

    func generateKeyProof(
        keyId: String, typ: String, issuer: String, audience: String, extraClaims: [String: String]
    ) async throws -> String {
        keyProofCalls.append((keyId, typ, issuer, audience, extraClaims))
        if refuseKeyProof { throw Refused() }
        let header = try JSONSerialization.data(withJSONObject: ["alg": "ES256", "typ": typ])
        var claims: [String: Any] = ["iss": issuer, "aud": audience]
        for (k, v) in extraClaims { claims[k] = v }
        let payload = try JSONSerialization.data(withJSONObject: claims)
        return [header, payload, Data("sig".utf8)].map(Self.b64url).joined(separator: ".")
    }

    func generateDPoPProof(keyId: String, htm: String, htu: String, nonce: String?, accessTokenHash: String?) async throws -> String {
        dpopProofCalls.append((keyId, htm, htu, nonce, accessTokenHash))
        if refuseKeyProof { throw Refused() }
        return "dpop-proof-for-\(keyId)"
    }

    private static func b64url(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}

/// Records every `sign_response` the dispatcher sends - the seam
/// `handleSignRequest` takes instead of a live `WalletEngineSession`.
private final class RecordingSignResponseSender: SignResponseSender, @unchecked Sendable {
    struct Sent {
        let flowId: String
        let proofJwt: String?
        let vpToken: String?
        let proofs: [ProofObject]?
        let clientAttestation: String?
        let clientAttestationPoP: String?
        let dpopKeyId: String?
        let dpopProof: String?
        let messageId: String?
    }
    private(set) var sent: [Sent] = []

    func sendSignResponse(_ m: SignResponseMessage) {
        sent.append(Sent(
            flowId: m.flowId, proofJwt: m.proofJwt, vpToken: m.vpToken, proofs: m.proofs,
            clientAttestation: m.clientAttestation, clientAttestationPoP: m.clientAttestationPoP,
            dpopKeyId: m.dpopKeyId, dpopProof: m.dpopProof, messageId: m.messageId
        ))
    }
}

/// go-wallet-backend#304's `request_attestation` sign action: the engine,
/// having resolved the issuer's authorization server itself, asks the client
/// for a WIA + per-flow PoP bound to that AS. The backend's `RequestSign`
/// blocks for 30 s on a matching `message_id`, so the contract under test is
/// as much "always answer" as "answer correctly".
final class SirosWalletSignRequestTests: XCTestCase {

    private func makeWallet(keystore: RecordingKeystoreManager) -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://backend.example.invalid", redirectUri: "https://wallet.example.invalid/cb")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: keystore)
        XCTAssertNotNil(wallet, "wallet should initialise with an injected keystore on every platform")
        return wallet!
    }

    private func signRequest(action: String, params: [String: Any]) throws -> SignRequestMessage {
        let json: [String: Any] = [
            "type": "sign_request", "flow_id": "flow-1", "message_id": "msg-42", "action": action, "params": params,
        ]
        return try JSONDecoder().decode(SignRequestMessage.self, from: JSONSerialization.data(withJSONObject: json))
    }

    private func decodePayload(_ jwt: String) throws -> [String: Any] {
        let parts = jwt.split(separator: ".")
        XCTAssertEqual(parts.count, 3)
        var b64 = String(parts[1]).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64 += "=" }
        let data = try XCTUnwrap(Data(base64Encoded: b64))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    /// The PoP must be bound to exactly what the engine asked for: `aud` =
    /// `params.audience` (the AS the token request goes to), `iss` =
    /// `params.issuer` (the flow's effective client_id, override included) -
    /// NOT to anything the client would have derived on its own.
    func testRequestAttestationRespondsWithWiaAndPopBoundToEngineParams() async throws {
        let keystore = RecordingKeystoreManager()
        let wallet = makeWallet(keystore: keystore)
        wallet.cachedWia = "cached-wia-jwt"
        wallet.cachedWiaExpiresAt = Int(Date().timeIntervalSince1970) + 3600
        let sender = RecordingSignResponseSender()

        let msg = try signRequest(action: "request_attestation", params: [
            "audience": "https://as.example.invalid",
            "issuer": "https://registered-client-id.example.invalid",
        ])
        await wallet.handleSignRequest(engine: sender, msg: msg)

        XCTAssertEqual(sender.sent.count, 1, "exactly one sign_response must be sent")
        let sent = try XCTUnwrap(sender.sent.first)
        XCTAssertEqual(sent.flowId, "flow-1")
        XCTAssertEqual(sent.messageId, "msg-42", "response must correlate to the request's message_id or RequestSign never unblocks")
        XCTAssertEqual(sent.clientAttestation, "cached-wia-jwt")
        XCTAssertNil(sent.proofJwt); XCTAssertNil(sent.vpToken); XCTAssertNil(sent.proofs)

        let pop = try XCTUnwrap(sent.clientAttestationPoP)
        let claims = try decodePayload(pop)
        XCTAssertEqual(claims["aud"] as? String, "https://as.example.invalid")
        XCTAssertEqual(claims["iss"] as? String, "https://registered-client-id.example.invalid")

        XCTAssertEqual(keystore.keyProofCalls.count, 1)
        let call = try XCTUnwrap(keystore.keyProofCalls.first)
        XCTAssertEqual(call.typ, "oauth-client-attestation-pop+jwt")
        XCTAssertEqual(call.keyId, "instance-key-1", "PoP must be signed with the persistent instance key")
        XCTAssertNil(call.extraClaims["challenge"], "unreachable AS publishes no challenge_endpoint, so no challenge claim")
    }

    /// `sign_client_auth` (go-wallet-backend#317): the engine asks for a DPoP
    /// proof and a fresh attestation PoP for one request. Both must be signed
    /// with the instance key - the WIA's `cnf` key - and the reply must name
    /// that key as `dpop_key_id`, so the token ends up bound to the attested
    /// key.
    func testSignClientAuthSignsDpopAndFreshPopWithInstanceKey() async throws {
        let keystore = RecordingKeystoreManager()
        let wallet = makeWallet(keystore: keystore)
        wallet.cachedWia = "cached-wia-jwt"
        wallet.cachedWiaExpiresAt = Int(Date().timeIntervalSince1970) + 3600
        let sender = RecordingSignResponseSender()

        let msg = try signRequest(action: "sign_client_auth", params: [
            "audience": "https://as.example.invalid",
            "issuer": "https://registered-client-id.example.invalid",
            "htm": "POST",
            "htu": "https://as.example.invalid/token",
            "dpop_nonce": "n-1",
            "ath": "ath-value",
        ])
        await wallet.handleSignRequest(engine: sender, msg: msg)

        XCTAssertEqual(sender.sent.count, 1)
        let sent = try XCTUnwrap(sender.sent.first)
        XCTAssertEqual(sent.messageId, "msg-42")
        XCTAssertEqual(sent.dpopKeyId, "instance-key-1", "the key is named so the engine can ask for it again on renewal")
        XCTAssertEqual(sent.dpopProof, "dpop-proof-for-instance-key-1")
        XCTAssertEqual(sent.clientAttestation, "cached-wia-jwt")
        let pop = try XCTUnwrap(sent.clientAttestationPoP)
        let claims = try decodePayload(pop)
        XCTAssertEqual(claims["aud"] as? String, "https://as.example.invalid")
        XCTAssertEqual(claims["iss"] as? String, "https://registered-client-id.example.invalid")

        XCTAssertEqual(keystore.dpopProofCalls.count, 1)
        let dpop = try XCTUnwrap(keystore.dpopProofCalls.first)
        XCTAssertEqual(dpop.keyId, "instance-key-1", "DPoP proof and PoP must be signed with one key")
        XCTAssertEqual(dpop.htm, "POST")
        XCTAssertEqual(dpop.htu, "https://as.example.invalid/token")
        XCTAssertEqual(dpop.nonce, "n-1")
        XCTAssertEqual(dpop.accessTokenHash, "ath-value")
        XCTAssertEqual(keystore.keyProofCalls.first?.keyId, "instance-key-1")
    }

    /// A resource-request `sign_client_auth` (no audience) yields a DPoP proof
    /// only, and a renewal's `key_id` picks the key the refresh_token was
    /// bound to instead of the current instance key. No PoP either way.
    func testSignClientAuthDpopOnlyHonoursKeyIdHint() async throws {
        let keystore = RecordingKeystoreManager()
        let wallet = makeWallet(keystore: keystore)
        let sender = RecordingSignResponseSender()

        await wallet.handleSignRequest(engine: sender, msg: try signRequest(action: "sign_client_auth", params: [
            "htm": "POST", "htu": "https://issuer.example.invalid/credential", "ath": "ath-value", "key_id": "old-instance-key",
        ]))

        XCTAssertEqual(sender.sent.count, 1)
        let sent = try XCTUnwrap(sender.sent.first)
        XCTAssertEqual(sent.dpopKeyId, "old-instance-key")
        XCTAssertEqual(sent.dpopProof, "dpop-proof-for-old-instance-key")
        XCTAssertNil(sent.clientAttestation)
        XCTAssertNil(sent.clientAttestationPoP)
        XCTAssertEqual(keystore.dpopProofCalls.first?.keyId, "old-instance-key")
        XCTAssertNil(keystore.dpopProofCalls.first?.nonce)
        XCTAssertTrue(keystore.keyProofCalls.isEmpty, "no attestation was asked for")
    }

    /// A failing keystore still gets exactly one answer: the key is named
    /// (so the engine knows the action is understood) but no proof - the
    /// engine then fails that request rather than silently downgrading.
    func testSignClientAuthWithFailingKeystoreStillAnswersOnce() async throws {
        let keystore = RecordingKeystoreManager()
        keystore.refuseKeyProof = true
        let wallet = makeWallet(keystore: keystore)
        let sender = RecordingSignResponseSender()

        await wallet.handleSignRequest(engine: sender, msg: try signRequest(action: "sign_client_auth", params: [
            "htm": "POST", "htu": "https://as.example.invalid/token",
        ]))

        XCTAssertEqual(sender.sent.count, 1)
        XCTAssertEqual(sender.sent.first?.messageId, "msg-42")
        XCTAssertEqual(sender.sent.first?.dpopKeyId, "instance-key-1")
        XCTAssertNil(sender.sent.first?.dpopProof)
    }

    /// No `issuer` from the engine: fall back to the wallet's own default
    /// client_id convention (`redirectUri`), never an empty `iss`.
    func testRequestAttestationFallsBackToRedirectUriAsClientId() async throws {
        let keystore = RecordingKeystoreManager()
        let wallet = makeWallet(keystore: keystore)
        wallet.cachedWia = "cached-wia-jwt"
        wallet.cachedWiaExpiresAt = Int(Date().timeIntervalSince1970) + 3600
        let sender = RecordingSignResponseSender()

        await wallet.handleSignRequest(
            engine: sender,
            msg: try signRequest(action: "request_attestation", params: ["audience": "https://as.example.invalid"])
        )

        let pop = try XCTUnwrap(sender.sent.first?.clientAttestationPoP)
        XCTAssertEqual(try decodePayload(pop)["iss"] as? String, "https://wallet.example.invalid/cb")
    }

    /// No WIA available (nothing cached, no backend to fetch one from): the
    /// client must still answer - with an EMPTY sign_response - so the engine
    /// proceeds without attestation immediately rather than after 30 s.
    func testRequestAttestationWithoutWiaSendsEmptyResponse() async throws {
        let keystore = RecordingKeystoreManager()
        let wallet = makeWallet(keystore: keystore)
        XCTAssertNil(wallet.cachedWia)
        XCTAssertNil(wallet.apiClient, "no backend client, so ensureWalletInstanceAttestation can't mint a WIA")
        let sender = RecordingSignResponseSender()

        await wallet.handleSignRequest(
            engine: sender,
            msg: try signRequest(action: "request_attestation", params: [
                "audience": "https://as.example.invalid", "issuer": "https://client.example.invalid",
            ])
        )

        XCTAssertEqual(sender.sent.count, 1)
        let sent = try XCTUnwrap(sender.sent.first)
        XCTAssertEqual(sent.messageId, "msg-42")
        XCTAssertNil(sent.clientAttestation)
        XCTAssertNil(sent.clientAttestationPoP)
        XCTAssertTrue(keystore.keyProofCalls.isEmpty, "no PoP is signed when there is no WIA to pair it with")
    }

    /// PoP signing failing (locked keystore, missing key, ...) degrades the
    /// same way: an empty response, never a half pair and never silence.
    func testRequestAttestationWithFailingKeystoreSendsEmptyResponse() async throws {
        let keystore = RecordingKeystoreManager()
        keystore.refuseKeyProof = true
        let wallet = makeWallet(keystore: keystore)
        wallet.cachedWia = "cached-wia-jwt"
        wallet.cachedWiaExpiresAt = Int(Date().timeIntervalSince1970) + 3600
        let sender = RecordingSignResponseSender()

        await wallet.handleSignRequest(
            engine: sender,
            msg: try signRequest(action: "request_attestation", params: ["audience": "https://as.example.invalid"])
        )

        XCTAssertEqual(sender.sent.count, 1)
        XCTAssertNil(sender.sent.first?.clientAttestation)
        XCTAssertNil(sender.sent.first?.clientAttestationPoP)
    }

    /// A request with no audience can't produce a correctly-bound PoP; decline.
    func testRequestAttestationWithoutAudienceSendsEmptyResponse() async throws {
        let keystore = RecordingKeystoreManager()
        let wallet = makeWallet(keystore: keystore)
        wallet.cachedWia = "cached-wia-jwt"
        wallet.cachedWiaExpiresAt = Int(Date().timeIntervalSince1970) + 3600
        let sender = RecordingSignResponseSender()

        await wallet.handleSignRequest(engine: sender, msg: try signRequest(action: "request_attestation", params: [:]))

        XCTAssertEqual(sender.sent.count, 1)
        XCTAssertNil(sender.sent.first?.clientAttestationPoP)
        XCTAssertTrue(keystore.keyProofCalls.isEmpty)
    }

    /// Regression: an action this build doesn't know used to be silently
    /// dropped (`default: break`), leaving the engine on its 30 s sign
    /// timeout. It must now be answered - with an empty response, since the
    /// engine has no dedicated sign-error message.
    func testUnknownSignActionIsAnsweredNotDropped() async throws {
        let wallet = makeWallet(keystore: RecordingKeystoreManager())
        let sender = RecordingSignResponseSender()

        await wallet.handleSignRequest(
            engine: sender,
            msg: try signRequest(action: "some_future_action", params: ["audience": "https://x.example.invalid"])
        )

        XCTAssertEqual(sender.sent.count, 1)
        let sent = try XCTUnwrap(sender.sent.first)
        XCTAssertEqual(sent.flowId, "flow-1")
        XCTAssertEqual(sent.messageId, "msg-42")
        XCTAssertNil(sent.proofJwt); XCTAssertNil(sent.vpToken); XCTAssertNil(sent.proofs)
        XCTAssertNil(sent.clientAttestation); XCTAssertNil(sent.clientAttestationPoP)
    }
}

// MARK: - Wallet instance lifecycle facade (SID-AUTH-06)

/// `SirosWallet.listWalletInstances()`: the facade refuses when not logged in
/// and otherwise forwards to the backend client.
final class SirosWalletLifecycleFacadeTests: XCTestCase {
    private func makeWallet() -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://backend.example.invalid", redirectUri: "https://wallet.example.invalid/cb")
        return SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: RecordingKeystoreManager())!
    }

    /// Minimal recording HTTP function: captures method/path/body and answers
    /// per path (not from one queue) - `listWalletInstances()` fetches a
    /// Wallet Instance Attestation first when this session has none, to know
    /// which row is this device, so a positional queue would hand the
    /// attestation's challenge request the listing's answer.
    private final class Recorder: @unchecked Sendable {
        var calls: [(method: String, path: String, body: [String: Any]?)] = []
        var responses: [String: String]
        init(_ responses: [String: String]) { self.responses = responses }
        func calls(to path: String) -> [(method: String, path: String, body: [String: Any]?)] {
            calls.filter { $0.path == path }
        }
        var httpFn: @Sendable (String, URL, [String: String], Data?) async throws -> Data {
            { [self] method, url, _, body in
                let parsed = body.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
                self.calls.append((method, url.path, parsed))
                return Data((self.responses[url.path] ?? "{}").utf8)
            }
        }
    }

    func testNotLoggedInIsAnAuthError() async {
        let wallet = makeWallet()
        XCTAssertNil(wallet.apiClient)
        do {
            _ = try await wallet.listWalletInstances()
            XCTFail("expected SirosError.auth")
        } catch SirosError.auth { }
        catch { XCTFail("unexpected \(error)") }
    }

    func testFacadeForwardsToTheBackendClient() async throws {
        let wallet = makeWallet()
        let recorder = Recorder([
            "/user/session/instances": #"{"instances":[{"id":"jkt-1","status":"active","credential_id":"pk-1"}]}"#,
        ])
        let client = BackendApiClient(baseUrl: "https://backend.example.invalid", tenantId: "default", httpFn: recorder.httpFn)
        client.setAppToken("t")
        wallet.apiClient = client
        let instances = try await wallet.listWalletInstances()
        XCTAssertEqual(instances.map(\.id), ["jkt-1"])
        let listCalls = recorder.calls(to: "/user/session/instances")
        XCTAssertEqual(listCalls.count, 1)
        XCTAssertEqual(listCalls[0].method, "GET")
        // No WIA was obtainable here (the stubbed challenge answers `{}`), so
        // no row can be marked as this device - and the listing still works.
        XCTAssertFalse(instances[0].isThisDevice)
    }
}
