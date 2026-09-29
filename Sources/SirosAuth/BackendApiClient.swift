// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials

/// Type alias for an injectable HTTP function used by BackendApiClient.
/// Parameters: method, URL, headers, optional body. Returns: response data.
public typealias HttpFunction = @Sendable (String, URL, [String: String], Data?) async throws -> Data

/// Authenticated HTTP client for the wallet backend REST API.
///
/// Requires a valid `appToken` (JWT) obtained from `WebAuthnAuthClient.login()`
/// or `WebAuthnAuthClient.register()`.
public final class BackendApiClient: @unchecked Sendable {

    private let baseUrl: String
    private let tenantId: String
    private let httpFn: HttpFunction
    private let lock = NSLock()
    private var _appToken: String?
    /// Waits, in seconds, between the attempts of a `409 ERASURE_INCOMPLETE`
    /// retry (see `revokeAllWalletInstances(reason:)`). One more attempt is
    /// made than there are entries here, so the default is five attempts over
    /// about 15 s - long enough for a transient backend failure to clear,
    /// short enough that the OS will not suspend the app mid-loop. Tests pass
    /// zeros.
    private let erasureRetryDelays: [TimeInterval]

    /// Create a client with a custom HTTP function (for testing).
    public init(
        baseUrl: String,
        tenantId: String = "default",
        erasureRetryDelays: [TimeInterval] = [1, 2, 4, 8],
        httpFn: @escaping HttpFunction
    ) {
        self.baseUrl = baseUrl
        self.tenantId = tenantId
        self.erasureRetryDelays = erasureRetryDelays
        self.httpFn = httpFn
    }

    #if !os(Linux)
    /// Create a client using URLSession for HTTP.
    public convenience init(
        baseUrl: String,
        tenantId: String = "default",
        erasureRetryDelays: [TimeInterval] = [1, 2, 4, 8]
    ) {
        self.init(baseUrl: baseUrl, tenantId: tenantId, erasureRetryDelays: erasureRetryDelays) { method, url, headers, body in
            var request = URLRequest(url: url)
            request.httpMethod = method
            request.httpBody = body
            for (key, value) in headers {
                request.setValue(value, forHTTPHeaderField: key)
            }
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse else {
                throw SirosError.network(message: "Invalid response")
            }
            guard (200..<300).contains(httpResponse.statusCode) else {
                let bodyStr = String(data: data, encoding: .utf8) ?? ""
                throw SirosError.backendApi(
                    code: httpResponse.statusCode,
                    message: "API request failed: \(httpResponse.statusCode)",
                    body: bodyStr
                )
            }
            return data
        }
    }
    #endif

    public func setAppToken(_ token: String) {
        lock.lock()
        defer { lock.unlock() }
        _appToken = token
    }

    private var _authTokens: AuthTokens?

    /// Configure this client to use `AuthTokens` for automatic token management.
    /// When set, `setAppToken` is ignored and tokens are obtained from the AS.
    public func setAuthTokens(_ tokens: AuthTokens) {
        lock.lock()
        defer { lock.unlock() }
        _authTokens = tokens
    }

    // MARK: - API endpoints

    /// GET /user/session/account-info
    public func getAccountInfo() async throws -> [String: Any] {
        try await get("/user/session/account-info")
    }

    /// GET /storage/vc — list all credentials
    public func getCredentials() async throws -> [String: Any] {
        try await get("/storage/vc")
    }

    /// POST /storage/vc — store a credential
    public func storeCredential(_ credential: [String: Any]) async throws -> [String: Any] {
        try await post("/storage/vc", body: credential)
    }

    /// GET /storage/vc/:id
    public func getCredential(id: String) async throws -> [String: Any] {
        try await get("/storage/vc/\(id)")
    }

    /// DELETE /storage/vc/:id
    public func deleteCredential(id: String) async throws -> [String: Any] {
        try await delete("/storage/vc/\(id)")
    }

    /// GET /issuer/all — list registered issuers
    public func getIssuers() async throws -> Any {
        try await getRaw("/issuer/all")
    }

    /// GET /issuer/:id/metadata
    public func getIssuerMetadata(id: Int) async throws -> [String: Any] {
        try await get("/issuer/\(id)/metadata")
    }

    /// POST /v1/resolve — resolve an issuer through the backend's AuthZEN
    /// endpoint, which returns its metadata already authenticated together
    /// with a decision about the issuer's registration.
    ///
    /// Unlike `getIssuerMetadata(id:)` this works for any issuer URL, not only
    /// the ones registered with this wallet's own backend, and unlike a direct
    /// well-known fetch the document arrives verified rather than merely
    /// downloaded.
    public func resolveIssuer(
        issuerUrl: String,
        credentialTypes: [String] = []
    ) async throws -> [String: Any] {
        var body: [String: Any] = [
            "subject_id": issuerUrl,
            "subject_type": "url",
            "resource_type": "credential_issuer",
        ]
        if !credentialTypes.isEmpty {
            body["credential_types"] = credentialTypes
        }
        return try await post("/v1/resolve", body: body)
    }

    /// POST /v1/resolve — resolve a "key" subject (a `did:` identifier) to
    /// its verification key material, proxied by the backend directly to
    /// the PDP (see go-wallet-backend's `AuthZENProxyHandler.Resolve`).
    ///
    /// Distinct from `resolveIssuer`, which always sends `subject_type:
    /// "url"` for OpenID4VCI issuer metadata resolution - this is the
    /// counterpart for a DID-scheme subject's
    /// `TrustEvaluationRequest.requires_resolution` (go-wallet-backend#396/
    /// #401): when the engine cannot resolve the DID itself (no verifier PDP
    /// configured), it defers to the frontend/SDK, which must call this
    /// before `evaluateTrust`. Used for BOTH verifiers and issuers - an
    /// issuer request has no signed authorization request object to verify
    /// (OID4VCI has nothing analogous to OpenID4VP's request JWT), so it
    /// calls this with no `request_jwt` at all.
    ///
    /// The response's `context.trust_metadata` is the resolved DID Document,
    /// with a `decision` the caller must check is explicitly `true` before
    /// trusting anything in `context` - the caller is responsible for
    /// extracting a `verificationMethod` entry's `publicKeyJwk`. A
    /// `credential_verifier` caller must additionally verify the
    /// accompanying `request_jwt` against the SPECIFIC method its `kid`
    /// names (see `SirosWallet`'s `resolveDidKeyMaterial`); a
    /// `credential_issuer` caller has no signature to verify and forwards
    /// every resolved method instead (see `resolveIssuerDidKeyMaterial`).
    public func resolveKey(subjectId: String) async throws -> [String: Any] {
        let body: [String: Any] = [
            "subject_id": subjectId,
            "subject_type": "key",
        ]
        return try await post("/v1/resolve", body: body)
    }

    /// GET /verifier/all — list registered verifiers
    public func getVerifiers() async throws -> [String: Any] {
        try await get("/verifier/all")
    }

    /// GET /user/session/private-data
    public func getPrivateData() async throws -> [String: Any] {
        try await get("/user/session/private-data")
    }

    /// POST /user/session/private-data
    public func updatePrivateData(_ data: [String: Any]) async throws -> [String: Any] {
        try await post("/user/session/private-data", body: data)
    }

    /// GET /health
    public func healthCheck() async throws -> [String: Any] {
        try await get("/health")
    }

    /// GET /api/v1/tenants/:id/config
    public func getTenantConfig() async throws -> [String: Any] {
        try await get("/api/v1/tenants/\(tenantId)/config")
    }

    /// POST /v1/evaluate — AuthZEN trust evaluation
    public func evaluateTrust(_ requestBody: [String: Any]) async throws -> [String: Any] {
        try await post("/v1/evaluate", body: requestBody)
    }

    /// POST /user/session/refresh — refresh appToken
    public func refreshSession(refreshToken: String) async throws -> [String: Any] {
        try await post("/user/session/refresh", body: ["refreshToken": refreshToken])
    }

    // MARK: - Wallet Provider endpoints

    /// POST /wallet-provider/key-attestation/generate — request a key attestation JWT.
    /// - Parameters:
    ///   - jwks: Array of JWK dictionaries for the keys to attest.
    ///   - nonce: OpenID4VCI nonce from the issuer.
    ///   - securityProperties: Optional security properties dictionary for KA claims (CS-04 §7.1.3).
    ///   - credentialIssuer: Optional target issuer URL - binds the KA's `aud` claim,
    ///     preventing a KA minted for one issuer from being replayed against another.
    ///   - walletInstanceId: Optional WIA JWK Thumbprint (`cnf.jkt`) identifying this
    ///     wallet instance, sent as `wallet_instance_id` - lets the backend's KA trust
    ///     gate look up this instance's recorded `attestation_source` and lift its
    ///     `security_properties` clamp when it's genuinely native-attested. Omitted
    ///     when nil/empty.
    /// - Returns: Key attestation JWT string.
    public func requestKeyAttestation(
        jwks: [[String: Any]],
        nonce: String,
        securityProperties: [String: Any]? = nil,
        credentialIssuer: String? = nil,
        walletInstanceId: String? = nil
    ) async throws -> String {
        var openid4vci: [String: Any] = ["nonce": nonce]
        if let issuer = credentialIssuer, !issuer.isEmpty {
            openid4vci["credential_issuer"] = issuer
        }
        var body: [String: Any] = [
            "jwks": jwks,
            "openid4vci": openid4vci,
        ]
        if let props = securityProperties {
            body["security_properties"] = props
        }
        // The WIA's JWK-thumbprint identity (`cnf.jkt`) - lets the backend's
        // KA trust gate look up this wallet instance's own recorded
        // attestation_source and lift the K3 clamp when it's genuinely
        // native-attested. Omitted whenever the caller has no such WIA.
        if let id = walletInstanceId, !id.isEmpty {
            body["wallet_instance_id"] = id
        }
        let result = try await post("/wallet-provider/key-attestation/generate", body: body)
        guard let attestation = result["key_attestation"] as? String else {
            throw SirosError.backendApi(code: 0, message: "Missing key_attestation in response", body: "")
        }
        return attestation
    }

    /// POST /wallet-provider/wia/challenge — request a WIA challenge nonce.
    /// - Returns: Dictionary with "challenge" and "expires_at" keys.
    public func requestWIAChallenge() async throws -> [String: Any] {
        try await post("/wallet-provider/wia/challenge", body: [:])
    }

    /// POST /wallet-provider/wia/generate — generate a Wallet Instance Attestation.
    /// - Parameters:
    ///   - pop: WIA-PoP JWT (typ: oauth-client-attestation-pop+jwt).
    ///   - challenge: The challenge nonce from requestWIAChallenge().
    ///   - nativeAttestation: Optional platform attestation evidence.
    /// - Returns: WIA JWT string.
    /// - Parameters:
    ///   - clientId: this wallet's OAuth client_id (e.g. its redirect_uri, per
    ///     OID4VCI's unregistered-client convention) - embedded as the WIA JWT's
    ///     `sub` claim. draft-ietf-oauth-attestation-based-client-auth-10 requires
    ///     "the sub claim MUST specify client_id value of the OAuth Client";
    ///     omitting this falls back to the instance identifier (jkt) server-side.
    ///   - credentialId: base64url WebAuthn credential id of the passkey this
    ///     installation logs in with. The backend records it on the wallet
    ///     instance so that suspending or revoking the instance also refuses
    ///     login with that passkey (SID-AUTH-06, go-wallet-backend#319).
    ///     Optional; older backends ignore it.
    public func generateWIA(
        pop: String,
        challenge: String,
        clientId: String? = nil,
        nativeAttestation: [String: Any]? = nil,
        credentialId: String? = nil
    ) async throws -> String {
        var body: [String: Any] = [
            "pop": pop,
            "challenge": challenge,
        ]
        if let clientId, !clientId.isEmpty {
            body["client_id"] = clientId
        }
        if let native = nativeAttestation {
            body["native_attestation"] = native
        }
        if let credentialId, !credentialId.isEmpty {
            body["credential_id"] = credentialId
        }
        let result = try await post("/wallet-provider/wia/generate", body: body)
        guard let wia = result["wallet_instance_attestation"] as? String else {
            throw SirosError.backendApi(code: 0, message: "Missing wallet_instance_attestation in response", body: "")
        }
        return wia
    }

    /// POST /wallet-provider/fido2-attestation/register — register a FIDO2/CTAP2
    /// hardware-key attestation once, at key-creation time, so the backend can
    /// durably mark the wallet instance as hardware-key-attested (see
    /// `FIDO2AttestationService` in go-wallet-backend). Throws `SirosError.backendApi`
    /// if the backend rejects the attestation (e.g. untrusted AAGUID/chain) or the
    /// feature isn't enabled.
    /// - Parameters:
    ///   - walletInstanceId: The WIA JWK Thumbprint (`cnf.jkt`) this key belongs to.
    ///   - attestationObject: The raw CTAP2 makeCredential attestation object
    ///     (siros-wscd-manager's `AttestationChain.certificates[0]`).
    ///   - clientDataHash: The 32-byte hash the attestation signature was computed
    ///     over (`AttestationChain.clientDataHash`).
    public func registerFido2Attestation(
        walletInstanceId: String,
        attestationObject: Data,
        clientDataHash: Data
    ) async throws {
        let body: [String: Any] = [
            "wallet_instance_id": walletInstanceId,
            "attestation_object": WebAuthnAuthClient.base64UrlEncode(attestationObject),
            "client_data_hash": WebAuthnAuthClient.base64UrlEncode(clientDataHash),
        ]
        _ = try await post("/wallet-provider/fido2-attestation/register", body: body)
    }

    // MARK: - Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319)

    private static let pathInstances = "/user/session/instances"

    /// GET /user/session/instances — this user's wallet instances in the current tenant.
    public func listWalletInstances() async throws -> [WalletInstance] {
        let result = try await get(Self.pathInstances)
        guard let raw = result["instances"] as? [[String: Any]] else {
            // The backend always sends the array (empty when the user has no
            // instances); its absence is a malformed or non-JSON response, not
            // "no instances", so surface it rather than mask it.
            throw SirosError.backendApi(code: 0, message: "Missing instances in response", body: "")
        }
        return raw.compactMap(WalletInstance.init(json:))
    }

    /// PUT /user/session/instances/{id}/status — suspend, reactivate or revoke
    /// one of this user's instances. Throws `SirosError.backendApi` with code
    /// 404 for an instance that is not the caller's and 409 for an invalid
    /// transition (e.g. reactivating a revoked instance).
    ///
    /// Revoking the caller's last instance deactivates the wallet, so this
    /// request runs the same erasure cascade as
    /// `revokeAllWalletInstances(reason:)` and can answer `409
    /// ERASURE_INCOMPLETE`; it is retried here on the same budget. If the
    /// erasure is still unfinished when the budget runs out the recorded
    /// status is returned anyway (it stands - only the cascade is unfinished)
    /// and the residual is logged for an administrator.
    public func setWalletInstanceStatus(instanceId: String, status: WalletInstance.Status, reason: String? = nil) async throws -> WalletInstance {
        var body: [String: Any] = ["status": status.rawValue]
        if let reason, !reason.isEmpty { body["reason"] = reason }
        let attempted = try await retryWhileErasureIncomplete(
            "setWalletInstanceStatus(\(instanceId), \(status.rawValue))"
        ) { () -> WalletInstance in
            let result = try await self.put("\(Self.pathInstances)/\(instanceId)/status", body: body)
            // Today the backend answers {id, status}; decode the whole object
            // when it sends more, so callers see every field it returns.
            if let full = WalletInstance(json: result) {
                return full
            }
            guard let newStatus = (result["status"] as? String).flatMap(WalletInstance.Status.init(rawValue:)) else {
                throw SirosError.backendApi(code: 0, message: "Missing status in response", body: "")
            }
            return WalletInstance(id: result["id"] as? String ?? instanceId, status: newStatus)
        }
        // A 409 that outlived the retries, or a 401 that dropped the acting
        // token with the erased key material, both leave the recorded status
        // standing - report it rather than failing a change that took effect.
        return attempted.value ?? WalletInstance(id: instanceId, status: status)
    }

    /// POST /user/session/instances/revoke-all — deactivate the wallet: every
    /// instance revoked, wallet data erased server-side, new enrollment
    /// required.
    ///
    /// The backend records the revocations before it erases, so it can answer
    /// `409 ERASURE_INCOMPLETE`; repeating the identical request re-runs the
    /// erasure. This does that on the documented budget (five attempts, 1 s →
    /// 8 s) and reports what happened in `DeactivationOutcome.complete`. A
    /// `401` after such a `409` means the acting token was dropped together
    /// with the erased key material, which is the erasure having succeeded -
    /// it counts as complete.
    public func revokeAllWalletInstances(reason: String? = nil) async throws -> DeactivationOutcome {
        var body: [String: Any] = [:]
        if let reason, !reason.isEmpty { body["reason"] = reason }
        // The first attempt reports how many instances it revoked; a repeat
        // answers 0 because there is nothing left to revoke. Keep the largest
        // count seen (the 409 body carries it too) so the caller can tell the
        // user what actually happened.
        let seen = RevokedCounter()
        let attempted = try await retryWhileErasureIncomplete(
            "revokeAllWalletInstances",
            onIncomplete: { error in
                if case let .backendApi(_, _, incompleteBody) = error,
                   let incompleteBody,
                   let data = incompleteBody.data(using: .utf8),
                   let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                   let revoked = json["revoked"] as? Int {
                    seen.record(revoked)
                }
            }
        ) { () -> Int in
            let result = try await self.post("\(Self.pathInstances)/revoke-all", body: body)
            guard let revoked = result["revoked"] as? Int else {
                throw SirosError.backendApi(code: 0, message: "Missing revoked count in response", body: "")
            }
            return revoked
        }
        return DeactivationOutcome(
            revoked: max(seen.value, attempted.value ?? 0),
            complete: attempted.complete
        )
    }

    /// Largest `revoked` count seen across the attempts of one erasure retry.
    private final class RevokedCounter: @unchecked Sendable {
        private let lock = NSLock()
        private var _value = 0
        var value: Int { lock.lock(); defer { lock.unlock() }; return _value }
        func record(_ count: Int) { lock.lock(); _value = max(_value, count); lock.unlock() }
    }

    private struct Attempted<T> {
        let value: T?
        let complete: Bool
    }

    /// Run `request`, repeating it while the backend answers `409
    /// ERASURE_INCOMPLETE` (SID-AUTH-06): the status change is already
    /// recorded, only the erasure cascade needs re-running, and the protocol
    /// says to repeat the identical request until it answers `200`.
    ///
    /// Ends with `complete == false` when the budget runs out, and with
    /// `complete == true, value == nil` on a `401` that follows such a `409` -
    /// that is the acting token being dropped along with the erased key
    /// material, i.e. the erasure got far enough that the wallet is gone. A
    /// `401` on the very first attempt is an ordinary authentication failure
    /// and is rethrown.
    private func retryWhileErasureIncomplete<T>(
        _ what: String,
        onIncomplete: (SirosError) -> Void = { _ in },
        request: () async throws -> T
    ) async throws -> Attempted<T> {
        let attempts = erasureRetryDelays.count + 1
        var sawIncomplete = false
        var lastBody: String?
        for attempt in 0..<attempts {
            if attempt > 0 {
                let seconds = erasureRetryDelays[attempt - 1]
                if seconds > 0 {
                    try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                }
            }
            do {
                return Attempted(value: try await request(), complete: true)
            } catch let error as SirosError {
                guard case let .backendApi(code, _, body) = error else { throw error }
                if code == 409, error.apiErrorCode == errorErasureIncomplete {
                    sawIncomplete = true
                    lastBody = body
                    onIncomplete(error)
                    print("[SirosAuth] \(what): ERASURE_INCOMPLETE (attempt \(attempt + 1)/\(attempts)) — repeating the request")
                } else if code == 401, sawIncomplete {
                    print("[SirosAuth] \(what): acting token dropped with the erased key material — erasure complete")
                    return Attempted(value: nil, complete: true)
                } else {
                    throw error
                }
            }
        }
        print("""
            [SirosAuth] \(what): still ERASURE_INCOMPLETE after \(attempts) attempts — the status change \
            stands, residual data must be cleaned up by an administrator: \(lastBody ?? "")
            """)
        return Attempted(value: nil, complete: false)
    }

    // MARK: - HTTP primitives

    private func put(_ path: String, body: [String: Any]) async throws -> [String: Any] {
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        let data = try await request("PUT", path: path, body: bodyData)
        return try parseJsonObject(data)
    }

    private func get(_ path: String) async throws -> [String: Any] {
        let data = try await request("GET", path: path)
        return try parseJsonObject(data)
    }

    private func getRaw(_ path: String) async throws -> Any {
        let data = try await request("GET", path: path)
        return try JSONSerialization.jsonObject(with: data)
    }

    private func post(_ path: String, body: [String: Any]) async throws -> [String: Any] {
        let bodyData = try JSONSerialization.data(withJSONObject: body)
        let data = try await request("POST", path: path, body: bodyData)
        return try parseJsonObject(data)
    }

    private func delete(_ path: String) async throws -> [String: Any] {
        let data = try await request("DELETE", path: path)
        return try parseJsonObject(data)
    }

    private func request(_ method: String, path: String, body: Data? = nil) async throws -> Data {
        guard let url = URL(string: "\(baseUrl)\(path)") else {
            throw SirosError.network(message: "Invalid URL: \(baseUrl)\(path)")
        }
        var headers: [String: String] = [
            "X-Tenant-ID": tenantId,
            "Content-Type": "application/json",
        ]
        let tokens = currentAuthTokens()
        if let tokens {
            let token = try await tokens.ensureBackendToken()
            headers["Authorization"] = "Bearer \(token.raw)"
        } else if let token = currentAppToken() {
            headers["Authorization"] = "Bearer \(token)"
        }
        do {
            return try await httpFn(method, url, headers, body)
        } catch {
            // A 401 here means the backend token itself was rejected (expired/
            // revoked/session invalidated server-side) - `AuthTokens.
            // registerTokenRejection` was previously never called from
            // anywhere (dead code), so repeated silent 401s never triggered
            // `onSessionRejected`/a forced logout, leaving a stale session
            // looking "connected" indefinitely. Only applies to the
            // `AuthTokens`-managed path: the legacy bare `appToken` path has
            // no `AuthTokens` instance to register against.
            if let tokens, case let SirosError.backendApi(code, _, _) = error, code == 401 {
                tokens.registerTokenRejection(AuthTokens.tokenBackend)
            }
            throw error
        }
    }

    private func currentAppToken() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return _appToken
    }

    private func currentAuthTokens() -> AuthTokens? {
        lock.lock()
        defer { lock.unlock() }
        return _authTokens
    }

    private func parseJsonObject(_ data: Data) throws -> [String: Any] {
        if data.isEmpty {
            return [:]
        }
        guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return [:]
        }
        return json
    }
}
