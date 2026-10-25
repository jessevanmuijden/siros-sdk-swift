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

    /// Create a client with a custom HTTP function (for testing).
    public init(
        baseUrl: String,
        tenantId: String = "default",
        httpFn: @escaping HttpFunction
    ) {
        self.baseUrl = baseUrl
        self.tenantId = tenantId
        self.httpFn = httpFn
    }

    #if !os(Linux)
    /// Create a client using URLSession for HTTP.
    public convenience init(
        baseUrl: String,
        tenantId: String = "default"
    ) {
        self.init(baseUrl: baseUrl, tenantId: tenantId) { method, url, headers, body in
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

    /// Resolve a DID to its DID document, for callers - `Did.swift`'s
    /// `DidResolutionDelegate`, which `SirosWallet` backs with this - that
    /// just want the document rather than the raw AuthZEN envelope
    /// `resolveKey` returns.
    ///
    /// DID method resolution is a trust decision: which document is
    /// authoritative for an identifier. That belongs to the deployment's
    /// trust registry, not to each wallet's own idea of which hosts to
    /// believe, so the wallet asks rather than fetches. `did:jwk` is the one
    /// exception and never gets here - it carries its own key and resolves
    /// offline (see `DidResolver.resolve`).
    ///
    /// Built on `resolveKey`, not a second `/v1/resolve` call: `/v1/resolve`
    /// is itself an AuthZEN evaluation, not a plain lookup, so a denied
    /// response (`decision: false`) can still carry `trust_metadata`
    /// (`context` is populated independently of the decision) - skipping
    /// this check would extract and use a denied subject's key material,
    /// exactly the gap `resolveDidKeyMaterial` closes for the verifier path.
    /// go-wallet-backend's own ResolveDID path rejects `decision == false`
    /// the same way.
    ///
    /// - Returns: the DID document, or nil if the backend could not resolve
    ///   it, or the resolution was not explicitly decided `true`.
    public func resolveDid(_ did: String) async throws -> [String: Any]? {
        let response = try await resolveKey(subjectId: did)
        guard response["decision"] as? Bool == true,
              let context = response["context"] as? [String: Any],
              let document = context["trust_metadata"] as? [String: Any],
              document["id"] != nil
        else { return nil }
        return document
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

    // MARK: - Account deletion (go-wallet-backend#352)

    /// POST /user/session/delete-begin - start the step-up for deleting the
    /// account: returns the single-use challenge and the WebAuthn assertion
    /// options for the caller's own passkeys (`400 NO_PASSKEY` when the
    /// account has none, `403` when the token lacks the `w` scope, both thrown
    /// as `SirosError.backendApi`). The assertion must be sent to
    /// `deleteAccount(challengeId:credential:confirm:)` within 2 minutes.
    public func deleteAccountBegin() async throws -> AccountDeletionChallenge {
        // Same `{"$b64u": ...}` binary encoding as the login options.
        let result = TaggedBinary.decode(try await post("/user/session/delete-begin", body: [:]))
        return try AccountDeletionChallenge(json: result)
    }

    /// DELETE /user/session - delete the account, authorised by the passkey
    /// assertion for `challengeId` and the typed confirmation (`"DELETE"`).
    ///
    /// Every outcome the backend defines is an `AccountDeletionResponse`; this
    /// throws only for transport failures and responses outside the contract.
    /// A `401` carrying a step-up code does not count against the session
    /// token (see `request`): the token is fine, the assertion was not.
    public func deleteAccount(
        challengeId: String,
        credential: [String: Any],
        confirm: String
    ) async throws -> AccountDeletionResponse {
        let body: [String: Any] = [
            "challengeId": challengeId,
            "credential": credential,
            "confirm": confirm,
        ]
        let data: Data
        do {
            data = try await request(
                "DELETE", path: "/user/session",
                body: try JSONSerialization.data(withJSONObject: body),
                tokenStillValidOn: Self.stepUpErrorCodes
            )
        } catch let error as SirosError {
            if let mapped = AccountDeletionResponse(failure: error) { return mapped }
            throw error
        }
        guard let response = AccountDeletionResponse(success: try parseJsonObject(data)) else {
            throw SirosError.backendApi(code: 0, message: "Unrecognised delete-account response", body: String(data: data, encoding: .utf8))
        }
        return response
    }

    private static let stepUpErrorCodes: Set<String> = [errorStepUpRequired, errorStepUpFailed]

    // MARK: - HTTP primitives

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

    /// - Parameter tokenStillValidOn: `401` error codes that say something
    ///   other than "the token is rejected", so they are not registered as a
    ///   token rejection.
    private func request(
        _ method: String,
        path: String,
        body: Data? = nil,
        tokenStillValidOn: Set<String> = []
    ) async throws -> Data {
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
            if let tokens, case let SirosError.backendApi(code, _, _) = error, code == 401,
               !((error as? SirosError)?.apiErrorCode.map(tokenStillValidOn.contains) ?? false) {
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
