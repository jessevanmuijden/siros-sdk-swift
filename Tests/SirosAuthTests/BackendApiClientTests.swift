// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosAuth

final class BackendApiClientTests: XCTestCase {

    func testGetAccountInfoSendsExpectedHeaders() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("token-abc")

        let _ = try await client.getAccountInfo()

        XCTAssertEqual(server.requests.count, 1)
        let req = server.requests[0]
        XCTAssertEqual(req.path, "/user/session/account-info")
        XCTAssertEqual(req.method, "GET")
        XCTAssertEqual(req.headers["X-Tenant-ID"], "default")
        XCTAssertEqual(req.headers["Authorization"], "Bearer token-abc")
    }

    // MARK: - DID key resolution (go-wallet-backend#396/#401, this SDK's #168)

    /// `subject_type: "key"` is the core distinction from `resolveIssuer`'s
    /// `subject_type: "url"` - the two must never be confused.
    func testResolveKeyPostsKeySubjectTypeToResolveEndpoint() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"context\":{}}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("token-resolve")

        _ = try await client.resolveKey(subjectId: "did:web:verifier.example.com")

        XCTAssertEqual(server.requests.count, 1)
        let req = server.requests[0]
        XCTAssertEqual(req.path, "/v1/resolve")
        XCTAssertEqual(req.method, "POST")
        XCTAssertEqual(req.headers["Authorization"], "Bearer token-resolve")
        let body = try bodyJSON(req)
        XCTAssertEqual(body["subject_id"] as? String, "did:web:verifier.example.com")
        XCTAssertEqual(body["subject_type"] as? String, "key")
    }

    // MARK: - Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319)

    private func bodyJSON(_ req: MockHttpServer.RecordedRequest) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(req.body)) as? [String: Any])
    }

    func testGenerateWIASendsCredentialIdOnlyWhenGiven() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"wallet_instance_attestation":"wia.jwt"}"#)
        server.enqueue(#"{"wallet_instance_attestation":"wia.jwt"}"#)
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")

        _ = try await client.generateWIA(pop: "pop.jwt", challenge: "c-1", clientId: "siros://cb", credentialId: "pk-1")
        _ = try await client.generateWIA(pop: "pop.jwt", challenge: "c-2")

        XCTAssertEqual(try bodyJSON(server.requests[0])["credential_id"] as? String, "pk-1")
        XCTAssertNil(try bodyJSON(server.requests[1])["credential_id"])
    }

    func testListWalletInstancesDecodesBackendShape() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"instances":[{"id":"jkt-1","tenant_id":"default","user_id":"u1","status":"suspended","wscd_type":"native_ios","credential_id":"pk-1","attestation_source":"app_attest","last_attested_at":"2026-09-08T10:00:00Z","status_reason":"lost phone","unknown_member":1},{"id":"bad","status":"weird"}]}"#)
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")

        let instances = try await client.listWalletInstances()

        XCTAssertEqual(server.requests[0].method, "GET")
        XCTAssertEqual(server.requests[0].path, "/user/session/instances")
        XCTAssertEqual(instances.count, 1, "an entry with an unknown status is skipped, not fatal")
        XCTAssertEqual(instances[0].id, "jkt-1")
        XCTAssertEqual(instances[0].status, .suspended)
        XCTAssertEqual(instances[0].credentialId, "pk-1")
        XCTAssertEqual(instances[0].statusReason, "lost phone")
    }

    func testListWalletInstancesFailsOnMalformedResponse() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"unexpected":true}"#)
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")
        do {
            _ = try await client.listWalletInstances()
            XCTFail("a response without the instances array must not read as 'no instances'")
        } catch SirosError.backendApi(_, let message, _) {
            XCTAssertTrue(message.contains("instances"))
        }
    }

    func testSetWalletInstanceStatusDecodesFullObjectWhenReturned() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"id":"jkt-1","tenant_id":"default","status":"revoked","wscd_type":"native_ios","credential_id":"pk-1","status_reason":"stolen"}"#)
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")

        let result = try await client.setWalletInstanceStatus(instanceId: "jkt-1", status: .revoked, reason: "stolen")

        XCTAssertEqual(result.status, .revoked)
        XCTAssertEqual(result.credentialId, "pk-1")
        XCTAssertEqual(result.statusReason, "stolen")
    }

    func testSetWalletInstanceStatusPutsStatusAndReason() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"id":"jkt-1","status":"suspended"}"#)
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")

        let result = try await client.setWalletInstanceStatus(instanceId: "jkt-1", status: .suspended, reason: "lost phone")

        XCTAssertEqual(server.requests[0].method, "PUT")
        XCTAssertEqual(server.requests[0].path, "/user/session/instances/jkt-1/status")
        let body = try bodyJSON(server.requests[0])
        XCTAssertEqual(body["status"] as? String, "suspended")
        XCTAssertEqual(body["reason"] as? String, "lost phone")
        XCTAssertEqual(result.status, .suspended)
    }

    func testRevokeAllWalletInstancesFailsOnMalformedResponse() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"ok":true}"#)
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")
        do {
            _ = try await client.revokeAllWalletInstances()
            XCTFail("a reply without the revoked count must not read as zero revoked")
        } catch SirosError.backendApi(_, let message, _) {
            XCTAssertTrue(message.contains("revoked"))
        }
    }

    func testRevokeAllWalletInstancesPostsAndReturnsCount() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"revoked":2}"#)
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")

        let outcome = try await client.revokeAllWalletInstances(reason: "device stolen")

        XCTAssertEqual(server.requests[0].method, "POST")
        XCTAssertEqual(server.requests[0].path, "/user/session/instances/revoke-all")
        XCTAssertEqual(try bodyJSON(server.requests[0])["reason"] as? String, "device stolen")
        XCTAssertEqual(outcome, DeactivationOutcome(revoked: 2, complete: true))
    }

    // MARK: - 409 ERASURE_INCOMPLETE retry protocol (SID-AUTH-06)

    /// No waiting between erasure retries in tests; the production default is
    /// 1 s → 8 s (see `BackendApiClient.erasureRetryDelays`).
    private func retryingClient(_ server: MockHttpServer) -> BackendApiClient {
        let client = BackendApiClient(
            baseUrl: "https://api.example.com",
            tenantId: "default",
            erasureRetryDelays: [0, 0, 0, 0],
            httpFn: server.httpFunction
        )
        client.setAppToken("t")
        return client
    }

    /// The backend records the revocations before it erases, so a 409 means
    /// "the status stands, re-run the erasure" - the client repeats the
    /// identical request until it gets a 200. The repeat answers
    /// `{"revoked": 0}` (nothing left to revoke), so the count reported to the
    /// caller must be the one from the first answer, not the last.
    func testRevokeAllRepeatsTheRequestUntilTheErasureCompletes() async throws {
        let server = MockHttpServer()
        server.enqueueFailure(code: 409, body: #"{"error":"ERASURE_INCOMPLETE","revoked":2}"#)
        server.enqueue(#"{"revoked":0}"#)
        let client = retryingClient(server)

        let outcome = try await client.revokeAllWalletInstances(reason: "device stolen")

        XCTAssertEqual(server.requests.count, 2)
        // "repeating the identical request re-runs the erasure" - same body.
        XCTAssertEqual(server.requests[0].path, server.requests[1].path)
        XCTAssertEqual(server.requests[0].body, server.requests[1].body)
        XCTAssertEqual(outcome, DeactivationOutcome(revoked: 2, complete: true))
    }

    /// Five attempts, then stop: the wallet is deactivated either way, so the
    /// caller is told the erasure is unfinished (residual data for an
    /// administrator) rather than being handed an error for a change that did
    /// take effect.
    func testRevokeAllReportsIncompleteAfterTheRetryBudget() async throws {
        let server = MockHttpServer()
        for _ in 0..<5 {
            server.enqueueFailure(code: 409, body: #"{"error":"ERASURE_INCOMPLETE","revoked":2}"#)
        }
        let client = retryingClient(server)

        let outcome = try await client.revokeAllWalletInstances()

        XCTAssertEqual(server.requests.count, 5)
        XCTAssertEqual(outcome, DeactivationOutcome(revoked: 2, complete: false))
    }

    /// The acting token's exemption from the lifecycle cut-off ends with the
    /// key material. A 401 after a 409 is therefore the erasure having reached
    /// the keys - the wallet is deactivated, which is exactly "complete".
    func testRevokeAllTreatsA401AfterThe409AsACompletedErasure() async throws {
        let server = MockHttpServer()
        server.enqueueFailure(code: 409, body: #"{"error":"ERASURE_INCOMPLETE","revoked":3}"#)
        server.enqueueFailure(code: 401, body: #"{"error":"unauthorized"}"#)
        let client = retryingClient(server)

        let outcome = try await client.revokeAllWalletInstances()

        XCTAssertEqual(server.requests.count, 2)
        XCTAssertEqual(outcome, DeactivationOutcome(revoked: 3, complete: true))
    }

    /// A 401 that was never preceded by a 409 is an ordinary auth failure.
    func testRevokeAllStillFailsOnAPlain401() async throws {
        let server = MockHttpServer()
        server.enqueueFailure(code: 401, body: #"{"error":"unauthorized"}"#)
        let client = retryingClient(server)

        do {
            _ = try await client.revokeAllWalletInstances()
            XCTFail("a 401 with no preceding ERASURE_INCOMPLETE must not read as a completed erasure")
        } catch SirosError.backendApi(let code, _, _) {
            XCTAssertEqual(code, 401)
        }
        XCTAssertEqual(server.requests.count, 1)
    }

    /// A 409 that is not ERASURE_INCOMPLETE (invalid transition) is not retried.
    func testSetWalletInstanceStatusDoesNotRetryAnInvalidTransition() async throws {
        let server = MockHttpServer()
        server.enqueueFailure(code: 409, body: #"{"error":"invalid status transition"}"#)
        let client = retryingClient(server)

        do {
            _ = try await client.setWalletInstanceStatus(instanceId: "jkt-1", status: .active)
            XCTFail("an invalid transition must surface, not be retried")
        } catch SirosError.backendApi(let code, _, _) {
            XCTAssertEqual(code, 409)
        }
        XCTAssertEqual(server.requests.count, 1)
    }

    /// Revoking the last instance runs the same erasure cascade, so the status
    /// write retries on the same budget and reports the status that was
    /// recorded even when the cascade never finished.
    func testSetWalletInstanceStatusRetriesTheErasureAndKeepsTheRecordedStatus() async throws {
        let server = MockHttpServer()
        for _ in 0..<5 {
            server.enqueueFailure(code: 409, body: #"{"error":"ERASURE_INCOMPLETE","id":"jkt-1","status":"revoked"}"#)
        }
        let client = retryingClient(server)

        let result = try await client.setWalletInstanceStatus(instanceId: "jkt-1", status: .revoked, reason: "stolen")

        XCTAssertEqual(server.requests.count, 5)
        XCTAssertEqual(result.id, "jkt-1")
        XCTAssertEqual(result.status, .revoked)
    }

    func testUnauthenticatedRequestOmitsAuthorizationHeader() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.healthCheck()

        XCTAssertEqual(server.requests[0].path, "/health")
        XCTAssertNil(server.requests[0].headers["Authorization"])
    }

    func testGetIssuersAcceptsArrayPayload() async throws {
        let server = MockHttpServer()
        server.enqueue("[{\"id\": 1, \"visible\": true}]")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let issuers = try await client.getIssuers()
        XCTAssertTrue(issuers is [Any])
    }

    func testUpdatePrivateDataPostsJsonBody() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)
        client.setAppToken("token-xyz")

        let _ = try await client.updatePrivateData(["privateData": "opaque"])

        XCTAssertEqual(server.requests[0].path, "/user/session/private-data")
        XCTAssertEqual(server.requests[0].method, "POST")
        if let body = server.requests[0].body {
            let bodyStr = String(data: body, encoding: .utf8) ?? ""
            XCTAssertTrue(bodyStr.contains("privateData"))
        }
    }

    func testRequestKeyAttestationSendsJwksNonceAndCredentialIssuer() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"key_attestation\": \"signed-jwt\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let result = try await client.requestKeyAttestation(
            jwks: [["kty": "EC"]],
            nonce: "nonce-1",
            securityProperties: ["key_storage": ["iso_18045_high"]],
            credentialIssuer: "https://issuer.example.com"
        )

        XCTAssertEqual(result, "signed-jwt")
        let req = server.requests[0]
        XCTAssertEqual(req.path, "/wallet-provider/key-attestation/generate")
        let body = try XCTUnwrap(req.body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let jwks = try XCTUnwrap(json["jwks"] as? [[String: Any]])
        XCTAssertEqual(jwks.count, 1)
        let openid4vci = try XCTUnwrap(json["openid4vci"] as? [String: Any])
        XCTAssertEqual(openid4vci["nonce"] as? String, "nonce-1")
        XCTAssertEqual(openid4vci["credential_issuer"] as? String, "https://issuer.example.com")
        let securityProperties = try XCTUnwrap(json["security_properties"] as? [String: Any])
        XCTAssertEqual(securityProperties["key_storage"] as? [String], ["iso_18045_high"])
    }

    func testRequestKeyAttestationOmitsCredentialIssuerWhenNotProvided() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"key_attestation\": \"signed-jwt\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.requestKeyAttestation(jwks: [["kty": "EC"]], nonce: "nonce-1")

        let body = try XCTUnwrap(server.requests[0].body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        let openid4vci = try XCTUnwrap(json["openid4vci"] as? [String: Any])
        XCTAssertNil(openid4vci["credential_issuer"])
    }

    func testRequestKeyAttestationSendsWalletInstanceIdWhenProvided() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"key_attestation\": \"signed-jwt\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.requestKeyAttestation(
            jwks: [["kty": "EC"]],
            nonce: "nonce-1",
            walletInstanceId: "test-jkt"
        )

        let body = try XCTUnwrap(server.requests[0].body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["wallet_instance_id"] as? String, "test-jkt")
    }

    func testRequestKeyAttestationOmitsWalletInstanceIdWhenNotProvided() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"key_attestation\": \"signed-jwt\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.requestKeyAttestation(jwks: [["kty": "EC"]], nonce: "nonce-1")

        let body = try XCTUnwrap(server.requests[0].body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertNil(json["wallet_instance_id"])
    }

    func testRegisterFido2AttestationSendsExpectedFields() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"verified\": true}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        try await client.registerFido2Attestation(
            walletInstanceId: "test-jkt",
            attestationObject: Data([0x01, 0x02, 0x03]),
            clientDataHash: Data(repeating: 0x09, count: 32)
        )

        let req = server.requests[0]
        XCTAssertEqual(req.path, "/wallet-provider/fido2-attestation/register")
        XCTAssertEqual(req.method, "POST")
        let body = try XCTUnwrap(req.body)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
        XCTAssertEqual(json["wallet_instance_id"] as? String, "test-jkt")
        XCTAssertEqual(
            json["attestation_object"] as? String,
            WebAuthnAuthClient.base64UrlEncode(Data([0x01, 0x02, 0x03]))
        )
        XCTAssertEqual(
            json["client_data_hash"] as? String,
            WebAuthnAuthClient.base64UrlEncode(Data(repeating: 0x09, count: 32))
        )
    }

    func testEvaluateTrustPostsToExpectedEndpoint() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"decision\":true}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)
        client.setAppToken("token-trust")

        let response = try await client.evaluateTrust(["subject": "issuer-123"])

        XCTAssertEqual(server.requests[0].path, "/v1/evaluate")
        XCTAssertEqual(server.requests[0].method, "POST")
        XCTAssertEqual(server.requests[0].headers["Authorization"], "Bearer token-trust")
    }

    func testDeleteCredentialUsesDeleteMethod() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let _ = try await client.deleteCredential(id: "cred-42")

        XCTAssertEqual(server.requests[0].path, "/storage/vc/cred-42")
        XCTAssertEqual(server.requests[0].method, "DELETE")
    }

    func testTenantConfigUsesTenantSpecificPath() async throws {
        let server = MockHttpServer()
        server.enqueue("{}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "tenant-42", httpFn: server.httpFunction)

        let _ = try await client.getTenantConfig()

        XCTAssertEqual(server.requests[0].path, "/api/v1/tenants/tenant-42/config")
        XCTAssertEqual(server.requests[0].headers["X-Tenant-ID"], "tenant-42")
    }

    func testBlankSuccessBodyReturnsEmptyJsonObject() async throws {
        let server = MockHttpServer()
        server.enqueueData(Data())
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let response = try await client.healthCheck()
        XCTAssertTrue(response.isEmpty)
    }

    func testRefreshSessionPostsRefreshToken() async throws {
        let server = MockHttpServer()
        server.enqueue("{\"appToken\":\"new-token\"}")
        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: server.httpFunction)

        let response = try await client.refreshSession(refreshToken: "refresh-abc")

        XCTAssertEqual(server.requests[0].path, "/user/session/refresh")
        XCTAssertEqual(server.requests[0].method, "POST")
        if let body = server.requests[0].body {
            let bodyStr = String(data: body, encoding: .utf8) ?? ""
            XCTAssertTrue(bodyStr.contains("refresh-abc"))
        }
    }

    // MARK: - registerTokenRejection wiring (401 responses)
    //
    // Regression coverage for `request(_:path:body:)`'s previously-missing
    // call into `AuthTokens.registerTokenRejection` on a 401 - see
    // `AuthTokensTests.swift`'s doc comment for the full bug history.

    private func buildJwt(_ payload: String) -> String {
        let header = Data(#"{"alg":"RS256","typ":"JWT"}"#.utf8).base64URLEncoded
        let body = Data(payload.utf8).base64URLEncoded
        let sig = Data("fake".utf8).base64URLEncoded
        return "\(header).\(body).\(sig)"
    }

    /// `AuthTokens` backed by an `AuthServerClient` that always successfully
    /// mints the same (long-lived) backend token - isolates these tests to
    /// exercise only `BackendApiClient.request`'s own 401-handling, not
    /// token-minting itself.
    private func makeAuthTokens() -> AuthTokens {
        let exp = Int(Date().timeIntervalSince1970) + 3600
        let jwt = buildJwt(#"{"sub":"u","aud":"wallet-backend","tenant_id":"default","tac":"rwlid","exp":\#(exp)}"#)
        let authClient = AuthServerClient(baseUrl: "https://auth.example.com", tenantId: "default") { _, _, _, _ in
            try! JSONSerialization.data(withJSONObject: ["access_token": jwt, "token_type": "Bearer", "expires_in": 3600])
        }
        return AuthTokens(authServerClient: authClient, tenantId: "default")
    }

    func testRepeatedFourOhOneResponsesRegisterTokenRejection() async throws {
        let tokens = makeAuthTokens()
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: { _, _, _, _ in
            throw SirosError.backendApi(code: 401, message: "unauthorized", body: nil)
        })
        client.setAuthTokens(tokens)

        for _ in 0..<3 {
            do {
                _ = try await client.getAccountInfo()
                XCTFail("expected the 401 to propagate")
            } catch SirosError.backendApi(let code, _, _) {
                XCTAssertEqual(code, 401)
            }
        }

        XCTAssertEqual(rejectedCount, 1, "3 rejections within the window must trigger onSessionRejected exactly once")
    }

    func testNonFourOhOneErrorsDoNotRegisterTokenRejection() async throws {
        let tokens = makeAuthTokens()
        var rejectedCount = 0
        tokens.onSessionRejected = { rejectedCount += 1 }

        let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: { _, _, _, _ in
            throw SirosError.backendApi(code: 500, message: "server error", body: nil)
        })
        client.setAuthTokens(tokens)

        for _ in 0..<5 {
            _ = try? await client.getAccountInfo()
        }

        XCTAssertEqual(rejectedCount, 0, "a 500 is a server problem, not evidence the token itself was rejected")
    }
}

private extension Data {
    var base64URLEncoded: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
