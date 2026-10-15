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

    /// `resolveDid` is `resolveKey` plus extracting `context.trust_metadata`
    /// for callers (DIIP's `DidResolutionDelegate`) that just want the
    /// document, not the raw AuthZEN envelope.
    func testResolveDidReturnsDocumentWhenDecisionIsTrue() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"decision":true,"context":{"trust_metadata":{"id":"did:web:issuer.example.com"}}}"#)
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")

        let document = try await client.resolveDid("did:web:issuer.example.com")

        XCTAssertEqual(document?["id"] as? String, "did:web:issuer.example.com")
    }

    /// Regression (mirrors `resolveDidKeyMaterial`'s own fail-closed check,
    /// see `SirosWalletTrustResolutionTests.testHandleTrustEvaluationFailsClosedWhenResolveDecisionIsNotTrue`):
    /// `/v1/resolve` is itself an AuthZEN evaluation, and `context` is
    /// populated independently of `decision` - a denied response can still
    /// carry a `trust_metadata` document. `resolveDid` must not hand that
    /// document to a caller (DIIP's `DidResolver`) that has no other
    /// decision check of its own, or an unauthorized subject's DID document
    /// would be trusted exactly as if go-trust had approved it.
    func testResolveDidReturnsNilWhenDecisionIsNotTrue() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"decision":false,"context":{"trust_metadata":{"id":"did:web:issuer.example.com"}}}"#)
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")

        let document = try await client.resolveDid("did:web:issuer.example.com")

        XCTAssertNil(document, "a denied resolution must never be treated as a resolved DID document")
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

    // MARK: - Account deletion (go-wallet-backend#352)

    private static let beginBody = #"{"challengeId":"ch-1","publicKey":{"challenge":{"$b64u":"AQID"},"rpId":"wallet.example.com","userVerification":"required","allowCredentials":[{"type":"public-key","id":{"$b64u":"cGstMQ"},"transports":["internal"]}]}}"#

    private func deletingClient(_ server: MockHttpServer) -> BackendApiClient {
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")
        return client
    }

    private func delete(_ server: MockHttpServer) async throws -> AccountDeletionResponse {
        try await deletingClient(server).deleteAccount(
            challengeId: "ch-1", credential: ["id": "pk-1", "type": "public-key"], confirm: "DELETE"
        )
    }

    func testDeleteAccountBeginPostsAndDecodesTheAssertionOptions() async throws {
        let server = MockHttpServer()
        server.enqueue(Self.beginBody)

        let challenge = try await deletingClient(server).deleteAccountBegin()

        XCTAssertEqual(server.requests[0].method, "POST")
        XCTAssertEqual(server.requests[0].path, "/user/session/delete-begin")
        XCTAssertEqual(challenge.challengeId, "ch-1")
        XCTAssertEqual(challenge.rpId, "wallet.example.com")
        XCTAssertEqual(challenge.challenge, Data([1, 2, 3]))
        XCTAssertEqual(challenge.userVerification, "required")
        XCTAssertEqual(challenge.allowCredentials.map(\.id), [Data("pk-1".utf8)])
    }

    func testDeleteAccountBeginRejectsAResponseWithoutAChallenge() async throws {
        for body in [
            #"{"publicKey":{"challenge":{"$b64u":"AQID"},"rpId":"x"}}"#,
            #"{"challengeId":"c","publicKey":{"rpId":"x"}}"#,
            #"{"challengeId":"c","publicKey":{"challenge":{"$b64u":"AQID"}}}"#,
            #"{"challengeId":"c"}"#,
        ] {
            let server = MockHttpServer()
            server.enqueue(body)
            do {
                _ = try await deletingClient(server).deleteAccountBegin()
                XCTFail("must not accept \(body)")
            } catch SirosError.backendApi(let code, _, _) {
                XCTAssertEqual(code, 0)
            }
        }
    }

    func testDeleteAccountSendsTheStepUpAssertionAndConfirmationAsJson() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"result":"DELETED"}"#)

        let response = try await delete(server)

        XCTAssertEqual(response, .deleted)
        XCTAssertEqual(server.requests[0].method, "DELETE")
        XCTAssertEqual(server.requests[0].path, "/user/session")
        let body = try bodyJSON(server.requests[0])
        XCTAssertEqual(body["challengeId"] as? String, "ch-1")
        XCTAssertEqual(body["confirm"] as? String, "DELETE")
        XCTAssertEqual((body["credential"] as? [String: Any])?["id"] as? String, "pk-1")
        XCTAssertEqual(server.requests[0].headers["Authorization"], "Bearer t")
    }

    func testDeleteAccountMaps202CleanupPending() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"error":"DELETION_CLEANUP_PENDING","result":"DELETED","message":"m"}"#)
        let response = try await delete(server)
        XCTAssertEqual(response, .cleanupPending)
    }

    func testDeleteAccountMaps202OperatorRequired() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"error":"DELETION_OPERATOR_REQUIRED","result":"PENDING","message":"m"}"#)
        let response = try await delete(server)
        XCTAssertEqual(response, .operatorRequired)
    }

    func testDeleteAccountMaps409IncompleteAndCarriesTheServerMessage() async throws {
        let server = MockHttpServer()
        server.enqueueFailure(code: 409, body: #"{"error":"DELETION_INCOMPLETE","message":"try again"}"#)
        let response = try await delete(server)
        XCTAssertEqual(response, .incomplete(message: "try again"))
    }

    func testDeleteAccountMapsTheStepUpAndConfirmationErrors() async throws {
        let cases: [(Int, String, AccountDeletionResponse)] = [
            (401, #"{"error":"STEP_UP_REQUIRED"}"#, .stepUpRequired),
            (401, #"{"error":"STEP_UP_FAILED"}"#, .stepUpFailed),
            (410, #"{"error":"STEP_UP_EXPIRED"}"#, .stepUpExpired),
            (400, #"{"error":"CONFIRMATION_REQUIRED"}"#, .confirmationRequired),
            (401, #"{"error":"Unauthorized"}"#, .sessionRejected),
            (401, "", .sessionRejected),
            (404, #"{"error":"User not found"}"#, .accountNotFound),
        ]
        for (code, body, expected) in cases {
            let server = MockHttpServer()
            server.enqueueFailure(code: code, body: body)
            let response = try await delete(server)
            XCTAssertEqual(response, expected, "\(code) \(body)")
        }
    }

    /// Outside the contract the client throws instead of guessing: a 409 that
    /// is not DELETION_INCOMPLETE, a plain 400, a 5xx, and a 2xx that names
    /// neither outcome.
    func testDeleteAccountThrowsForResponsesOutsideTheContract() async throws {
        for (code, body) in [(409, #"{"error":"other"}"#), (400, #"{"error":"bad json"}"#), (500, "")] {
            let server = MockHttpServer()
            server.enqueueFailure(code: code, body: body)
            do {
                _ = try await delete(server)
                XCTFail("\(code) must throw")
            } catch SirosError.backendApi(let thrown, _, _) {
                XCTAssertEqual(thrown, code)
            }
        }
        let server = MockHttpServer()
        server.enqueue("{}")
        do {
            _ = try await delete(server)
            XCTFail("an unrecognised 2xx must not read as deleted")
        } catch SirosError.backendApi(let code, _, _) {
            XCTAssertEqual(code, 0)
        }
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

    /// A step-up 401 says the assertion was bad, not the session token: three
    /// of them must not trigger the forced logout a rejected token does,
    /// while three plain 401s still must.
    func testStepUp401sDoNotRegisterTokenRejectionButPlain401sDo() async throws {
        for (body, expected) in [(#"{"error":"STEP_UP_FAILED"}"#, 0), (#"{"error":"STEP_UP_REQUIRED"}"#, 0), (#"{"error":"Unauthorized"}"#, 1)] {
            let tokens = makeAuthTokens()
            var rejectedCount = 0
            tokens.onSessionRejected = { rejectedCount += 1 }
            let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: { _, _, _, _ in
                throw SirosError.backendApi(code: 401, message: "unauthorized", body: body)
            })
            client.setAuthTokens(tokens)
            for _ in 0..<3 {
                _ = try? await client.deleteAccount(challengeId: "c", credential: [:], confirm: "DELETE")
            }
            XCTAssertEqual(rejectedCount, expected, body)
        }
    }

    /// Same for the add-passkey `register-finish`: a refused authorising
    /// assertion is not a rejected session token.
    func testEnrollmentAuthorization401sDoNotRegisterTokenRejectionButPlain401sDo() async throws {
        for (body, expected) in [
            (#"{"error":"ENROLLMENT_AUTHORIZATION_FAILED"}"#, 0),
            (#"{"error":"ENROLLMENT_AUTHORIZATION_REQUIRED"}"#, 0),
            (#"{"error":"Unauthorized"}"#, 1),
        ] {
            let tokens = makeAuthTokens()
            var rejectedCount = 0
            tokens.onSessionRejected = { rejectedCount += 1 }
            let client = BackendApiClient(baseUrl: "https://api.example.com", httpFn: { _, _, _, _ in
                throw SirosError.backendApi(code: 401, message: "unauthorized", body: body)
            })
            client.setAuthTokens(tokens)
            for _ in 0..<3 {
                _ = try? await client.passkeyRegisterFinish(
                    challengeId: "c",
                    credential: RegisterResult(credentialId: Data([1]), attestationObject: Data(), clientDataJSON: Data()),
                    nickname: "n", privateData: nil, authorization: nil
                )
            }
            XCTAssertEqual(rejectedCount, expected, body)
        }
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
