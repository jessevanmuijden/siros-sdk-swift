// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
import SirosCredentials
@testable import SirosAuth

/// `BackendApiClient.passkeyRegisterBegin/Finish` (go-wallet-backend#352).
final class PasskeyEnrollmentClientTests: XCTestCase {

    private static let createOptions = #""createOptions":{"publicKey":{"rp":{"id":"wallet.example.com","name":"Wallet"},"user":{"id":{"$b64u":"dXNlcg"},"name":"alice","displayName":"Alice"},"challenge":{"$b64u":"AQID"}}}"#
    private static let authorization = #""authorization":{"publicKey":{"rpId":"wallet.example.com","challenge":{"$b64u":"BAUG"},"allowCredentials":[{"type":"public-key","id":{"$b64u":"cGstMQ"}}],"userVerification":"required"}}"#

    private func client(_ server: MockHttpServer) -> BackendApiClient {
        let client = BackendApiClient(baseUrl: "https://api.example.com", tenantId: "default", httpFn: server.httpFunction)
        client.setAppToken("t")
        return client
    }

    private let attestation = RegisterResult(
        credentialId: Data("new".utf8), attestationObject: Data([7]), clientDataJSON: Data([8])
    )
    private let assertion = AuthenticateResult(
        credentialId: Data("pk-1".utf8), authenticatorData: Data([1]), clientDataJSON: Data([2]),
        signature: Data([3]), userHandle: Data([4])
    )

    private func finish(
        _ server: MockHttpServer, authorization: Bool = true, ifMatch: String? = nil
    ) async throws -> AddPasskeyOutcome {
        try await client(server).passkeyRegisterFinish(
            challengeId: "ch-1", credential: attestation, nickname: "Laptop",
            privateData: Data([1, 2, 3]), authorization: authorization ? assertion : nil, ifMatch: ifMatch
        )
    }

    private func ready(_ begin: AddPasskeyBegin) throws -> PasskeyEnrollmentChallenge {
        guard case let .ready(challenge) = begin else { throw XCTSkip("not ready: \(begin)") }
        return challenge
    }

    func testBeginDecodesCreationAndAuthorizationOptions() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"username":"alice","challengeId":"ch-1",\#(Self.createOptions),\#(Self.authorization)}"#)

        let begin = try ready(try await client(server).passkeyRegisterBegin())

        XCTAssertEqual(server.requests[0].method, "POST")
        XCTAssertEqual(server.requests[0].path, "/user/session/webauthn/register-begin")
        XCTAssertEqual(begin.challengeId, "ch-1")
        XCTAssertEqual(begin.username, "alice")
        XCTAssertEqual(begin.createOptions.rpId, "wallet.example.com")
        XCTAssertEqual(begin.createOptions.userId, Data("user".utf8))
        XCTAssertEqual(begin.createOptions.userName, "alice")
        XCTAssertEqual(begin.createOptions.userDisplayName, "Alice")
        XCTAssertEqual(begin.createOptions.challenge, Data([1, 2, 3]))
        XCTAssertNil(begin.createOptions.prfSalt, "the caller adds its own salt")
        let authorization = try XCTUnwrap(begin.authorization)
        XCTAssertEqual(authorization.rpId, "wallet.example.com")
        XCTAssertEqual(authorization.challenge, Data([4, 5, 6]))
        XCTAssertEqual(authorization.allowCredentials?.map(\.id), [Data("pk-1".utf8)])
        XCTAssertEqual(authorization.userVerification, "required")
    }

    func testBeginWithoutAuthorizationMeansTheAccountHasNoPasskey() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"username":"alice","challengeId":"ch-1",\#(Self.createOptions)}"#)
        let begin = try ready(try await client(server).passkeyRegisterBegin())
        XCTAssertNil(begin.authorization)
    }

    func testBeginRejectsAMalformedResponseRatherThanDroppingTheAuthorization() async throws {
        for body in [
            #"{"createOptions":{"publicKey":{}}}"#,
            #"{"challengeId":"c"}"#,
            // authorization present but unusable: must not read as "no passkey"
            #"{"challengeId":"c",\#(Self.createOptions),"authorization":{"publicKey":{"rpId":"x"}}}"#,
            #"{"challengeId":"c",\#(Self.createOptions),"authorization":{}}"#,
        ] {
            let server = MockHttpServer()
            server.enqueue(body)
            do {
                _ = try await client(server).passkeyRegisterBegin()
                XCTFail("must not accept \(body)")
            } catch SirosError.backendApi(let code, _, _) {
                XCTAssertEqual(code, 0)
            }
        }
    }

    func testBeginMapsRevokedTokenAndMissingScopeToValues() async throws {
        let server = MockHttpServer()
        server.enqueueFailure(code: 401, body: #"{"error":"Unauthorized"}"#)
        server.enqueueFailure(code: 403, body: #"{"error":"insufficient_scope","message":"no i scope"}"#)
        server.enqueueFailure(code: 500, body: "")
        let c = client(server)
        guard case .sessionRevoked = try await c.passkeyRegisterBegin() else { return XCTFail("401") }
        guard case let .forbidden(message) = try await c.passkeyRegisterBegin() else { return XCTFail("403") }
        XCTAssertEqual(message, "no i scope")
        do {
            _ = try await c.passkeyRegisterBegin()
            XCTFail("a 500 is outside the contract")
        } catch SirosError.backendApi(let code, _, _) {
            XCTAssertEqual(code, 500)
        }
    }

    func testFinishSendsCredentialAuthorizationPrivateDataAndPrecondition() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"credentialId":"abc"}"#)

        let response = try await finish(server, ifMatch: "etag-1")

        XCTAssertEqual(response, .added(credentialId: "abc"))
        let request = server.requests[0]
        XCTAssertEqual(request.method, "POST")
        XCTAssertEqual(request.path, "/user/session/webauthn/register-finish")
        XCTAssertEqual(request.headers["X-Private-Data-If-Match"], "etag-1")
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.body)) as? [String: Any])
        XCTAssertEqual(body["challengeId"] as? String, "ch-1")
        XCTAssertEqual(body["nickname"] as? String, "Laptop")
        let credential = body["credential"] as? [String: Any]
        XCTAssertEqual(credential?["id"] as? String, "bmV3")
        XCTAssertEqual((credential?["response"] as? [String: Any])?["attestationObject"] as? String, "Bw")
        let authorization = body["authorization"] as? [String: Any]
        XCTAssertEqual(authorization?["id"] as? String, "cGstMQ")
        XCTAssertEqual((authorization?["response"] as? [String: Any])?["signature"] as? String, "Aw")
        XCTAssertEqual((authorization?["response"] as? [String: Any])?["userHandle"] as? String, "BA")
        XCTAssertEqual((body["privateData"] as? [String: Any])?["$b64u"] as? String, "AQID")
    }

    func testFinishOmitsAuthorizationAndPreconditionWhenThereAreNone() async throws {
        let server = MockHttpServer()
        server.enqueue(#"{"credentialId":"abc"}"#)
        _ = try await finish(server, authorization: false)
        let request = server.requests[0]
        XCTAssertNil(request.headers["X-Private-Data-If-Match"])
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: XCTUnwrap(request.body)) as? [String: Any])
        XCTAssertNil(body["authorization"])
    }

    func testFinishMapsEveryBackendOutcome() async throws {
        let cases: [(Int, String, AddPasskeyOutcome)] = [
            (401, #"{"error":"ENROLLMENT_AUTHORIZATION_REQUIRED","message":"m"}"#, .authorizationRequired(message: "m")),
            (401, #"{"error":"ENROLLMENT_AUTHORIZATION_FAILED","message":"m"}"#, .authorizationFailed(message: "m")),
            (401, #"{"error":"Unauthorized"}"#, .sessionRevoked(message: nil)),
            (412, "", .privateDataConflict(currentEtag: nil)),
            (404, "{}", .retryNeeded(message: nil)),
            (400, #"{"error":"Registration response could not be verified"}"#,
             .registrationRejected(status: 400, message: "Registration response could not be verified")),
            (403, #"{"error":"Authenticator not allowed"}"#,
             .registrationRejected(status: 403, message: "Authenticator not allowed")),
        ]
        for (code, body, expected) in cases {
            let server = MockHttpServer()
            server.enqueueFailure(code: code, body: body)
            let response = try await finish(server)
            XCTAssertEqual(response, expected, "\(code) \(body)")
        }
    }

    func testFinishThrowsForAResponseOutsideTheContract() async {
        let server = MockHttpServer()
        server.enqueueFailure(code: 500, body: "")
        do {
            _ = try await finish(server)
            XCTFail("a 500 is not a contract outcome")
        } catch SirosError.backendApi(let code, _, _) {
            XCTAssertEqual(code, 500)
        } catch { XCTFail("\(error)") }
    }

    // MARK: - ETag

    private final class ResponseServer: @unchecked Sendable {
        private let lock = NSLock()
        private var queue: [HttpResponse]
        private(set) var headers: [[String: String]] = []
        init(_ responses: [HttpResponse]) { queue = responses }
        var fn: HttpResponseFunction {
            { [self] _, _, requestHeaders, _ in
                lock.lock(); defer { lock.unlock() }
                headers.append(requestHeaders)
                return queue.removeFirst()
            }
        }
    }

    /// The ETag of a private-data read is what the enrolment's finish is made
    /// conditional on, so it cannot overwrite what another device wrote.
    func testTheLatestPrivateDataEtagIsSentAsIfMatchOnFinish() async throws {
        let server = ResponseServer([
            HttpResponse(status: 200, data: Data(#"{"privateData":"x"}"#.utf8), headers: ["X-Private-Data-ETag": "etag-7"]),
            HttpResponse(status: 200, data: Data(#"{"credentialId":"abc"}"#.utf8), headers: ["X-Private-Data-ETag": "etag-8"]),
        ])
        let client = BackendApiClient(baseUrl: "https://api.example.com", responseFn: server.fn)
        client.setAppToken("t")
        XCTAssertNil(client.privateDataEtag)

        _ = try await client.getPrivateData()
        XCTAssertEqual(client.privateDataEtag, "etag-7")
        let outcome = try await client.passkeyRegisterFinish(
            challengeId: "c", credential: attestation, nickname: "n", privateData: Data([1]), authorization: nil
        )

        XCTAssertEqual(outcome, .added(credentialId: "abc"))
        XCTAssertEqual(server.headers[1]["X-Private-Data-If-Match"], "etag-7")
        XCTAssertEqual(client.privateDataEtag, "etag-8", "the response's new ETag is kept")
    }

    func testAConflictCarriesTheBackendsCurrentEtagWithoutReplacingTheWritePrecondition() async throws {
        let server = ResponseServer([HttpResponse(status: 412, data: Data(), headers: ["x-private-data-etag": "etag-9"])])
        let client = BackendApiClient(baseUrl: "https://api.example.com", responseFn: server.fn)
        let outcome = try await client.passkeyRegisterFinish(
            challengeId: "c", credential: attestation, nickname: "n", privateData: nil, authorization: nil, ifMatch: "old"
        )
        XCTAssertEqual(outcome, .privateDataConflict(currentEtag: "etag-9"))
        // The conflict's reported version is informational, kept apart from
        // the write precondition - see `conflictPrivateDataEtag`'s doc
        // comment. `privateDataEtag` was never set by anything here (no
        // successful read/write happened), so it stays nil, NOT "etag-9".
        XCTAssertNil(client.privateDataEtag)
        XCTAssertEqual(client.conflictPrivateDataEtag, "etag-9")
        XCTAssertEqual(server.headers[0]["X-Private-Data-If-Match"], "old")
    }

    /// Regression for the bug this fixes: a 412 must not silently become the
    /// default write precondition, or a caller that naively retries the SAME
    /// (still stale) enrollment would send its v1-based `privateData` with an
    /// `If-Match` that now happens to match the server's newer (v2) state -
    /// overwriting whatever changed it (e.g. another device's PRF entries)
    /// with stale data. Demonstrated here: after the conflict,
    /// `privateDataEtag` is still "v1" (the version actually paired with the
    /// loaded container), so a naive retry (no explicit `ifMatch`) sends
    /// `If-Match: v1` again - which the backend would (correctly) still
    /// refuse as a conflict against its real v2 state, rather than accepting
    /// it because the client had already adopted v2 as its own precondition.
    func testConflictThenNaiveRetryDoesNotSilentlyAdoptTheConflictingEtag() async throws {
        let server = ResponseServer([
            HttpResponse(status: 200, data: Data(#"{"privateData":"x"}"#.utf8), headers: ["X-Private-Data-ETag": "v1"]),
            HttpResponse(status: 412, data: Data(), headers: ["x-private-data-etag": "v2"]),
            HttpResponse(status: 412, data: Data(), headers: ["x-private-data-etag": "v2"]),
        ])
        let client = BackendApiClient(baseUrl: "https://api.example.com", responseFn: server.fn)

        // The enrolment prepared its container against v1.
        _ = try await client.getPrivateData()
        XCTAssertEqual(client.privateDataEtag, "v1")

        let firstAttempt = try await client.passkeyRegisterFinish(
            challengeId: "c", credential: attestation, nickname: "n", privateData: Data([1]), authorization: nil
        )
        XCTAssertEqual(firstAttempt, .privateDataConflict(currentEtag: "v2"))
        // Still v1: the conflict must not have replaced the write precondition.
        XCTAssertEqual(client.privateDataEtag, "v1")

        // A naive retry (no explicit ifMatch, no re-fetch/reconciliation)
        // sends the same v1-based data - with If-Match: v1 again, not v2.
        let retry = try await client.passkeyRegisterFinish(
            challengeId: "c", credential: attestation, nickname: "n", privateData: Data([1]), authorization: nil
        )
        XCTAssertEqual(server.headers[2]["X-Private-Data-If-Match"], "v1", "must not have adopted the conflicting v2 etag")
        XCTAssertEqual(retry, .privateDataConflict(currentEtag: "v2"), "the backend still refuses it - no silent overwrite")
    }
}
