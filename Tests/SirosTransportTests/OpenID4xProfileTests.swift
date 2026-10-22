// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

// MARK: - Mock peer context

private final class MockPeerContext: WmpPeerContext, @unchecked Sendable {
    let codec = WmpCodec()

    private let lock = NSLock()
    private var _notifications: [(method: String, params: [String: AnyCodable]?)] = []

    var notifications: [(method: String, params: [String: AnyCodable]?)] {
        lock.lock()
        defer { lock.unlock() }
        return _notifications
    }

    func notify(method: String, params: [String: AnyCodable]?) async throws {
        lock.lock()
        _notifications.append((method, params))
        lock.unlock()
    }

    func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse {
        return JsonRpcResponse(id: "mock", result: [:])
    }
}

// MARK: - Tests

final class OpenID4xProfileTests: XCTestCase {

    // MARK: - handleProgress routing

    func testHandleProgressSignRequestCallsOnSignRequest() async throws {
        let ctx = MockPeerContext()
        var receivedFlowId: String?
        var receivedParams: SignSubFlowParams?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { flowId, params in
                receivedFlowId = flowId
                receivedParams = params
                return SignSubFlowResult(proofs: [ProofObject(proofType: "jwt", jwt: "header.payload.sig")])
            }
        ))
        profile.initialize(ctx: ctx)

        let payload = try buildSignPayload()
        let progressParams = FlowProgressParams(
            flowId: "flow-1",
            step: "sign_request",
            payload: payload
        )
        await profile.handleProgress(params: progressParams)

        XCTAssertEqual(receivedFlowId, "flow-1")
        XCTAssertEqual(receivedParams?.action, "sign")
        XCTAssertEqual(receivedParams?.nonce, "nonce-abc")
        XCTAssertEqual(receivedParams?.audience, "https://issuer.example")

        // Verify sign_response notification sent on wmp.flow.action
        XCTAssertEqual(ctx.notifications.count, 1)
        let notification = ctx.notifications[0]
        XCTAssertEqual(notification.method, WmpMethods.flowAction)
        if case .string(let action) = notification.params?["action"] {
            XCTAssertEqual(action, "sign_response")
        } else {
            XCTFail("Expected action = sign_response in notification params")
        }
    }

    /// `sign_client_auth` over WMP (go-wallet-backend#317): the sub-flow params
    /// decode under the engine's wire names, and the result members go back
    /// under the legacy `sign_response` names so a backend needs one code path.
    func testHandleProgressSignClientAuthRoundTripsClientAuthMembers() async throws {
        let ctx = MockPeerContext()
        var receivedParams: SignSubFlowParams?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, params in
                receivedParams = params
                return SignSubFlowResult(
                    clientAttestation: "wia", clientAttestationPoP: "pop", dpopKeyId: "k-1", dpopProof: "dpop"
                )
            }
        ))
        profile.initialize(ctx: ctx)

        let payload: [String: AnyCodable] = [
            "action": .string("sign_client_auth"), "nonce": .string(""), "audience": .string("https://as.example.com"),
            "issuer": .string("siros-sample://callback"), "htm": .string("POST"), "htu": .string("https://as.example.com/token"),
            "dpop_nonce": .string("n-1"), "ath": .string("h"), "key_id": .string("k-1"),
        ]
        await profile.handleProgress(params: FlowProgressParams(flowId: "flow-1", step: "sign_request", payload: .object_(payload)))

        XCTAssertEqual(receivedParams?.action, "sign_client_auth")
        XCTAssertEqual(receivedParams?.issuer, "siros-sample://callback")
        XCTAssertEqual(receivedParams?.htm, "POST")
        XCTAssertEqual(receivedParams?.htu, "https://as.example.com/token")
        XCTAssertEqual(receivedParams?.dpopNonce, "n-1")
        XCTAssertEqual(receivedParams?.ath, "h")
        XCTAssertEqual(receivedParams?.keyId, "k-1")

        XCTAssertEqual(ctx.notifications.count, 1)
        let params = ctx.notifications[0].params
        XCTAssertEqual(params?["action"], .string("sign_response"))
        XCTAssertEqual(params?["client_attestation"], .string("wia"))
        XCTAssertEqual(params?["client_attestation_pop"], .string("pop"))
        XCTAssertEqual(params?["dpop_key_id"], .string("k-1"))
        XCTAssertEqual(params?["dpop_proof"], .string("dpop"))
    }

    /// A DPoP-only `sign_client_auth` (credential / deferred / notification
    /// request) has no audience and no c_nonce; a peer that omits the members
    /// instead of sending "" must still reach the handler.
    func testSignClientAuthWithoutAudienceOrNonceStillDecodes() async throws {
        let ctx = MockPeerContext()
        var receivedParams: SignSubFlowParams?
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, params in
                receivedParams = params
                return SignSubFlowResult(dpopKeyId: "k-1", dpopProof: "dpop")
            }
        ))
        profile.initialize(ctx: ctx)

        let payload: [String: AnyCodable] = [
            "action": .string("sign_client_auth"), "htm": .string("POST"),
            "htu": .string("https://issuer.example.com/credential"), "ath": .string("h"),
        ]
        await profile.handleProgress(params: FlowProgressParams(flowId: "flow-1", step: "sign_request", payload: .object_(payload)))

        XCTAssertEqual(receivedParams?.action, "sign_client_auth")
        XCTAssertEqual(receivedParams?.audience, "")
        XCTAssertEqual(receivedParams?.nonce, "")
        XCTAssertEqual(receivedParams?.htm, "POST")
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].params?["dpop_proof"], .string("dpop"))
    }

    func testHandleProgressMatchRequestCallsOnMatchRequest() async throws {
        let ctx = MockPeerContext()
        var receivedFlowId: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onMatchRequest: { flowId, _ in
                receivedFlowId = flowId
                return MatchResult(matches: [
                    CredentialMatch(credentialId: "cred-1", format: "vc+sd-jwt"),
                ])
            }
        ))
        profile.initialize(ctx: ctx)

        let progressParams = FlowProgressParams(
            flowId: "flow-2",
            step: "match_request",
            payload: nil
        )
        await profile.handleProgress(params: progressParams)

        XCTAssertEqual(receivedFlowId, "flow-2")
        XCTAssertEqual(ctx.notifications.count, 1)
        let notification = ctx.notifications[0]
        XCTAssertEqual(notification.method, WmpMethods.flowAction)
        if case .string(let action) = notification.params?["action"] {
            XCTAssertEqual(action, "match_response")
        } else {
            XCTFail("Expected action = match_response in notification params")
        }
    }

    /// A wallet with nothing to present answers with an empty match set; the
    /// reason travelling with it is the only explanation of *why*, and this
    /// transport used to drop it on the floor.
    func testMatchResponseCarriesNoMatchReason() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onMatchRequest: { _, _ in
                MatchResult(matches: [], noMatchReason: "no stored credential matches the requested type(s): urn:eudi:pid:1")
            }
        ))
        profile.initialize(ctx: ctx)

        await profile.handleProgress(params: FlowProgressParams(flowId: "flow-4", step: "match_request", payload: nil))

        XCTAssertEqual(ctx.notifications.count, 1)
        let params = ctx.notifications[0].params
        XCTAssertEqual(params?["action"], .string("match_response"))
        XCTAssertEqual(params?["matches"], .array([]))
        XCTAssertEqual(
            params?["no_match_reason"],
            .string("no stored credential matches the requested type(s): urn:eudi:pid:1")
        )
    }

    func testMatchResponseOmitsNoMatchReasonWhenMatched() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onMatchRequest: { _, _ in
                MatchResult(matches: [CredentialMatch(credentialId: "cred-1", format: "dc+sd-jwt")])
            }
        ))
        profile.initialize(ctx: ctx)

        await profile.handleProgress(params: FlowProgressParams(flowId: "flow-5", step: "match_request", payload: nil))

        XCTAssertNil(ctx.notifications.first?.params?["no_match_reason"])
    }

    func testHandleProgressTrustEvaluationCallsOnTrustEvaluation() async throws {
        let ctx = MockPeerContext()
        var receivedFlowId: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onTrustEvaluation: { flowId, _ in
                receivedFlowId = flowId
                return TrustResult(trusted: true, framework: "eidas", reason: nil)
            }
        ))
        profile.initialize(ctx: ctx)

        let progressParams = FlowProgressParams(
            flowId: "flow-3",
            step: "trust_evaluation_required",
            payload: nil
        )
        await profile.handleProgress(params: progressParams)

        XCTAssertEqual(receivedFlowId, "flow-3")
        XCTAssertEqual(ctx.notifications.count, 1)
        let notification = ctx.notifications[0]
        XCTAssertEqual(notification.method, WmpMethods.flowAction)
        if case .string(let action) = notification.params?["action"] {
            XCTAssertEqual(action, "trust_result")
        } else {
            XCTFail("Expected action = trust_result in notification params")
        }
        if case .bool(let trusted) = notification.params?["trusted"] {
            XCTAssertTrue(trusted)
        } else {
            XCTFail("Expected trusted = true in notification params")
        }
    }

    func testHandleProgressUnknownStepCallsOnProgress() async throws {
        let ctx = MockPeerContext()
        var receivedStep: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onProgress: { _, step, _ in
                receivedStep = step
            }
        ))
        profile.initialize(ctx: ctx)

        let progressParams = FlowProgressParams(
            flowId: "flow-4",
            step: VCIStep.parsingOffer,
            payload: nil
        )
        await profile.handleProgress(params: progressParams)

        XCTAssertEqual(receivedStep, VCIStep.parsingOffer)
        XCTAssertEqual(ctx.notifications.count, 0, "No outgoing notification expected for passthrough progress")
    }

    // MARK: - handleComplete / handleError / handleCancel

    func testHandleCompleteCallsOnComplete() async throws {
        let ctx = MockPeerContext()
        var completedFlowId: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onComplete: { flowId, _ in completedFlowId = flowId }
        ))
        profile.initialize(ctx: ctx)

        await profile.handleComplete(params: FlowCompleteParams(flowId: "flow-5"))
        XCTAssertEqual(completedFlowId, "flow-5")
    }

    func testHandleErrorCallsOnError() async throws {
        let ctx = MockPeerContext()
        var errorFlowId: String?
        var errorCode: String?

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onError: { flowId, code, _ in
                errorFlowId = flowId
                errorCode = code
            }
        ))
        profile.initialize(ctx: ctx)

        await profile.handleError(params: FlowErrorParams(flowId: "flow-6", code: "E_ISSUER", message: "issuer error"))
        XCTAssertEqual(errorFlowId, "flow-6")
        XCTAssertEqual(errorCode, "E_ISSUER")
    }

    // MARK: - Error propagation

    func testHandleProgressSignRequestHandlerErrorSendsFlowError() async throws {
        let ctx = MockPeerContext()

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in
                struct SignError: Error, LocalizedError {
                    var errorDescription: String? { "key not found" }
                }
                throw SignError()
            }
        ))
        profile.initialize(ctx: ctx)

        let payload = try buildSignPayload()
        let progressParams = FlowProgressParams(
            flowId: "flow-7",
            step: "sign_request",
            payload: payload
        )
        await profile.handleProgress(params: progressParams)

        // Should send wmp.flow.error
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowError)
        if case .string(let code) = ctx.notifications[0].params?["code"] {
            XCTAssertEqual(code, "SIGN_ERROR")
        } else {
            XCTFail("Expected code = SIGN_ERROR in flow error notification")
        }
    }

    /// An error that names its WMP code is reported with it, not as SIGN_ERROR.
    func testSignHandlerErrorWithAWmpCodeIsReportedWithThatCode() async throws {
        struct Refusal: Error, LocalizedError, WmpErrorCodeProviding {
            var wmpErrorCode: String? { "invalid_transaction_data" }
            var errorDescription: String? { "developer detail: payee Zebra amount 98765" }
        }
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in throw Refusal() }))
        profile.initialize(ctx: ctx)
        await profile.handleProgress(params: FlowProgressParams(flowId: "flow-8", step: "sign_request", payload: try buildSignPayload()))
        XCTAssertEqual(ctx.notifications.count, 1)
        if case .string(let code) = ctx.notifications[0].params?["code"] {
            XCTAssertEqual(code, "invalid_transaction_data")
        } else {
            XCTFail("expected a code")
        }
        if case .string(let message) = ctx.notifications[0].params?["message"] {
            XCTAssertEqual(message, "invalid_transaction_data", "only the code goes to the peer, no developer text")
        } else {
            XCTFail("expected a message")
        }
    }

    func testHandleProgressTrustEvaluationHandlerErrorSendsUntrustedResult() async throws {
        let ctx = MockPeerContext()

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onTrustEvaluation: { _, _ in
                struct TrustError: Error {}
                throw TrustError()
            }
        ))
        profile.initialize(ctx: ctx)

        await profile.handleProgress(params: FlowProgressParams(
            flowId: "flow-8",
            step: "trust_evaluation_required",
            payload: nil
        ))

        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowAction)
        if case .bool(let trusted) = ctx.notifications[0].params?["trusted"] {
            XCTAssertFalse(trusted, "Trust evaluation error should result in trusted=false")
        } else {
            XCTFail("Expected trusted field in trust_result notification")
        }
    }

    // MARK: - startFlow / initialize

    func testStartFlowReturnsMatchingResult() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile()
        profile.initialize(ctx: ctx)

        let params = FlowStartParams(
            wmp: WmpMeta(),
            flowId: "flow-9",
            flowType: OID4FlowTypes.oid4vci
        )
        let result = try await profile.startFlow(params: params)
        XCTAssertEqual(result.flowId, "flow-9")
        XCTAssertEqual(result.flowType, OID4FlowTypes.oid4vci)
    }

    func testProfileHasExpectedFlowTypes() {
        let profile = OpenID4xProfile()
        XCTAssertTrue(profile.flowTypes.contains(OID4FlowTypes.oid4vci))
        XCTAssertTrue(profile.flowTypes.contains(OID4FlowTypes.oid4vp))
    }

    func testHandleProgressSignRequestNilPayloadSendsFlowError() async throws {
        let ctx = MockPeerContext()

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in
                XCTFail("handler should not be called when payload is nil")
                return SignSubFlowResult()
            }
        ))
        profile.initialize(ctx: ctx)

        await profile.handleProgress(params: FlowProgressParams(
            flowId: "flow-nil",
            step: "sign_request",
            payload: nil
        ))

        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowError)
        if case .string(let code) = ctx.notifications[0].params?["code"] {
            XCTAssertEqual(code, "INVALID_PARAMS")
        } else {
            XCTFail("Expected code = INVALID_PARAMS in flow error")
        }
    }
}

// MARK: - Helpers

private func buildSignPayload() throws -> AnyCodable {
    let signParams = SignSubFlowParams(
        action: "sign",
        nonce: "nonce-abc",
        audience: "https://issuer.example",
        proofType: "jwt"
    )
    let data = try JSONEncoder().encode(signParams)
    return try JSONDecoder().decode(AnyCodable.self, from: data)
}
