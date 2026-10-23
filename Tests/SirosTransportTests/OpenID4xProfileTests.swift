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

    private var _released: [String] = []
    var released: [String] { lock.lock(); defer { lock.unlock() }; return _released }
    func releaseFlow(flowId: String) { lock.lock(); _released.append(flowId); lock.unlock() }

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

    func testSignChildFlowDecodesTheEnginesParamsAndAnswersOnTheChild() async throws {
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
        await profile.runChildFlow(params: childStart(flowType: "sign", parent: "flow-1", payload: try buildSignPayload()))
        XCTAssertEqual(receivedFlowId, "flow-1")
        XCTAssertEqual(receivedParams?.action, "sign")
        XCTAssertEqual(receivedParams?.nonce, "nonce-abc")
        XCTAssertEqual(receivedParams?.audience, "https://issuer.example")
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowComplete)
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
        await profile.runChildFlow(params: childStart(flowType: "sign", parent: "flow-1", payload: .object_(payload)))

        XCTAssertEqual(receivedParams?.action, "sign_client_auth")
        XCTAssertEqual(receivedParams?.issuer, "siros-sample://callback")
        XCTAssertEqual(receivedParams?.htm, "POST")
        XCTAssertEqual(receivedParams?.htu, "https://as.example.com/token")
        XCTAssertEqual(receivedParams?.dpopNonce, "n-1")
        XCTAssertEqual(receivedParams?.ath, "h")
        XCTAssertEqual(receivedParams?.keyId, "k-1")

        XCTAssertEqual(ctx.notifications.count, 1)
        let params = ctx.notifications[0].params?["result"]?.objectValue
        XCTAssertNil(params?["action"])
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
        await profile.runChildFlow(params: childStart(flowType: "sign", parent: "flow-1", payload: .object_(payload)))

        XCTAssertEqual(receivedParams?.action, "sign_client_auth")
        XCTAssertEqual(receivedParams?.audience, "")
        XCTAssertEqual(receivedParams?.nonce, "")
        XCTAssertEqual(receivedParams?.htm, "POST")
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].params?["result"]?.objectValue?["dpop_proof"], .string("dpop"))
    }

    /// Engine-blind issuance over WMP: `generate_proof` carries the negotiated pair and is answered with
    /// the wallet's public JWK; `decrypt_credential_response` carries the JWE and is answered with the
    /// control fields only.
    func testWmpCarriesCredentialResponseEncryptionBothWays() async throws {
        let ctx = MockPeerContext()
        var seen: [SignSubFlowParams] = []
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, params in
                seen.append(params)
                if params.action == "generate_proof" {
                    return SignSubFlowResult(
                        proofs: [ProofObject(proofType: "jwt", jwt: "a.b.c")],
                        credentialResponseEncryptionJwk: ["kty": "EC", "crv": "P-256", "x": "X", "y": "Y", "use": "enc", "alg": "ECDH-ES+A256KW"]
                    )
                }
                return SignSubFlowResult(transactionId: "tx-1", interval: 5)
            }
        ))
        profile.initialize(ctx: ctx)

        await profile.runChildFlow(params: childStart(flowType: "sign", flowId: "c1", params: [
            "parent_flow_id": .string("f"),
            "action": .string("generate_proof"), "nonce": .string("n"), "audience": .string("https://i.example"),
            "credential_response_encryption": .object_([
                "alg": .string("ECDH-ES+A256KW"), "enc": .string("A256GCM"), "required": .bool(true),
            ]),
        ]))
        XCTAssertEqual(seen[0].credentialResponseEncryption, CredentialResponseEncryptionRequest(alg: "ECDH-ES+A256KW", enc: "A256GCM", required: true))
        let proofReply = ctx.notifications[0].params?["result"]?.objectValue
        XCTAssertEqual(proofReply?["credential_response_encryption_jwk"]?.objectValue?["alg"], .string("ECDH-ES+A256KW"))
        XCTAssertEqual(proofReply?["credential_response_encryption_jwk"]?.objectValue?["use"], .string("enc"))

        await profile.runChildFlow(params: childStart(flowType: "sign", flowId: "c2", params: [
            "parent_flow_id": .string("f"),
            "action": .string("decrypt_credential_response"), "jwe": .string("a.b.c.d.e"), "deferred": .bool(true),
        ]))
        XCTAssertEqual(seen[1].jwe, "a.b.c.d.e")
        XCTAssertEqual(seen[1].deferred, true)
        let decryptReply = ctx.notifications[1].params?["result"]?.objectValue
        XCTAssertEqual(decryptReply?["transaction_id"], .string("tx-1"))
        XCTAssertEqual(decryptReply?["interval"], .int(5))
        XCTAssertNil(decryptReply?["credentials"])
        XCTAssertNil(decryptReply?["credential_response_encryption_jwk"])
    }

    func testWmpSignPresentationCarriesResponseEncryptionAndAnswersWithResponseJwe() async throws {
        let ctx = MockPeerContext()
        var seen: SignSubFlowParams?
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, params in
            seen = params
            return SignSubFlowResult(responseJwe: "h..i.c.t")
        }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "sign", params: [
            "parent_flow_id": .string("f"),
            "action": .string("sign_presentation"), "nonce": .string("n"), "audience": .string("a"), "state": .string("st"),
            "response_encryption": .object_([
                "jwk": .object_(["kty": .string("EC"), "crv": .string("P-256"), "x": .string("X"), "y": .string("Y")]),
                "alg": .string("ECDH-ES"), "enc": .string("A128GCM"),
            ]),
            "verified_request": .object_(["client_id": .string("c1")]),
        ]))
        XCTAssertEqual(seen?.responseEncryption?.enc, "A128GCM")
        XCTAssertEqual(seen?.state, "st")
        XCTAssertEqual(seen?.verifiedRequest?.clientId, "c1")
        let reply = ctx.notifications[0].params?["result"]?.objectValue
        XCTAssertEqual(reply?["response_jwe"], .string("h..i.c.t"))
        XCTAssertNil(reply?["vp_token"])
    }

    // MARK: - Child flows (the orchestrator's nested sign / match flows)

    /// A child start carrying `payload`'s members plus the `parent_flow_id` the engine adds.
    private func childStart(flowType: String, parent: String, payload: AnyCodable?, flowId: String = "child-1") -> FlowStartParams {
        var members = payload?.objectValue ?? [:]
        members["parent_flow_id"] = .string(parent)
        return childStart(flowType: flowType, flowId: flowId, params: members)
    }

    private func childStart(flowType: String, flowId: String = "child-1", params: [String: AnyCodable]) -> FlowStartParams {
        FlowStartParams(wmp: WmpMeta(version: "0.1", sessionId: "s"), flowId: flowId, flowType: flowType, params: .object_(params))
    }

    /// The orchestrator starts a `sign` child flow and expects `wmp.flow.complete` ON THE CHILD with the
    /// response as `result` (not a `wmp.flow.action` `sign_response` on the parent).
    func testASignChildFlowIsAnsweredWithFlowCompleteOnTheChild() async throws {
        let ctx = MockPeerContext()
        var handlerFlowId: String?
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { flowId, params in
            handlerFlowId = flowId
            XCTAssertEqual(params.action, "generate_proof")
            return SignSubFlowResult(proofs: [ProofObject(proofType: "jwt", jwt: "a.b.c")])
        }))
        profile.initialize(ctx: ctx)
        XCTAssertTrue(profile.flowTypes.contains("sign"))
        XCTAssertTrue(profile.flowTypes.contains("match"))
        await profile.runChildFlow(params: childStart(flowType: "sign", params: [
            "action": .string("generate_proof"), "nonce": .string("n"), "audience": .string("a"),
            "parent_flow_id": .string("parent-1"),
        ]))
        XCTAssertEqual(handlerFlowId, "parent-1", "the wallet's state belongs to the parent flow")
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowComplete)
        let params = ctx.notifications[0].params
        XCTAssertEqual(params?["flow_id"], .string("child-1"))
        let result = try XCTUnwrap(params?["result"]?.objectValue)
        XCTAssertNotNil(result["proofs"])
        XCTAssertNil(result["action"], "the result is the response JSON, not an action")
        XCTAssertNil(params?["action"])
    }

    /// The engine-blind issuance answers travel the child-flow route: the key's JWK with the proofs, and
    /// exactly one of `credential_count` / `transaction_id` + `interval` for `decrypt_credential_response`.
    func testEngineBlindIssuanceAnswersAreTheResultOfTheChildFlow() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, params in
            params.action == "generate_proof"
                ? SignSubFlowResult(
                    credentialResponseEncryptionJwk: ["kty": "EC", "crv": "P-256", "x": "X", "y": "Y", "use": "enc", "alg": "ECDH-ES"]
                )
                : SignSubFlowResult(credentialCount: 2)
        }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "sign", flowId: "c-a", params: [
            "action": .string("generate_proof"), "parent_flow_id": .string("vci-1"),
            "credential_response_encryption": .object_(["alg": .string("ECDH-ES"), "enc": .string("A256GCM"), "required": .bool(true)]),
        ]))
        await profile.runChildFlow(params: childStart(flowType: "sign", flowId: "c-b", params: [
            "action": .string("decrypt_credential_response"), "parent_flow_id": .string("vci-1"),
            "jwe": .string("a.b.c.d.e"), "deferred": .bool(false),
        ]))
        let keyResult = ctx.notifications[0].params?["result"]?.objectValue
        XCTAssertEqual(keyResult?["credential_response_encryption_jwk"]?.objectValue?["use"], .string("enc"))
        XCTAssertNil(keyResult?["proofs"], "a key-only answer has no proofs")
        let decryptResult = ctx.notifications[1].params?["result"]?.objectValue
        XCTAssertEqual(decryptResult?["credential_count"], .int(2))
        XCTAssertNil(decryptResult?["transaction_id"])
        XCTAssertEqual(ctx.notifications[1].method, WmpMethods.flowComplete)
    }

    /// Engine-blind presentation over WMP: `response_encryption`, `state` and `verified_request` arrive in the
    /// child flow's params, and the answer is `response_jwe` in the child's `result`, with no `vp_token`.
    func testAPresentationChildFlowAnswersWithResponseJweAndNoVpToken() async throws {
        let ctx = MockPeerContext()
        var seen: SignSubFlowParams?
        var seenFlow: String?
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { flowId, params in
            seenFlow = flowId
            seen = params
            return SignSubFlowResult(responseJwe: "h..i.c.t")
        }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "sign", flowId: "c-p", params: [
            "action": .string("sign_presentation"), "nonce": .string("n"), "audience": .string("a"), "state": .string("st"),
            "parent_flow_id": .string("vp-9"),
            "response_encryption": .object_([
                "jwk": .object_(["kty": .string("EC"), "crv": .string("P-256"), "x": .string("X"), "y": .string("Y"), "kid": .string("k")]),
                "alg": .string("ECDH-ES"), "enc": .string("A128GCM"),
            ]),
            "verified_request": .object_(["client_id": .string("c1")]),
        ]))
        XCTAssertEqual(seenFlow, "vp-9")
        XCTAssertEqual(seen?.verifiedRequest?.clientId, "c1")
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowComplete)
        let result = ctx.notifications[0].params?["result"]?.objectValue
        XCTAssertEqual(result?["response_jwe"], .string("h..i.c.t"))
        XCTAssertNil(result?["vp_token"])
    }

    /// A `response_encryption` that is present but unusable is an error, never "absent": absent would select
    /// the plain vp_token path and hand the engine a presentation the verifier asked to be encrypted.
    func testAPresentButMalformedResponseEncryptionNeverReachesTheSigner() async throws {
        for bad in [AnyCodable.null_, .object_(["jwk": .object_([:]), "alg": .string("ECDH-ES")]), .string("x")] {
            let ctx = MockPeerContext()
            var signed = false
            let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
                signed = true
                return SignSubFlowResult(vpToken: "plain")
            }))
            profile.initialize(ctx: ctx)
            await profile.runChildFlow(params: childStart(flowType: "sign", params: [
                "action": .string("sign_presentation"), "response_encryption": bad,
            ]))
            XCTAssertFalse(signed, "\(bad)")
            XCTAssertEqual(ctx.notifications.count, 1)
            XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowError, "\(bad)")
        }
    }

    func testARefusedSignChildFlowIsAFlowErrorOnTheChildWithReasonRejected() async throws {
        struct Refused: Error, WmpErrorCodeProviding { var wmpErrorCode: String? { "DECRYPT_FAILED" } }
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in throw Refused() }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "sign", params: ["action": .string("sign_presentation")]))
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowError)
        let params = ctx.notifications[0].params
        XCTAssertEqual(params?["flow_id"], .string("child-1"))
        XCTAssertEqual(params?["code"], .int(-31006), "a number: go-wmp rejects a string code and the refusal would be lost")
        XCTAssertEqual(params?["message"], .string("DECRYPT_FAILED"))
        XCTAssertEqual(params?["data"]?.objectValue?["reason"], .string("rejected"))
        XCTAssertEqual(params?["data"]?.objectValue?["error_code"], .string("DECRYPT_FAILED"))
        XCTAssertEqual(ctx.released, ["child-1"], "a finished child is no longer tracked by the peer")
    }

    /// A child cancelled while its handler is suspended gets no reply, even when the handler returns normally.
    /// The handler is waited for at entry, suspended on a gate that does not throw on cancellation, and shown to
    /// reach its normal return, so only the profile's suppression keeps the answer back.
    func testACancelledChildFlowAnswersNothing() async throws {
        final class Gate: @unchecked Sendable {
            private let lock = NSLock()
            private var entered = false, returned = false
            private var continuation: CheckedContinuation<Void, Never>?
            private var opened = false
            var didEnter: Bool { lock.lock(); defer { lock.unlock() }; return entered }
            var didReturn: Bool { lock.lock(); defer { lock.unlock() }; return returned }
            func wait() async {
                await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                    lock.lock(); entered = true
                    if opened { lock.unlock(); c.resume() } else { continuation = c; lock.unlock() }
                }
                lock.lock(); returned = true; lock.unlock()
            }
            func open() { lock.lock(); opened = true; let c = continuation; continuation = nil; lock.unlock(); c?.resume() }
        }
        let ctx = MockPeerContext()
        let gate = Gate()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
            await gate.wait()
            return SignSubFlowResult(vpToken: "late")        // returns normally despite the cancellation
        }))
        profile.initialize(ctx: ctx)
        _ = try await profile.startFlow(params: childStart(flowType: "sign", flowId: "c-x", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("vp-1"),
        ]))
        for _ in 0..<200 where !gate.didEnter { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertTrue(gate.didEnter, "the handler is entered before the cancel")
        await profile.handleCancel(params: FlowCancelParams(flowId: "c-x"))
        gate.open()
        for _ in 0..<200 where !gate.didReturn { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertTrue(gate.didReturn, "the handler returned normally")
        // The child's task finishes by releasing its flow a second time (the cancel released it first).
        for _ in 0..<200 where ctx.released.count < 2 { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertTrue(ctx.notifications.isEmpty, "no complete and no error for a cancelled child")
    }

    /// Two answers are queued for the resume. While the first replay send is suspended the second's parent is
    /// cancelled (or the profile shuts down): the second answer is revalidated before it is sent and never goes out.
    func testAReplayDoesNotSendAnAnswerCancelledWhileAnEarlierSendWasSuspended() async throws {
        for ending in ["cancelParent", "shutdown"] {
            let ctx = ReplayPeerContext()
            let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }))
            profile.initialize(ctx: ctx)
            for (child, parent) in [("c1", "p1"), ("c2", "p2")] {
                await profile.runChildFlow(params: childStart(flowType: "sign", flowId: child, params: [
                    "action": .string("sign_presentation"), "parent_flow_id": .string(parent),
                ]))
            }
            ctx.startReplay()
            profile.sessionResumed()
            for _ in 0..<200 where ctx.inFlight.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
            let first = try XCTUnwrap(ctx.inFlight.first)
            let second = first == "c1" ? "c2" : "c1"
            if ending == "shutdown" { profile.shutdown() } else {
                await profile.handleCancel(params: FlowCancelParams(flowId: second == "c1" ? "p1" : "p2"))
            }
            ctx.release()
            try await Task.sleep(nanoseconds: 200_000_000)
            XCTAssertEqual(ctx.sentFlowIds, [first], "\(ending): only the send already under way completes; \(second) is not sent")
        }
    }

    /// Cancelling a child whose answer is queued for the resume is a child cancel: the wallet's parent-flow
    /// cancellation callback is not invoked (it would reset the parent's guards).
    func testCancellingAChildWithAQueuedAnswerDoesNotCancelTheParentInTheWallet() async throws {
        let ctx = ReplayPeerContext()           // every send fails: the answer is queued
        var cancelled: [String] = []
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") },
            onCancel: { id, _ in cancelled.append(id) }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "sign", flowId: "c1", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("p1"),
        ]))
        await profile.handleCancel(params: FlowCancelParams(flowId: "c1"))
        XCTAssertTrue(cancelled.isEmpty, "only a child operation was cancelled")
        await profile.handleCancel(params: FlowCancelParams(flowId: "p1"))
        XCTAssertEqual(cancelled, ["p1"], "a flow of its own still is")
    }

    /// A second resume while the first replay send is suspended does not send the same answer again.
    func testASecondResumeDoesNotResendAnAnswerWhoseReplayIsSuspended() async throws {
        let ctx = ReplayPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "sign", flowId: "c1", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("p1"),
        ]))
        ctx.startReplay()
        profile.sessionResumed()
        for _ in 0..<200 where ctx.inFlight.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
        profile.sessionResumed()
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(ctx.inFlight, ["c1"], "the second drain finds nothing to send: the first claimed it")
        ctx.release()
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(ctx.sentFlowIds, ["c1"])
    }

    /// A resume that lands while a child's ORIGINAL send is suspended (and that send then fails) is not missed: the
    /// answer queued afterwards is retried at once, without rerunning the handler.
    func testAResumeDuringTheOriginalSendDoesNotLeaveTheAnswerQueued() async throws {
        let ctx = FailAfterReleaseContext()
        let counter = Counter()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in counter.bump(); return SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        let run = Task { await profile.runChildFlow(params: self.childStart(flowType: "sign", flowId: "c1", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("p1"),
        ])) }
        for _ in 0..<200 where !ctx.inFirstNotify { try await Task.sleep(nanoseconds: 10_000_000) }
        profile.sessionResumed()                      // the connection is back; the queue is still empty
        ctx.releaseFailing()                          // the old send now reports its failure
        await run.value
        for _ in 0..<200 where ctx.sent.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(ctx.sent, ["c1"], "retried without waiting for another resume")
        XCTAssertEqual(counter.value, 1)
    }

    /// Shutdown after a failed terminal send releases that child's routing entry too.
    func testShutdownReleasesChildrenWithQueuedAnswers() async throws {
        let ctx = ReplayPeerContext()           // every send fails: the answer is queued
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "sign", flowId: "c1", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("p1"),
        ]))
        XCTAssertFalse(ctx.released.contains("c1"), "still held for the resume")
        profile.shutdown()
        XCTAssertTrue(ctx.released.contains("c1"))
    }

    private func queueOneAnswer(_ ctx: ScriptedPeerContext, profile: OpenID4xProfile) async {
        await profile.runChildFlow(params: childStart(flowType: "sign", flowId: "c1", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("p1"),
        ]))   // the script's first step fails this send: the answer is queued
    }

    /// A child-only cancel while its replay send is suspended is not undone by that send failing: the answer is not
    /// requeued, and a later resume sends nothing.
    func testACancelledReplayingChildIsNotRequeuedWhenItsSendFails() async throws {
        let ctx = ScriptedPeerContext([.fail, .blockThenFail, .succeed])
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        await queueOneAnswer(ctx, profile: profile)
        profile.sessionResumed()
        for _ in 0..<200 where !ctx.blockedNow { try await Task.sleep(nanoseconds: 10_000_000) }
        await profile.handleCancel(params: FlowCancelParams(flowId: "c1"))   // child-only cancel
        ctx.releaseBlocked()
        try await Task.sleep(nanoseconds: 100_000_000)
        profile.sessionResumed()
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertTrue(ctx.sent.isEmpty, "a cancelled child's answer never goes out")
    }

    /// A second resume during a suspended replay that then fails is not lost: the answer is drained again.
    func testAReplayThatFailsAfterAnotherResumeIsRetried() async throws {
        let ctx = ScriptedPeerContext([.fail, .blockThenFail, .succeed])
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        await queueOneAnswer(ctx, profile: profile)
        profile.sessionResumed()
        for _ in 0..<200 where !ctx.blockedNow { try await Task.sleep(nanoseconds: 10_000_000) }
        profile.sessionResumed()                       // finds the answer claimed
        ctx.releaseBlocked()                           // the suspended replay now fails
        for _ in 0..<300 where ctx.sent.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(ctx.sent, ["c1"])
    }

    /// A redelivered start for a child that was cancelled does not run its handler again.
    func testACancelledChildsRedeliveredStartDoesNotRunAgain() async throws {
        let ctx = MockPeerContext()
        let counter = Counter()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in counter.bump(); return SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        let start = childStart(flowType: "sign", flowId: "c1", params: ["action": .string("sign_presentation"), "parent_flow_id": .string("p1")])
        await profile.handleCancel(params: FlowCancelParams(flowId: "c1"))   // cancelled before it ran
        _ = try await profile.startFlow(params: start)
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(counter.value, 0)
    }

    /// A start refused for good (its parent ended, or the profile stopped) releases the route the peer registered,
    /// so a later cancel of that child cannot be mistaken for a parent cancel; a tracked duplicate keeps its own.
    func testARefusedChildStartReleasesItsRoute() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        await profile.handleCancel(params: FlowCancelParams(flowId: "p1"))   // the parent ended
        _ = try await profile.startFlow(params: childStart(flowType: "sign", flowId: "late", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("p1"),
        ]))
        XCTAssertTrue(ctx.released.contains("late"), "the dropped start's route is released")
        profile.shutdown()
        _ = try await profile.startFlow(params: childStart(flowType: "sign", flowId: "later", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("p2"),
        ]))
        XCTAssertTrue(ctx.released.contains("later"), "and so is a start after shutdown")
    }

    /// A malformed `verified_request` (or `state`) fails the sign request as INVALID_PARAMS instead of being read as
    /// absent, which with `response_encryption` omitted would have answered a direct_post.jwt request in plaintext.
    func testAMalformedVerifiedRequestIsInvalidParamsAndSignsNothing() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
            XCTFail("a malformed request is never signed"); return SignSubFlowResult(vpToken: "plaintext")
        }))
        profile.initialize(ctx: ctx)
        for bad in [
            ["verified_request": AnyCodable.object_(["client_id": .string("c"), "response_mode": .string("direct_post.jwt"), "signed": .string("yes")])],
            ["state": AnyCodable.int(7)],
        ] {
            var members: [String: AnyCodable] = ["action": .string("sign_presentation"), "nonce": .string("n"), "audience": .string("a"), "parent_flow_id": .string("p")]
            for (k, v) in bad { members[k] = v }
            await profile.runChildFlow(params: FlowStartParams(wmp: WmpMeta(), flowId: "c1", flowType: "sign", params: .object_(members)))
        }
        XCTAssertEqual(ctx.notifications.count, 2)
        for message in ctx.notifications {
            XCTAssertEqual(message.method, WmpMethods.flowError)
            XCTAssertEqual(message.params?["data"]?.objectValue?["error_code"], .string("INVALID_PARAMS"))
        }
    }

    private func signStart(_ child: String = "c1", parent: String = "p1") -> FlowStartParams {
        childStart(flowType: "sign", flowId: child, params: ["action": .string("sign_presentation"), "parent_flow_id": .string(parent)])
    }

    /// A child whose answer was sent is remembered: a start redelivered while its parent is still active runs the
    /// handler once only, after the original send and after a replay alike.
    func testARedeliveredStartAfterASentAnswerRunsNothing() async throws {
        for path in ["original", "replay"] {
            let ctx = ScriptedPeerContext(path == "original" ? [.succeed] : [.fail, .succeed])
            let counter = Counter()
            let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in counter.bump(); return SignSubFlowResult(vpToken: "t") }))
            profile.initialize(ctx: ctx)
            _ = try await profile.startFlow(params: signStart())
            if path == "replay" {
                for _ in 0..<200 where counter.value == 0 { try await Task.sleep(nanoseconds: 10_000_000) }
                try await Task.sleep(nanoseconds: 50_000_000)       // the original send failed and queued the answer
                profile.sessionResumed()
            }
            for _ in 0..<300 where ctx.sent.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
            XCTAssertEqual(ctx.sent, ["c1"], path)
            try await Task.sleep(nanoseconds: 50_000_000)
            _ = try await profile.startFlow(params: signStart())
            try await Task.sleep(nanoseconds: 100_000_000)
            XCTAssertEqual(counter.value, 1, "\(path): the redelivered start did not run the handler again")
        }
    }

    /// A parent ending while a replay send is suspended releases the claimed child's route at once, and its failing
    /// send is not requeued even after later terminal events have evicted the parent from the bounded ended-flow list.
    func testAParentEndingDuringAReplayReleasesTheChildAndSurvivesEviction() async throws {
        let ctx = ScriptedPeerContext([.fail, .blockThenFail, .succeed])
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: signStart())
        profile.sessionResumed()
        for _ in 0..<200 where !ctx.blockedNow { try await Task.sleep(nanoseconds: 10_000_000) }
        let releasedBefore = ctx.releasedRoutes.filter { $0 == "c1" }.count
        await profile.handleComplete(params: FlowCompleteParams(flowId: "p1"))          // the parent ends
        XCTAssertGreaterThan(ctx.releasedRoutes.filter { $0 == "c1" }.count, releasedBefore, "the claimed child's route is released at once")
        for i in 0..<400 { await profile.handleComplete(params: FlowCompleteParams(flowId: "other-\(i)")) }   // evict p1
        ctx.releaseBlocked()                                                                                       // the send fails
        try await Task.sleep(nanoseconds: 100_000_000)
        profile.sessionResumed()
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertTrue(ctx.sent.isEmpty, "a cancelled child's answer is never sent")
    }

    /// Cancelling a child whose answer a replay is sending is a child cancel: the wallet's parent-flow callback is
    /// not invoked (it would reset the parent's guards).
    func testCancellingAReplayingChildDoesNotCancelTheParentInTheWallet() async throws {
        let ctx = ScriptedPeerContext([.fail, .blockThenFail, .succeed])
        var cancelled: [String] = []
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }, onCancel: { id, _ in cancelled.append(id) }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: signStart())
        profile.sessionResumed()
        for _ in 0..<200 where !ctx.blockedNow { try await Task.sleep(nanoseconds: 10_000_000) }
        await profile.handleCancel(params: FlowCancelParams(flowId: "c1"))
        XCTAssertTrue(cancelled.isEmpty, "only the child operation was cancelled")
        ctx.releaseBlocked()
    }

    /// A send that fails while the connection stays healthy (a failed POST on a live stream) brings no resume event:
    /// the queued answer is retried after a bounded backoff, without `sessionResumed()` and without running the
    /// handler again.
    func testAFailedSendIsRetriedWithoutAResumeEvent() async throws {
        let ctx = ScriptedPeerContext([.fail, .succeed])
        let counter = Counter()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in counter.bump(); return SignSubFlowResult(vpToken: "t") }, sendRetryDelaysMs: [10, 10]
        ))
        profile.initialize(ctx: ctx)
        _ = try await profile.startFlow(params: signStart())
        for _ in 0..<300 where ctx.sent.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(ctx.sent, ["c1"])
        XCTAssertEqual(counter.value, 1)
    }

    /// The retries are bounded: after the last one the answer waits for the next resume.
    func testRetriesAreBoundedAndTheAnswerWaitsForAResume() async throws {
        let ctx = ScriptedPeerContext([.fail, .fail, .fail, .succeed])
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }, sendRetryDelaysMs: [10, 10]
        ))
        profile.initialize(ctx: ctx)
        _ = try await profile.startFlow(params: signStart())
        try await Task.sleep(nanoseconds: 400_000_000)
        XCTAssertTrue(ctx.sent.isEmpty, "three failures: the original and two retries; no more timed retries")
        profile.sessionResumed()
        for _ in 0..<300 where ctx.sent.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(ctx.sent, ["c1"])
    }

    /// The retry budget belongs to each answer: one that used its retries up (cancelled, or still queued) does not
    /// starve the next child's first transient failure.
    func testTheRetryBudgetIsPerAnswerNotShared() async throws {
        // A exhausts its single retry and is cancelled; B then fails once and must still be retried.
        let ctx = ScriptedPeerContext([.fail, .fail, .fail, .succeed])
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }, sendRetryDelaysMs: [10]))
        profile.initialize(ctx: ctx)
        _ = try await profile.startFlow(params: signStart("c1", parent: "p1"))
        try await Task.sleep(nanoseconds: 200_000_000)                      // A's original and its one retry both failed
        await profile.handleCancel(params: FlowCancelParams(flowId: "p1"))
        _ = try await profile.startFlow(params: signStart("c2", parent: "p2"))
        for _ in 0..<300 where ctx.sent.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(ctx.sent, ["c2"], "B's first failure got its own timed retry")
        // The same with A still queued (not cancelled): B is retried, A's spent budget is not B's.
        let ctx2 = ScriptedPeerContext([.fail, .fail, .fail, .succeed, .succeed])
        let profile2 = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }, sendRetryDelaysMs: [10]))
        profile2.initialize(ctx: ctx2)
        _ = try await profile2.startFlow(params: signStart("c1", parent: "p1"))
        try await Task.sleep(nanoseconds: 200_000_000)
        _ = try await profile2.startFlow(params: signStart("c2", parent: "p2"))
        for _ in 0..<300 where !ctx2.sent.contains("c2") { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertTrue(ctx2.sent.contains("c2"))
    }

    /// A cancelled replay removes its marker when its send finishes, even though its parent is still in the ended-flow
    /// list: markers must not grow without bound over a long session.
    func testACancelledReplayLeavesNoCancellationMarkerBehind() async throws {
        for _ in 0..<5 {
            let ctx = ScriptedPeerContext([.fail, .blockThenFail])
            let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }, sendRetryDelaysMs: []))
            profile.initialize(ctx: ctx)
            await profile.runChildFlow(params: signStart())
            profile.sessionResumed()
            for _ in 0..<200 where !ctx.blockedNow { try await Task.sleep(nanoseconds: 10_000_000) }
            await profile.handleCancel(params: FlowCancelParams(flowId: "p1"))
            ctx.releaseBlocked()
            try await Task.sleep(nanoseconds: 100_000_000)
            XCTAssertEqual(profile.cancellationMarkerCount, 0)
        }
    }

    /// A timed retry belongs to its own answer: B's retry never resends an answer A that has already used its budget.
    func testATimedRetryDoesNotResendAnotherAnswerWhoseBudgetIsSpent() async throws {
        // A: original fails, its one retry fails (spent). B: original fails, its retry succeeds.
        let ctx = ScriptedPeerContext([.fail, .fail, .fail, .succeed, .succeed])
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }, sendRetryDelaysMs: [10]))
        profile.initialize(ctx: ctx)
        _ = try await profile.startFlow(params: signStart("c1", parent: "p1"))
        try await Task.sleep(nanoseconds: 200_000_000)
        _ = try await profile.startFlow(params: signStart("c2", parent: "p2"))
        for _ in 0..<300 where ctx.sent.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
        try await Task.sleep(nanoseconds: 150_000_000)
        XCTAssertEqual(ctx.sent, ["c2"], "A waits for a resume; only B's own retry went out")
        profile.sessionResumed()                                           // a resume still drains the whole queue
        for _ in 0..<300 where !ctx.sent.contains("c1") { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertTrue(ctx.sent.contains("c1"))
    }

    /// A retry timer scheduled before a resume is stale after it: the resume reset the budgets and replayed the queue, so
    /// the old timer must not send the answer again. No tight timing: both timers are due ~200 ms after being set, the
    /// test waits for the one live retry and then for the stale one's due time to have long passed, and only an UPPER
    /// bound on the number of sends is asserted.
    func testARetryTimerScheduledBeforeAResumeDoesNothingAfterIt() async throws {
        let ctx = ScriptedPeerContext([.fail, .fail, .fail, .fail, .fail, .fail])
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }, sendRetryDelaysMs: [200]))
        profile.initialize(ctx: ctx)
        _ = try await profile.startFlow(params: signStart())
        for _ in 0..<500 where ctx.attempts < 1 { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(ctx.attempts, 1, "the original send failed; timer T1 is pending")
        profile.sessionResumed()                                            // replay -> attempt 2 fails -> timer T2
        for _ in 0..<500 where ctx.attempts < 3 { try await Task.sleep(nanoseconds: 10_000_000) }   // T2 (the live one) retries
        XCTAssertGreaterThanOrEqual(ctx.attempts, 3)
        try await Task.sleep(nanoseconds: 800_000_000)                      // long past T1's due time
        XCTAssertEqual(ctx.attempts, 3, "original, the resume's replay and ONE timed retry: the stale timer sent nothing")
    }

    /// A catch-up after a resume drains only ITS OWN child. Child A's send stays suspended across a resume while B fails
    /// and is replayed; when A then fails, A's catch-up must not send B again (that would bypass B's retry limit).
    func testACatchUpAfterAResumeResendsOnlyItsOwnChild() async throws {
        // (a) A's ORIGINAL send is the suspended one.
        let a = ScriptedPeerContext([.blockThenFail, .fail, .fail, .fail, .fail])
        let profileA = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }, sendRetryDelaysMs: []))
        profileA.initialize(ctx: a)
        let startA = Task { _ = try await profileA.startFlow(params: self.signStart("c1", parent: "p1")) }
        for _ in 0..<300 where !a.blockedNow { try await Task.sleep(nanoseconds: 10_000_000) }
        _ = try await profileA.startFlow(params: signStart("c2", parent: "p2"))                    // B's original fails: queued
        for _ in 0..<300 where a.attempts < 2 { try await Task.sleep(nanoseconds: 10_000_000) }
        profileA.sessionResumed()                                                                   // replays B (fails), bumps the generation
        for _ in 0..<300 where a.attempts < 3 { try await Task.sleep(nanoseconds: 10_000_000) }
        a.releaseBlocked()                                                                          // A's original now fails: its catch-up
        for _ in 0..<300 where a.attempts < 4 { try await Task.sleep(nanoseconds: 10_000_000) }
        try await Task.sleep(nanoseconds: 300_000_000)
        _ = await startA.result
        XCTAssertEqual(a.attemptedIds.filter { $0 == "c2" }.count, 2, "B: its original and its replay only; \(a.attemptedIds)")
        XCTAssertEqual(a.attemptedIds.filter { $0 == "c1" }.count, 2, "A: its original and its own catch-up; \(a.attemptedIds)")
        // (b) A's REPLAY is the suspended one.
        let b = ScriptedPeerContext([.fail, .blockThenFail, .fail, .fail, .fail, .fail])
        let profileB = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in SignSubFlowResult(vpToken: "t") }, sendRetryDelaysMs: []))
        profileB.initialize(ctx: b)
        _ = try await profileB.startFlow(params: signStart("c1", parent: "p1"))                    // A's original fails: queued
        for _ in 0..<300 where b.attempts < 1 { try await Task.sleep(nanoseconds: 10_000_000) }
        profileB.sessionResumed()                                                                   // A's replay is suspended
        for _ in 0..<300 where !b.blockedNow { try await Task.sleep(nanoseconds: 10_000_000) }
        _ = try await profileB.startFlow(params: signStart("c2", parent: "p2"))                    // B's original fails: queued
        for _ in 0..<300 where b.attempts < 3 { try await Task.sleep(nanoseconds: 10_000_000) }
        profileB.sessionResumed()                                                                   // replays B (fails)
        for _ in 0..<300 where b.attempts < 4 { try await Task.sleep(nanoseconds: 10_000_000) }
        b.releaseBlocked()                                                                          // A's replay fails: its catch-up
        for _ in 0..<300 where b.attempts < 5 { try await Task.sleep(nanoseconds: 10_000_000) }
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(b.attemptedIds.filter { $0 == "c2" }.count, 2, "B: its original and its replay only; \(b.attemptedIds)")
        XCTAssertEqual(b.attemptedIds.filter { $0 == "c1" }.count, 3, "A: original, replay and its own catch-up; \(b.attemptedIds)")
    }

    /// `onCancel` is told the flow type the flow was started as: an `oid4vp` parent's cancel is recognisable as one.
    func testOnCancelCarriesTheFlowTypeTheFlowStartedAs() async throws {
        let ctx = MockPeerContext()
        let seen = Counter()
        var received: [(String, String?)] = []
        let profile = OpenID4xProfile(config: OpenID4xConfig(onCancel: { id, type in received.append((id, type)); seen.bump() }))
        profile.initialize(ctx: ctx)
        _ = try await profile.startFlow(params: FlowStartParams(wmp: WmpMeta(), flowId: "v1", flowType: "oid4vp"))
        _ = try await profile.startFlow(params: FlowStartParams(wmp: WmpMeta(), flowId: "i1", flowType: "oid4vci"))
        await profile.handleCancel(params: FlowCancelParams(flowId: "v1"))
        await profile.handleCancel(params: FlowCancelParams(flowId: "i1"))
        await profile.handleCancel(params: FlowCancelParams(flowId: "never-started"))
        XCTAssertEqual(received.map(\.0), ["v1", "i1", "never-started"])
        XCTAssertEqual(received.map { $0.1 ?? "nil" }, ["oid4vp", "oid4vci", "nil"])
    }

    func testRepeatedShutdownNotifiesTheApplicationOnce() {
        var told = 0
        let profile = OpenID4xProfile(config: OpenID4xConfig(onShutdown: { told += 1 }))
        profile.shutdown(); profile.shutdown(); profile.shutdown()
        XCTAssertEqual(told, 1)
    }

    func testAMalformedSignPayloadIsInvalidParamsNotASignFailure() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
            XCTFail("a payload that does not decode never reaches the handler"); return SignSubFlowResult()
        }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "sign", params: ["parent_flow_id": .string("p"), "action": .int(7)]))
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowError)
        XCTAssertEqual(ctx.notifications[0].params?["data"]?.objectValue?["error_code"], .string("INVALID_PARAMS"))
    }

    /// A redelivered start while the terminal answer is still being sent runs no second handler.
    func testARedeliveredStartDuringTheTerminalSendRunsNoSecondHandler() async throws {
        let ctx = BlockingPeerContext()
        let counter = Counter()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in counter.bump(); return SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        let start = childStart(flowType: "sign", flowId: "c-r", params: ["action": .string("sign_presentation"), "parent_flow_id": .string("vp")])
        _ = try await profile.startFlow(params: start)
        for _ in 0..<200 where !ctx.inNotify { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertTrue(ctx.inNotify, "the answer is mid-send")
        _ = try await profile.startFlow(params: start)
        try await Task.sleep(nanoseconds: 100_000_000)
        ctx.unblock()
        try await Task.sleep(nanoseconds: 100_000_000)
        XCTAssertEqual(counter.value, 1)
    }

    /// An answer that could not be sent while the connection was down goes out when the session resumes, without
    /// running the handler again; a redelivered start meanwhile does not run it either.
    func testAnUnsentAnswerIsSentAfterResumeWithoutRerunningTheHandler() async throws {
        let ctx = FlakyPeerContext()
        let counter = Counter()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in counter.bump(); return SignSubFlowResult(vpToken: "t") }))
        profile.initialize(ctx: ctx)
        let start = childStart(flowType: "sign", flowId: "c-u", params: ["action": .string("sign_presentation"), "parent_flow_id": .string("vp")])
        await profile.runChildFlow(params: start)
        XCTAssertEqual(ctx.sent.count, 0, "the send failed")
        _ = try await profile.startFlow(params: start)
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(counter.value, 1, "no second handler")
        ctx.failing = false
        profile.sessionResumed()
        for _ in 0..<200 where ctx.sent.isEmpty { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(ctx.sent.first?.method, WmpMethods.flowComplete)
        XCTAssertEqual(counter.value, 1)
    }

    func testCancellingTheParentCancelsItsChildren() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        let ctx = MockPeerContext()
        let gate = Gate()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
            while await !gate.isOpen { try await Task.sleep(nanoseconds: 10_000_000) }
            return SignSubFlowResult(vpToken: "late")
        }))
        profile.initialize(ctx: ctx)
        _ = try await profile.startFlow(params: childStart(flowType: "sign", flowId: "c-y", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("vp-2"),
        ]))
        await profile.handleCancel(params: FlowCancelParams(flowId: "vp-2"))
        await gate.release()
        try await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertTrue(ctx.notifications.isEmpty)
    }

    /// A parent that completes or fails, or a session that ends, stops the children still suspended for it.
    func testTerminalParentMessagesAndShutdownStopSuspendedChildren() async throws {
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        for trigger in ["complete", "error", "shutdown"] {
            let ctx = MockPeerContext()
            let gate = Gate()
            let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
                while await !gate.isOpen { try await Task.sleep(nanoseconds: 10_000_000) }
                return SignSubFlowResult(vpToken: "late")
            }))
            profile.initialize(ctx: ctx)
            _ = try await profile.startFlow(params: childStart(flowType: "sign", flowId: "c-\(trigger)", params: [
                "action": .string("sign_presentation"), "parent_flow_id": .string("vp-\(trigger)"),
            ]))
            switch trigger {
            case "complete": await profile.handleComplete(params: FlowCompleteParams(flowId: "vp-complete"))
            case "error": await profile.handleError(params: FlowErrorParams(flowId: "vp-error", code: "x"))
            default: profile.shutdown()
            }
            XCTAssertTrue(ctx.released.contains("c-\(trigger)"), "\(trigger): the child's routing entry is released at once, not when the handler returns")
            await gate.release()
            try await Task.sleep(nanoseconds: 250_000_000)
            XCTAssertTrue(ctx.notifications.isEmpty, trigger)
        }
    }

    /// After `shutdown()` a child start that was still buffered runs no handler.
    /// A child that is already run directly (as a queued task is) after shutdown never enters its handler.
    func testAShutDownProfileNeverEntersTheHandlerOfAQueuedChild() async throws {
        let ctx = MockPeerContext()
        var entered = false
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
            entered = true
            return SignSubFlowResult(vpToken: "x")
        }, onMatchRequest: { _, _ in
            entered = true
            return MatchResult(matches: [])
        }))
        profile.initialize(ctx: ctx)
        profile.shutdown()
        await profile.runChildFlow(params: childStart(flowType: "sign", params: ["action": .string("sign_presentation")]))
        await profile.runChildFlow(params: childStart(flowType: "match", flowId: "m", params: ["dcql_query": .object_([:])]))
        XCTAssertFalse(entered)
        XCTAssertTrue(ctx.notifications.isEmpty)
    }

    /// An ordinary failure of a match handler is a MATCH_ERROR, as on the progress-step route.
    func testAMatchChildFailureIsReportedAsMatchError() async throws {
        struct Boom: Error {}
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onMatchRequest: { _, _ in throw Boom() }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "match", flowId: "m", params: ["dcql_query": .object_([:])]))
        XCTAssertEqual(ctx.notifications.first?.params?["message"], .string("MATCH_ERROR"))
        XCTAssertEqual(ctx.notifications.first?.params?["data"]?.objectValue?["error_code"], .string("MATCH_ERROR"))
    }

    /// A child start for a parent that already ended is dropped, and a redelivered start never launches a second
    /// handler or replaces the first one's tracking.
    func testStartsForEndedParentsAndDuplicateStartsAreDropped() async throws {
        actor Counter { var n = 0; func bump() { n += 1 }; var value: Int { n } }
        actor Gate { var open = false; func release() { open = true }; var isOpen: Bool { open } }
        let ctx = MockPeerContext()
        let counter = Counter()
        let gate = Gate()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
            await counter.bump()
            while await !gate.isOpen { try await Task.sleep(nanoseconds: 10_000_000) }
            return SignSubFlowResult(vpToken: "t")
        }))
        profile.initialize(ctx: ctx)
        // A local parent cancel arrives before the child's start does.
        await profile.handleCancel(params: FlowCancelParams(flowId: "vp-gone"))
        _ = try await profile.startFlow(params: childStart(flowType: "sign", flowId: "late", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("vp-gone"),
        ]))
        // The same child delivered twice while its handler is suspended.
        for _ in 0..<2 {
            _ = try await profile.startFlow(params: childStart(flowType: "sign", flowId: "dup", params: [
                "action": .string("sign_presentation"), "parent_flow_id": .string("vp-live"),
            ]))
        }
        try await Task.sleep(nanoseconds: 150_000_000)
        let entered = await counter.value
        XCTAssertEqual(entered, 1, "the ended parent's child and the redelivered start run no handler")
        await gate.release()
        try await Task.sleep(nanoseconds: 200_000_000)
        XCTAssertEqual(ctx.notifications.filter { $0.method == WmpMethods.flowComplete }.count, 1)
    }

    func testShutdownTellsTheApplication() {
        var told = 0
        let profile = OpenID4xProfile(config: OpenID4xConfig(onShutdown: { told += 1 }))
        profile.shutdown()
        XCTAssertEqual(told, 1)
    }

    /// The application hears of a shutdown last: by then the profile is stopped and its children are already
    /// released, so nothing the callback does can race a child that is still live.
    func testTheApplicationIsToldOfShutdownAfterTheChildrenAreReleased() async throws {
        let ctx = MockPeerContext()
        var releasedWhenTold: [String]?
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in
                try await Task.sleep(nanoseconds: 5_000_000_000)
                return SignSubFlowResult()
            },
            onShutdown: { releasedWhenTold = ctx.released }
        ))
        profile.initialize(ctx: ctx)
        _ = try await profile.startFlow(params: childStart(flowType: "sign", flowId: "c-live", params: [
            "action": .string("sign_presentation"), "parent_flow_id": .string("vp-1"),
        ]))
        profile.shutdown()
        XCTAssertEqual(releasedWhenTold?.contains("c-live"), true)
    }

    func testNoChildStartsAfterShutdown() async throws {
        let ctx = MockPeerContext()
        var ran = false
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
            ran = true
            return SignSubFlowResult(vpToken: "x")
        }))
        profile.initialize(ctx: ctx)
        profile.shutdown()
        _ = try await profile.startFlow(params: childStart(flowType: "sign", params: ["action": .string("sign_presentation")]))
        try await Task.sleep(nanoseconds: 150_000_000)
        XCTAssertFalse(ran)
        XCTAssertTrue(ctx.notifications.isEmpty)
    }

    func testAnIntegerFlowErrorCodeFromThePeerDecodes() throws {
        let params = try JSONDecoder().decode(FlowErrorParams.self, from: Data(#"{"flow_id":"f","code":-31006,"message":"m"}"#.utf8))
        XCTAssertEqual(params.code, "-31006")
        let text = try JSONDecoder().decode(FlowErrorParams.self, from: Data(#"{"flow_id":"f","code":"X","message":"m"}"#.utf8))
        XCTAssertEqual(text.code, "X")
    }

    func testAMatchChildFlowIsAnsweredWithTheMatchesAsTheResult() async throws {
        let ctx = MockPeerContext()
        var seenParent: String?
        let profile = OpenID4xProfile(config: OpenID4xConfig(onMatchRequest: { flowId, payload in
            seenParent = flowId
            XCTAssertNotNil(payload?.objectValue?["dcql_query"])
            return MatchResult(matches: [CredentialMatch(credentialQueryId: "pid", credentialId: "7", format: "dc+sd-jwt")])
        }))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "match", flowId: "m-1", params: [
            "dcql_query": .object_(["credentials": .array([])]), "parent_flow_id": .string("vp-1"),
        ]))
        XCTAssertEqual(seenParent, "vp-1")
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowComplete)
        XCTAssertEqual(ctx.notifications[0].params?["flow_id"], .string("m-1"))
        let matches = ctx.notifications[0].params?["result"]?.objectValue?["matches"]?.arrayValue
        XCTAssertEqual(matches?.count, 1)
        XCTAssertEqual(matches?.first?.objectValue?["credential_id"], .string("7"))
    }

    func testStartingAChildFlowReturnsAtOnceAndAnswersLater() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in
            try await Task.sleep(nanoseconds: 50_000_000)
            return SignSubFlowResult(vpToken: "tok")
        }))
        profile.initialize(ctx: ctx)
        let started = try await profile.startFlow(params: childStart(flowType: "sign", params: ["action": .string("sign_presentation")]))
        XCTAssertEqual(started.flowId, "child-1")
        XCTAssertTrue(ctx.notifications.isEmpty, "the start request is not held until the user answers")
        for _ in 0..<100 where ctx.notifications.isEmpty { try await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertEqual(ctx.notifications.first?.method, WmpMethods.flowComplete)
        XCTAssertEqual(ctx.notifications.first?.params?["result"]?.objectValue?["vp_token"], .string("tok"))
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

        await profile.runChildFlow(params: childStart(flowType: "match", parent: "flow-4", payload: nil))

        XCTAssertEqual(ctx.notifications.count, 1)
        let params = ctx.notifications[0].params?["result"]?.objectValue
        XCTAssertNil(params?["action"])
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

        await profile.runChildFlow(params: childStart(flowType: "match", parent: "flow-5", payload: nil))

        let result = ctx.notifications.first?.params?["result"]?.objectValue
        XCTAssertEqual(result?["matches"]?.arrayValue?.count, 1)
        XCTAssertNil(result?["no_match_reason"])
    }

    private func trustRequired(_ extra: [String: AnyCodable] = [:]) -> AnyCodable {
        var members: [String: AnyCodable] = ["trust_evaluation_required": .bool(true)]
        for (k, v) in extra { members[k] = v }
        return .object_(members)
    }

    func testMarkedTrustProgressIsAnsweredWithTheMembersUnderParams() async throws {
        let ctx = MockPeerContext()
        var receivedFlowId: String?
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onTrustEvaluation: { flowId, _ in
                receivedFlowId = flowId
                return TrustResult(trusted: true, framework: "eidas", reason: nil)
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.handleProgress(params: FlowProgressParams(flowId: "flow-3", step: VCIStep.evaluatingTrust, payload: trustRequired()))

        XCTAssertEqual(receivedFlowId, "flow-3")
        XCTAssertEqual(ctx.notifications.count, 1)
        let notification = ctx.notifications[0]
        XCTAssertEqual(notification.method, WmpMethods.flowAction)
        XCTAssertEqual(notification.params?["action"], .string("trust_result"))
        XCTAssertNil(notification.params?["trusted"], "go-wmp reads the members under `params`, not next to `action`")
        let members = notification.params?["params"]?.objectValue
        XCTAssertEqual(members?["trusted"], .bool(true))
        XCTAssertEqual(members?["framework"], .string("eidas"))
    }

    func testVerifierTrustProgressIsAnsweredToo() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(onTrustEvaluation: { _, _ in TrustResult(trusted: true) }))
        profile.initialize(ctx: ctx)
        await profile.handleProgress(params: FlowProgressParams(flowId: "f", step: VPStep.evaluatingVerifierTrust, payload: trustRequired()))
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].params?["action"], .string("trust_result"))
    }

    /// The engine's informational `evaluating_trust` progress is not a request, and neither is a bare
    /// `trust_evaluation_required` step name: an early answer could satisfy the engine's later wait.
    func testInformationalTrustProgressIsNotAnswered() async throws {
        let ctx = MockPeerContext()
        var progress: [String] = []
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onProgress: { _, step, _ in progress.append(step) },
            onTrustEvaluation: { _, _ in
                XCTFail("an unmarked progress must not reach the trust handler")
                return TrustResult(trusted: true)
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.handleProgress(params: FlowProgressParams(flowId: "f", step: VCIStep.evaluatingTrust, payload: nil))
        await profile.handleProgress(params: FlowProgressParams(flowId: "f", step: VPStep.evaluatingVerifierTrust, payload: .object_(["trust_evaluation_required": .bool(false)])))
        await profile.handleProgress(params: FlowProgressParams(flowId: "f", step: "trust_evaluation_required", payload: nil))
        XCTAssertTrue(ctx.notifications.isEmpty)
        XCTAssertEqual(progress.count, 3, "they are passed on as ordinary progress")
    }

    /// Sign and match are child flows now; a progress step of that name is only progress.
    func testSignAndMatchProgressStepsNoLongerRunHandlers() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in XCTFail("sign runs from a child flow only"); return SignSubFlowResult() },
            onMatchRequest: { _, _ in XCTFail("match runs from a child flow only"); return MatchResult(matches: []) }
        ))
        profile.initialize(ctx: ctx)
        for step in ["sign_request", "match_request", VCIStep.generatingProof, VPStep.matchingCredentials] {
            await profile.handleProgress(params: FlowProgressParams(flowId: "f", step: step, payload: try buildSignPayload()))
        }
        XCTAssertTrue(ctx.notifications.isEmpty)
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

    func testSignChildHandlerErrorSendsFlowError() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in
                struct SignError: Error, LocalizedError { var errorDescription: String? { "key not found" } }
                throw SignError()
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: childStart(flowType: "sign", parent: "flow-7", payload: try buildSignPayload()))
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowError)
        XCTAssertEqual(ctx.notifications[0].params?["flow_id"], .string("child-1"))
        XCTAssertEqual(ctx.notifications[0].params?["code"], .int(-31006))
        XCTAssertEqual(ctx.notifications[0].params?["data"]?.objectValue?["error_code"], .string("SIGN_ERROR"))
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
        await profile.runChildFlow(params: childStart(flowType: "sign", parent: "flow-8", payload: try buildSignPayload()))
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].params?["code"], .int(-31006))
        XCTAssertEqual(ctx.notifications[0].params?["data"]?.objectValue?["error_code"], .string("invalid_transaction_data"))
        if case .string(let message) = ctx.notifications[0].params?["message"] {
            XCTAssertEqual(message, "invalid_transaction_data", "only the code goes to the peer, no developer text")
        } else {
            XCTFail("expected a message")
        }
    }

    func testTrustHandlerErrorSendsUntrustedResult() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onTrustEvaluation: { _, _ in
                struct TrustError: Error {}
                throw TrustError()
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.handleProgress(params: FlowProgressParams(
            flowId: "flow-8", step: VCIStep.evaluatingTrust, payload: .object_(["trust_evaluation_required": .bool(true)])
        ))
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowAction)
        XCTAssertEqual(ctx.notifications[0].params?["params"]?.objectValue?["trusted"], .bool(false), "a failed evaluation is untrusted")
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

    func testSignChildWithNoParamsSendsFlowError() async throws {
        let ctx = MockPeerContext()
        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { _, _ in
                XCTFail("handler should not be called when params are missing")
                return SignSubFlowResult()
            }
        ))
        profile.initialize(ctx: ctx)
        await profile.runChildFlow(params: FlowStartParams(wmp: WmpMeta(), flowId: "child-1", flowType: "sign", params: nil))
        XCTAssertEqual(ctx.notifications.count, 1)
        XCTAssertEqual(ctx.notifications[0].method, WmpMethods.flowError)
        XCTAssertEqual(ctx.notifications[0].params?["code"], .int(-31006))
        XCTAssertEqual(ctx.notifications[0].params?["data"]?.objectValue?["error_code"], .string("INVALID_PARAMS"))
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

// MARK: - Peer doubles for the terminal-send cases

private final class Counter: @unchecked Sendable {
    private let lock = NSLock(); private var n = 0
    func bump() { lock.lock(); n += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
}

/// `notify` suspends until `unblock()`.
private final class BlockingPeerContext: WmpPeerContext, @unchecked Sendable {
    let codec = WmpCodec()
    private let lock = NSLock()
    private var blocked: CheckedContinuation<Void, Never>?
    private var opened = false
    private var _inNotify = false
    var inNotify: Bool { lock.lock(); defer { lock.unlock() }; return _inNotify }
    func releaseFlow(flowId: String) {}
    func notify(method: String, params: [String: AnyCodable]?) async throws {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            lock.lock(); _inNotify = true
            if opened { lock.unlock(); c.resume() } else { blocked = c; lock.unlock() }
        }
    }
    func unblock() { lock.lock(); opened = true; let c = blocked; blocked = nil; lock.unlock(); c?.resume() }
    func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse { JsonRpcResponse(id: "m", result: [:]) }
}

/// `notify` throws while `failing`.
private final class FlakyPeerContext: WmpPeerContext, @unchecked Sendable {
    let codec = WmpCodec()
    private let lock = NSLock()
    private var _failing = true
    private var _sent: [(method: String, params: [String: AnyCodable]?)] = []
    var failing: Bool { get { lock.lock(); defer { lock.unlock() }; return _failing } set { lock.lock(); _failing = newValue; lock.unlock() } }
    var sent: [(method: String, params: [String: AnyCodable]?)] { lock.lock(); defer { lock.unlock() }; return _sent }
    func releaseFlow(flowId: String) {}
    func notify(method: String, params: [String: AnyCodable]?) async throws {
        if failing { throw WmpSessionError.connectionFailed }
        lock.lock(); _sent.append((method, params)); lock.unlock()
    }
    func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse { JsonRpcResponse(id: "m", result: [:]) }
}

/// Fails every send until `startReplay()`, then suspends each send until `release()`, recording what went out.
private final class ReplayPeerContext: WmpPeerContext, @unchecked Sendable {
    let codec = WmpCodec()
    private let lock = NSLock()
    private var replaying = false
    private var blocked: [CheckedContinuation<Void, Never>] = []
    private var open = false
    private var _inFlight: [String] = []
    private var _sent: [String] = []
    var inFlight: [String] { lock.lock(); defer { lock.unlock() }; return _inFlight }
    var sentFlowIds: [String] { lock.lock(); defer { lock.unlock() }; return _sent }
    func startReplay() { lock.lock(); replaying = true; lock.unlock() }
    func release() {
        lock.lock(); open = true; let all = blocked; blocked = []; lock.unlock()
        for c in all { c.resume() }
    }
    private var _released: [String] = []
    var released: [String] { lock.lock(); defer { lock.unlock() }; return _released }
    func releaseFlow(flowId: String) { lock.lock(); _released.append(flowId); lock.unlock() }
    func notify(method: String, params: [String: AnyCodable]?) async throws {
        lock.lock(); let go = replaying; lock.unlock()
        if !go { throw WmpSessionError.connectionFailed }
        let id = params?["flow_id"]?.stringValue ?? "?"
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            lock.lock(); _inFlight.append(id)
            if open { lock.unlock(); c.resume() } else { blocked.append(c); lock.unlock() }
        }
        lock.lock(); _sent.append(id); lock.unlock()
    }
    func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse { JsonRpcResponse(id: "m", result: [:]) }
}

/// The first `notify` suspends until `releaseFailing()` and then throws; later ones succeed and are recorded.
private final class FailAfterReleaseContext: WmpPeerContext, @unchecked Sendable {
    let codec = WmpCodec()
    private let lock = NSLock()
    private var first = true
    private var blocked: CheckedContinuation<Void, Never>?
    private var released = false
    private var _inFirst = false
    private var _sent: [String] = []
    var inFirstNotify: Bool { lock.lock(); defer { lock.unlock() }; return _inFirst }
    var sent: [String] { lock.lock(); defer { lock.unlock() }; return _sent }
    func releaseFailing() { lock.lock(); released = true; let c = blocked; blocked = nil; lock.unlock(); c?.resume() }
    func releaseFlow(flowId: String) {}
    func notify(method: String, params: [String: AnyCodable]?) async throws {
        lock.lock(); let isFirst = first; first = false; lock.unlock()
        if isFirst {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                lock.lock(); _inFirst = true
                if released { lock.unlock(); c.resume() } else { blocked = c; lock.unlock() }
            }
            throw WmpSessionError.connectionFailed
        }
        lock.lock(); _sent.append(params?["flow_id"]?.stringValue ?? "?"); lock.unlock()
    }
    func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse { JsonRpcResponse(id: "m", result: [:]) }
}

/// Each `notify` takes the next scripted behaviour: fail at once, suspend until released and then fail, or succeed.
private final class ScriptedPeerContext: WmpPeerContext, @unchecked Sendable {
    enum Step { case fail, blockThenFail, succeed }
    let codec = WmpCodec()
    private let lock = NSLock()
    private var script: [Step]
    private var blocked: CheckedContinuation<Void, Never>?
    private var released = false
    private var _blockedNow = false
    private var _sent: [String] = []
    init(_ script: [Step]) { self.script = script }
    var blockedNow: Bool { lock.lock(); defer { lock.unlock() }; return _blockedNow }
    var sent: [String] { lock.lock(); defer { lock.unlock() }; return _sent }
    private var _attempts = 0
    var attempts: Int { lock.lock(); defer { lock.unlock() }; return _attempts }
    private var _attemptedIds: [String] = []
    /// The child flow each `notify` call carried, in call order.
    var attemptedIds: [String] { lock.lock(); defer { lock.unlock() }; return _attemptedIds }
    func releaseBlocked() { lock.lock(); released = true; let c = blocked; blocked = nil; lock.unlock(); c?.resume() }
    private var _routes: [String] = []
    var releasedRoutes: [String] { lock.lock(); defer { lock.unlock() }; return _routes }
    func releaseFlow(flowId: String) { lock.lock(); _routes.append(flowId); lock.unlock() }
    func notify(method: String, params: [String: AnyCodable]?) async throws {
        lock.lock(); _attempts += 1; _attemptedIds.append(params?["flow_id"]?.stringValue ?? "?"); let step = script.isEmpty ? Step.succeed : script.removeFirst(); lock.unlock()
        switch step {
        case .fail: throw WmpSessionError.connectionFailed
        case .blockThenFail:
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                lock.lock(); _blockedNow = true
                if released { lock.unlock(); c.resume() } else { blocked = c; lock.unlock() }
            }
            throw WmpSessionError.connectionFailed
        case .succeed:
            lock.lock(); _sent.append(params?["flow_id"]?.stringValue ?? "?"); lock.unlock()
        }
    }
    func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse { JsonRpcResponse(id: "m", result: [:]) }
}
