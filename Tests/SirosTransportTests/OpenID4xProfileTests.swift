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
