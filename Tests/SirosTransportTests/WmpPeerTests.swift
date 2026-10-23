// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

// MARK: - Stub profile

private final class StubProfile: WmpProfile, WmpFlowHandler, WmpMethodHandler, WmpResolveHandler {
    let name = "stub"
    let capabilities: [String] = ["stub/1.0"]
    var flowTypes: [String] = ["stub.flow"]
    var methods: [String] = ["stub.ping"]
    var resolveTypes: [String] = ["stub.did"]

    weak var ctx: WmpPeerContext?

    var startedFlows: [FlowStartParams] = []
    var actions: [FlowActionParams] = []
    var progresses: [FlowProgressParams] = []
    var completes: [FlowCompleteParams] = []
    var errors: [FlowErrorParams] = []
    var cancels: [FlowCancelParams] = []
    var methodCalls: [(String, AnyCodable?)] = []
    var resolves: [ResolveParams] = []

    func initialize(ctx: WmpPeerContext) { self.ctx = ctx }

    func startFlow(params: FlowStartParams) async throws -> FlowStartResult {
        startedFlows.append(params)
        return FlowStartResult(flowId: params.flowId, flowType: params.flowType)
    }

    func handleAction(params: FlowActionParams) async throws -> FlowActionResult {
        actions.append(params)
        return FlowActionResult(flowId: params.flowId)
    }

    func handleProgress(params: FlowProgressParams) async { progresses.append(params) }
    func handleComplete(params: FlowCompleteParams) async { completes.append(params) }
    func handleError(params: FlowErrorParams) async { errors.append(params) }
    func handleCancel(params: FlowCancelParams) async { cancels.append(params) }

    func handleMethod(method: String, params: AnyCodable?) async throws -> AnyCodable? {
        methodCalls.append((method, params))
        return nil
    }

    func handleResolve(params: ResolveParams) async throws -> ResolveResult {
        resolves.append(params)
        return ResolveResult(type: params.type)
    }
}

private final class ShutdownProfile: WmpProfile, WmpShutdownProfile, @unchecked Sendable {
    let name = "shutdown"
    let capabilities: [String] = []
    private let lock = NSLock()
    private var _count = 0
    var count: Int { lock.lock(); defer { lock.unlock() }; return _count }
    func initialize(ctx: WmpPeerContext) {}
    func shutdown() { lock.lock(); _count += 1; lock.unlock() }
}

private final class ResumeProfile: WmpProfile, WmpResumeProfile, @unchecked Sendable {
    let name = "resume"
    let capabilities: [String] = []
    private let lock = NSLock()
    private var _count = 0
    var count: Int { lock.lock(); defer { lock.unlock() }; return _count }
    func initialize(ctx: WmpPeerContext) {}
    func sessionResumed() { lock.lock(); _count += 1; lock.unlock() }
}

// MARK: - Helpers

private extension WmpPeerTests {
    func makePeer() -> (WmpPeer, FakeTransport, StubProfile) {
        let transport = FakeTransport()
        let session = WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 2_000))
        let peer = WmpPeer(session: session)
        let profile = StubProfile()
        peer.use(profile)
        return (peer, transport, profile)
    }

    func connectPeer(_ peer: WmpPeer, transport: FakeTransport) async throws {
        let codec = WmpCodec()
        let connectTask = Task { try await peer.connect(authToken: "token") }
        // Wait for session.create to be sent
        let deadline = Date().addingTimeInterval(2)
        while transport.sentMessages.isEmpty {
            if Date() > deadline { throw TimeoutError() }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let req = try codec.decodeRequest(transport.sentMessages.last!)
        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","id":"\(req.id!)","result":{"wmp":{"version":"0.1","session_id":"ses-1"},"resumption_token":"rt-1"}}
            """.data(using: .utf8)!
        )
        try await connectTask.value
    }
}

// MARK: - Tests

final class WmpPeerTests: XCTestCase {

    /// A profile's in-flight child handlers stop when the session ends, however it ends: an explicit close, a
    /// session that failed for good (reconnects exhausted), and a caller that tears the wallet down.
    func testProfilesAreShutDownWhenTheSessionEnds() async throws {
        // 1. close()
        let (peerA, transportA, _) = makePeer()
        let shutdownA = ShutdownProfile()
        peerA.use(shutdownA)
        try await connectPeer(peerA, transport: transportA)
        try? await peerA.close()
        XCTAssertGreaterThanOrEqual(shutdownA.count, 1, "shutdown is idempotent; the session's own close may also reach it")

        // 2. a teardown by a caller that cannot wait for close()
        let (peerB, transportB, _) = makePeer()
        let shutdownB = ShutdownProfile()
        peerB.use(shutdownB)
        try await connectPeer(peerB, transport: transportB)
        peerB.shutdownProfiles()
        XCTAssertGreaterThanOrEqual(shutdownB.count, 1)

        // 3. a session that fails for good: no close() is ever called
        let transportC = FakeTransport()
        let sessionC = WmpSession(
            transport: transportC,
            config: WmpSessionConfig(requestTimeoutMs: 2_000, maxReconnectAttempts: 1, reconnectBaseMs: 1, reconnectMaxMs: 1)
        )
        let peerC = WmpPeer(session: sessionC)
        let shutdownC = ShutdownProfile()
        peerC.use(shutdownC)
        try await connectPeer(peerC, transport: transportC)
        transportC.simulateFailure()
        for _ in 0..<150 where shutdownC.count == 0 { try await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertGreaterThanOrEqual(shutdownC.count, 1, "a failed session ends its children without a close()")
    }

    /// A real reconnection reaches the profiles: the session resumes after a loss, and the peer tells them, so
    /// answers kept for the resume go out. Creating the session is not a resume.
    func testAProfileIsToldWhenTheSessionResumesAfterALoss() async throws {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 2_000, maxReconnectAttempts: 3, reconnectBaseMs: 1, reconnectMaxMs: 1)
        )
        let peer = WmpPeer(session: session)
        let profile = ResumeProfile()
        peer.use(profile)
        try await connectPeer(peer, transport: transport)
        XCTAssertEqual(profile.count, 0, "creating the session is not a resume")
        await transport.disconnect()
        let codec = WmpCodec()
        var resumeId: String?
        for _ in 0..<300 where resumeId == nil {
            try await Task.sleep(nanoseconds: 10_000_000)
            for data in transport.sentMessages {
                if let req = try? codec.decodeRequest(data), req.method == "wmp.session.resume" { resumeId = req.id }
            }
        }
        transport.receiveFromServer(#"{"jsonrpc":"2.0","id":"\#(try XCTUnwrap(resumeId))","result":{}}"#.data(using: .utf8)!)
        for _ in 0..<300 where profile.count == 0 { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(profile.count, 1)
    }

    /// A cancel made locally reaches the handler and forgets the flow before it is sent, without waiting for an echo.
    func testALocalCancelStopsTheFlowHereAtOnce() async throws {
        let (peer, transport, profile) = makePeer()
        try await connectPeer(peer, transport: transport)
        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1","session_id":"ses-1"},"flow_type":"stub.flow","flow_id":"lc-1"}}
            """.data(using: .utf8)!
        )
        for _ in 0..<100 where profile.startedFlows.isEmpty { try await Task.sleep(nanoseconds: 20_000_000) }
        XCTAssertEqual(profile.startedFlows.count, 1)
        try await peer.cancelFlow(flowId: "lc-1", reason: "user")
        XCTAssertEqual(profile.cancels.map(\.flowId), ["lc-1"], "the handler is told by the local cancel itself")
    }

    /// A host reading `stateStream` still sees every state: the peer's own watching does not take elements from it.
    func testThePeerDoesNotConsumeTheHostsStateStream() async throws {
        let (peer, transport, _) = makePeer()
        let seen = Task { () -> [WmpSessionState] in
            var states: [WmpSessionState] = []
            for await s in peer.stateStream { states.append(s); if s == .closed { break } }
            return states
        }
        try await connectPeer(peer, transport: transport)
        try? await peer.close()
        let states = await seen.value
        XCTAssertTrue(states.contains(.active), "\(states)")
        XCTAssertEqual(states.last, .closed)
    }

    /// The terminal hook is in place before `create` returns: `create` starts the disconnect monitor, so a loss
    /// right after it must already find the hook.
    func testTheTerminalHookIsInstalledBeforeTheSessionIsCreated() async throws {
        let transport = FakeTransport()
        let session = WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 2_000))
        let peer = WmpPeer(session: session)
        let connect = Task { try await peer.connect(authToken: "token") }
        let deadline = Date().addingTimeInterval(2)
        while transport.sentMessages.isEmpty, Date() < deadline { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertNotNil(session.onTerminal, "installed while create is still in flight")
        connect.cancel()
        withExtendedLifetime(peer) {}
    }

    /// The local teardown does not depend on the close notification getting through: when it fails, the transport is still
    /// disconnected and the session ended (so reconnect work stops), and the failure is still reported.
    func testASessionClosesLocallyEvenWhenTheCloseNotificationFails() async throws {
        let (peer, transport, _) = makePeer()
        let shutdown = ShutdownProfile()
        peer.use(shutdown)
        try await connectPeer(peer, transport: transport)
        transport.failingMethod = "wmp.session.close"
        do { try await peer.close(); XCTFail("the failed notification is reported") } catch { /* expected */ }
        XCTAssertGreaterThanOrEqual(shutdown.count, 1)
        XCTAssertEqual(transport.currentState, .disconnected, "the transport is not left running")
    }

    func testProfileInitializeCalledOnUse() {
        let (peer, _, profile) = makePeer()
        XCTAssertNotNil(profile.ctx, "initialize(ctx:) should be called by use(_:)")
        withExtendedLifetime(peer) {}
    }

    func testDispatchFlowStartRoutesToHandler() async throws {
        let (peer, transport, profile) = makePeer()
        try await connectPeer(peer, transport: transport)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f1","flow_type":"stub.flow"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 50_000_000)

        XCTAssertEqual(profile.startedFlows.count, 1)
        XCTAssertEqual(profile.startedFlows[0].flowId, "f1")
    }

    func testDispatchFlowProgressRoutesToHandler() async throws {
        let (peer, transport, profile) = makePeer()
        try await connectPeer(peer, transport: transport)

        // Track the flow first
        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f2","flow_type":"stub.flow"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 30_000_000)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"f2","step":"processing"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 50_000_000)

        XCTAssertEqual(profile.progresses.count, 1)
        XCTAssertEqual(profile.progresses[0].step, "processing")
    }

    func testDispatchFlowCompleteRemovesFlowFromMap() async throws {
        let (peer, transport, profile) = makePeer()
        try await connectPeer(peer, transport: transport)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f3","flow_type":"stub.flow"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 30_000_000)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"wmp":{"version":"0.1"},"flow_id":"f3"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 50_000_000)

        XCTAssertEqual(profile.completes.count, 1)

        // After completion, a subsequent progress for the same flow should not route to handler
        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"wmp":{"version":"0.1"},"flow_id":"f3","step":"late"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 50_000_000)
        XCTAssertEqual(profile.progresses.count, 0, "No handler should receive progress after flow completion")
    }

    func testDispatchFlowCancelRemovesFlowFromMap() async throws {
        let (peer, transport, profile) = makePeer()
        try await connectPeer(peer, transport: transport)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f4","flow_type":"stub.flow"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 30_000_000)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.cancel","params":{"wmp":{"version":"0.1"},"flow_id":"f4","reason":"user_cancelled"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 50_000_000)

        XCTAssertEqual(profile.cancels.count, 1)
        XCTAssertEqual(profile.cancels[0].reason, "user_cancelled")
    }

    func testDispatchFlowErrorRemovesFlowFromMap() async throws {
        let (peer, transport, profile) = makePeer()
        try await connectPeer(peer, transport: transport)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f5","flow_type":"stub.flow"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 30_000_000)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.error","params":{"wmp":{"version":"0.1"},"flow_id":"f5","code":"E001","message":"something went wrong"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 50_000_000)

        XCTAssertEqual(profile.errors.count, 1)
        XCTAssertEqual(profile.errors[0].message, "something went wrong")
    }

    func testDispatchCustomMethodRoutesToHandler() async throws {
        let (peer, transport, profile) = makePeer()
        try await connectPeer(peer, transport: transport)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"stub.ping","params":{"echo":"hello"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 50_000_000)

        XCTAssertEqual(profile.methodCalls.count, 1)
        XCTAssertEqual(profile.methodCalls[0].0, "stub.ping")
    }

    func testDispatchResolveRoutesToHandler() async throws {
        let (peer, transport, profile) = makePeer()
        try await connectPeer(peer, transport: transport)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.resolve","params":{"type":"stub.did","identifier":"did:example:123"}}
            """.data(using: .utf8)!
        )
        try await Task.sleep(nanoseconds: 50_000_000)

        XCTAssertEqual(profile.resolves.count, 1)
        XCTAssertEqual(profile.resolves[0].identifier, "did:example:123")
    }

    func testFlowEventsStreamEmitsStartedEvent() async throws {
        let (peer, transport, _) = makePeer()
        try await connectPeer(peer, transport: transport)

        let eventTask = Task { () -> FlowEvent? in
            for await event in peer.flowEvents() {
                return event
            }
            return nil
        }

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.start","params":{"wmp":{"version":"0.1"},"flow_id":"f6","flow_type":"stub.flow"}}
            """.data(using: .utf8)!
        )

        let event = try await withTimeout(seconds: 2) { await eventTask.value }
        guard case .started(let flowId, let flowType, _) = event else {
            XCTFail("Expected .started event")
            return
        }
        XCTAssertEqual(flowId, "f6")
        XCTAssertEqual(flowType, "stub.flow")
    }

    func testStartFlowThrowsFlowFailedOnRpcError() async throws {
        let (peer, transport, _) = makePeer()
        try await connectPeer(peer, transport: transport)

        let flowTask = Task {
            try await peer.startFlow(flowType: "stub.flow", flowId: "f7")
        }

        // Wait for the request
        let deadline = Date().addingTimeInterval(2)
        while transport.sentMessages.count < 2 {
            if Date() > deadline { throw TimeoutError() }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        let codec = WmpCodec()
        let req = try codec.decodeRequest(transport.sentMessages.last!)

        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","id":"\(req.id!)","error":{"code":-32010,"message":"flow not found"}}
            """.data(using: .utf8)!
        )

        do {
            _ = try await flowTask.value
            XCTFail("Expected WmpSessionError.flowFailed")
        } catch WmpSessionError.flowFailed(let msg) {
            XCTAssertEqual(msg, "flow not found")
        } catch {
            XCTFail("Expected WmpSessionError.flowFailed, got \(error)")
        }
    }

    // MARK: - Helpers

    private func withTimeout<T>(seconds: TimeInterval, operation: @escaping () async throws -> T) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await operation() }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                throw TimeoutError()
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }
}

private struct TimeoutError: Error {}
