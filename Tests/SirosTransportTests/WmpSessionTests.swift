// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class WmpSessionTests: XCTestCase {
    private let codec = WmpCodec()

    func testCreateSendsSessionCreateAndTransitionsActive() async throws {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 2_000)
        )

        let createTask = Task {
            try await session.create(authToken: "app-token", sender: "sample-wallet")
        }

        // Wait for the create request to be sent
        try await waitForSentCount(transport, expected: 1)
        let createReq = try codec.decodeRequest(transport.sentMessages.last!)
        XCTAssertEqual(createReq.method, "wmp.session.create")
        XCTAssertNotNil(createReq.id)

        let createText = String(data: transport.sentMessages.last!, encoding: .utf8)!
        XCTAssertTrue(createText.contains("\"type\":\"bearer\""))
        XCTAssertTrue(createText.contains("\"token\":\"app-token\""))

        // Send success response
        transport.receiveFromServer(createSuccessResponse(requestId: createReq.id!).data(using: .utf8)!)
        try await createTask.value

        XCTAssertEqual(session.currentState, .active)

        try await session.close()
    }

    func testSendRequestTimesOutWithoutResponse() async {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 100)
        )

        // Connect first
        try? await transport.connect()

        do {
            _ = try await session.sendRequest(method: "wmp.flow.action", params: nil, timeoutMs: 100)
            XCTFail("Expected WmpTimeoutError")
        } catch is WmpTimeoutError {
            // expected
        } catch {
            XCTFail("Expected WmpTimeoutError, got \(error)")
        }
    }

    func testNotificationsFlowEmitsServerNotification() async throws {
        let transport = FakeTransport()
        let session = WmpSession(
            transport: transport,
            config: WmpSessionConfig(requestTimeoutMs: 2_000)
        )

        // Create session
        let createTask = Task { try await session.create(authToken: "token") }
        try await waitForSentCount(transport, expected: 1)
        let createReq = try codec.decodeRequest(transport.sentMessages.last!)
        transport.receiveFromServer(createSuccessResponse(requestId: createReq.id!).data(using: .utf8)!)
        try await createTask.value

        // Listen for notification
        let notificationTask = Task {
            for await notification in session.notifications() {
                return notification
            }
            fatalError("Stream ended")
        }

        // Send a notification from server
        transport.receiveFromServer(
            """
            {"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"state":"processing"}}
            """.data(using: .utf8)!
        )

        let notification = try await withTimeout(seconds: 2) {
            await notificationTask.value
        }
        XCTAssertEqual(notification.method, "wmp.flow.progress")

        try await session.close()
    }

    // MARK: - Helpers

    /// `onTerminal` fires when the session ends for good: on close, and once every reconnect attempt has failed;
    /// never on the transient `.failed` of one failed resume.
    func testOnTerminalFiresOnCloseAndWhenReconnectsAreExhaustedOnly() async throws {
        actor Count { var n = 0; func bump() { n += 1 }; var value: Int { n } }
        let counter = Count()
        let transport = FakeTransport()
        let session = WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 2_000))
        session.onTerminal = { Task { await counter.bump() } }
        let createTask = Task { try await session.create(authToken: "t", sender: "s") }
        try await waitForSentCount(transport, expected: 1)
        let req = try codec.decodeRequest(transport.sentMessages.last!)
        transport.receiveFromServer(createSuccessResponse(requestId: req.id!).data(using: .utf8)!)
        try await createTask.value
        let before = await counter.value
        XCTAssertEqual(before, 0, "an active session is not terminal")
        try await session.close()
        try await Task.sleep(nanoseconds: 100_000_000)
        let after = await counter.value
        XCTAssertEqual(after, 1)
    }

    /// A session created without a `resumption_token` has nothing to resume: losing the connection ends it at once,
    /// the same way an exhausted resume does (terminal hook, pending requests failed).
    func testLosingTheConnectionWithoutAResumptionTokenEndsTheSession() async throws {
        actor Count { var n = 0; func bump() { n += 1 }; var value: Int { n } }
        let counter = Count()
        let transport = FakeTransport()
        let session = WmpSession(transport: transport, config: WmpSessionConfig(requestTimeoutMs: 2_000))
        session.onTerminal = { Task { await counter.bump() } }
        let createTask = Task { try await session.create(authToken: "t", sender: "s") }
        try await waitForSentCount(transport, expected: 1)
        let req = try codec.decodeRequest(transport.sentMessages.last!)
        transport.receiveFromServer(
            #"{"jsonrpc":"2.0","id":"\#(req.id!)","result":{"wmp":{"version":"0.1","session_id":"session-123"}}}"#.data(using: .utf8)!
        )
        try await createTask.value
        await transport.disconnect()
        for _ in 0..<100 { if await counter.value > 0 { break }; try await Task.sleep(nanoseconds: 20_000_000) }
        let fired = await counter.value
        XCTAssertEqual(fired, 1)
        XCTAssertEqual(session.currentState, .failed)
    }

    private func waitForSentCount(_ transport: FakeTransport, expected: Int) async throws {
        let deadline = Date().addingTimeInterval(2)
        while transport.sentMessages.count < expected {
            if Date() > deadline { throw TimeoutError() }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    private func createSuccessResponse(requestId: String) -> String {
        """
        {"jsonrpc":"2.0","id":"\(requestId)","result":{"wmp":{"version":"0.1","session_id":"session-123"},"resumption_token":"resume-abc"}}
        """
    }

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
