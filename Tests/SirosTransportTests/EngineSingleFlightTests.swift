// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import SirosTransport

/// The engine keeps one session per (tenant, user) and closes the older socket
/// when a second connects. Kotlin SDK #282 found that the client opened several
/// sockets at once (a forced reconnect after a QR scan plus the reconnect each
/// callback of the replaced socket scheduled), so they superseded each other
/// and a presentation's replies went to a socket the engine no longer knew.
/// These tests drive `WalletEngineSession` through a fake socket whose
/// `cancel()` raises the same receive failure a real cancelled
/// `URLSessionWebSocketTask` does.
final class EngineSingleFlightTests: XCTestCase {
    /// Fake socket: `receiveMessage()` suspends until a frame is delivered or the
    /// socket fails/is cancelled (cancel throws, like URLSession's).
    final class FakeSocket: EngineSocket, @unchecked Sendable {
        struct Closed: Error {}
        private let lock = NSLock()
        private var _running = true
        private var _cancelled = false
        private var _sent: [String] = []
        var failSends = false
        /// True once the session's receive loop is suspended in `receiveMessage()`.
        private var _receiving = false
        var isReceiving: Bool { lock.lock(); defer { lock.unlock() }; return _receiving }
        /// A cancelled socket may still deliver a frame that was in flight; its failure arrives later.
        var deferFailureOnCancel = false
        private let frames: AsyncThrowingStream<URLSessionWebSocketTask.Message, Error>
        private let continuation: AsyncThrowingStream<URLSessionWebSocketTask.Message, Error>.Continuation
        private var iterator: AsyncThrowingStream<URLSessionWebSocketTask.Message, Error>.AsyncIterator

        init() {
            var c: AsyncThrowingStream<URLSessionWebSocketTask.Message, Error>.Continuation!
            frames = AsyncThrowingStream { c = $0 }
            continuation = c
            iterator = frames.makeAsyncIterator()
        }

        var isRunning: Bool { lock.lock(); defer { lock.unlock() }; return _running }
        var wasCancelled: Bool { lock.lock(); defer { lock.unlock() }; return _cancelled }
        var sent: [String] { lock.lock(); defer { lock.unlock() }; return _sent }
        func resume() {}

        func cancel(closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
            lock.lock(); _running = false; _cancelled = true; let deferred = deferFailureOnCancel; lock.unlock()
            if !deferred { continuation.finish(throwing: Closed()) }
        }

        func sendText(_ text: String, completion: @escaping @Sendable (Error?) -> Void) {
            lock.lock(); _sent.append(text); let fail = failSends; lock.unlock()
            completion(fail ? Closed() : nil)
        }

        func receiveMessage() async throws -> URLSessionWebSocketTask.Message {
            // Single reader (the session's receive loop), so the iterator is not shared.
            lock.lock(); _receiving = true; lock.unlock()
            guard let message = try await iterator.next() else { throw Closed() }
            return message
        }

        func sendPing(completion: @escaping @Sendable (Error?) -> Void) { completion(nil) }

        /// The server (or the network) ends the connection.
        func fail() {
            // The task's state is not touched: like a real one, it only reports the
            // failure through the pending receive.
            continuation.finish(throwing: Closed())
        }

        func deliver(_ text: String) { continuation.yield(.string(text)) }
    }

    final class Sockets: @unchecked Sendable {
        private let lock = NSLock()
        private var _all: [FakeSocket] = []
        var all: [FakeSocket] { lock.lock(); defer { lock.unlock() }; return _all }
        func make() -> FakeSocket {
            let s = FakeSocket()
            lock.lock(); _all.append(s); lock.unlock()
            return s
        }
    }

    private var sockets = Sockets()

    override func setUp() { sockets = Sockets() }

    private func makeSession() -> WalletEngineSession {
        let box = sockets
        let session = WalletEngineSession(
            baseUrl: "https://wallet.example.com",
            tenantId: "t",
            socketFactory: { _ in box.make() }
        )
        session.baseReconnectDelayMs = 40
        return session
    }

    private let handshakeComplete = #"{"type":"handshake_complete","session_id":"s1","capabilities":[]}"#

    /// Long enough for any reconnect that was going to happen (40 ms, then 80 ms backoff) to have happened.
    private func settle() async { try? await Task.sleep(nanoseconds: 400_000_000) }

    /// A real task reports its failure through the receive the loop is suspended in;
    /// wait for that state so the fake behaves alike regardless of scheduling.
    private func waitReceiving(_ index: Int = 0) async {
        await waitUntil("receive loop \(index) running") { sockets.all.indices.contains(index) && sockets.all[index].isReceiving }
    }

    private func waitUntil(_ what: String, _ condition: () -> Bool) async {
        for _ in 0..<200 {
            if condition() { return }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out waiting for: \(what)")
    }

    func testFailureRaisedByAForcedReconnectsReplacedSocketOpensNoFurtherConnection() async {
        let session = makeSession()
        session.connect(appToken: "tok")
        XCTAssertEqual(sockets.all.count, 1)
        await waitReceiving()
        session.forceReconnect(appToken: "tok2")
        XCTAssertEqual(sockets.all.count, 2)
        XCTAssertTrue(sockets.all[0].wasCancelled)
        // The failure the replaced socket raised from cancel() reaches its receive loop;
        // a late second callback and a failed send on it come too.
        sockets.all[0].fail()
        await settle()
        XCTAssertEqual(sockets.all.count, 2, "one replacement, not one per callback")
        XCTAssertEqual(session.currentState, .connecting)
        XCTAssertFalse(sockets.all[1].wasCancelled)
    }

    func testTwoFailuresOfTheCurrentSocketScheduleOneReconnect() async {
        let session = makeSession()
        session.connect(appToken: "tok")
        await waitReceiving()
        sockets.all[0].failSends = true
        sockets.all[0].fail() // the receive loop ends ...
        session.sendTrustResult(flowId: "f", trusted: true) // ... and so does a send on the same socket
        await settle()
        XCTAssertEqual(sockets.all.count, 2)
    }

    func testForcedReconnectReplacesAPendingBackoffAttemptInsteadOfAddingToIt() async {
        let session = makeSession()
        session.baseReconnectDelayMs = 200
        session.connect(appToken: "tok")
        await waitReceiving()
        sockets.all[0].fail()
        await waitUntil("backoff scheduled") { session.currentState == .reconnecting }
        session.forceReconnect(appToken: "tok2")
        await settle()
        try? await Task.sleep(nanoseconds: 300_000_000)
        XCTAssertEqual(sockets.all.count, 2, "the initial socket and the forced one only")
    }

    func testAConnectDuringABackoffReplacesThePendingAttempt() async {
        let session = makeSession()
        session.baseReconnectDelayMs = 200
        session.connect(appToken: "tok")
        await waitReceiving()
        sockets.all[0].fail()
        await waitUntil("backoff scheduled") { session.currentState == .reconnecting }
        session.connect(appToken: "tok2") // not .connected, so the guard lets it through
        XCTAssertEqual(sockets.all.count, 2)
        try? await Task.sleep(nanoseconds: 500_000_000)
        XCTAssertEqual(sockets.all.count, 2, "the pending attempt did not open a third socket")
    }

    func testOverlappingConnectsLeaveOneLiveSocket() async {
        let session = makeSession()
        session.connect(appToken: "tok")
        await waitReceiving()
        session.connect(appToken: "tok") // still .connecting: the guard lets it through
        XCTAssertEqual(sockets.all.count, 2)
        XCTAssertTrue(sockets.all[0].wasCancelled, "the first socket is superseded and cancelled")
        XCTAssertFalse(sockets.all[1].wasCancelled)
        await settle()
        XCTAssertEqual(sockets.all.count, 2, "cancelling the first raised no reconnect")
    }

    func testAFrameOfASupersededSocketIsIgnored() async {
        let session = makeSession()
        session.connect(appToken: "tok")
        await waitReceiving()
        sockets.all[0].deferFailureOnCancel = true
        session.forceReconnect(appToken: "tok2")
        // A handshake_complete of the replaced socket must not mark the new session connected.
        sockets.all[0].deliver(handshakeComplete)
        await settle()
        XCTAssertEqual(session.currentState, .connecting)
        sockets.all[1].deliver(handshakeComplete)
        await waitUntil("connected") { session.currentState == .connected }
    }

    func testASocketThatFailedIsNotReportedConnectedDuringTheBackoff() async {
        let session = makeSession()
        session.baseReconnectDelayMs = 300
        session.connect(appToken: "tok")
        await waitReceiving()
        XCTAssertTrue(session.isConnected)
        sockets.all[0].fail()
        await waitUntil("backoff") { session.currentState == .reconnecting }
        XCTAssertFalse(session.isConnected)
    }

    func testDisconnectCancelsAPendingBackoffAttempt() async {
        let session = makeSession()
        session.baseReconnectDelayMs = 200
        session.connect(appToken: "tok")
        await waitReceiving()
        sockets.all[0].fail()
        await waitUntil("backoff") { session.currentState == .reconnecting }
        session.disconnect()
        try? await Task.sleep(nanoseconds: 500_000_000)
        XCTAssertEqual(sockets.all.count, 1)
        XCTAssertEqual(session.currentState, .disconnected)
    }

    func testAnAutomaticAttemptParkedInTheTokenRefreshIsSupersededByAForcedReconnect() async {
        let session = makeSession()
        let entered = expectation(description: "attempt is inside the token refresh")
        let gate = AsyncStream<Void>.makeStream()
        session.connect(
            appToken: "tok",
            tokenProvider: {
                entered.fulfill()
                for await _ in gate.stream { break }
                return "late"
            }
        )
        await waitReceiving()
        sockets.all[0].fail() // the backoff attempt parks in tokenProvider after 40 ms
        await fulfillment(of: [entered], timeout: 5)
        session.forceReconnect(appToken: "tok2") // installs socket 1
        XCTAssertEqual(sockets.all.count, 2)
        gate.continuation.yield()
        await settle()
        XCTAssertEqual(sockets.all.count, 2, "the superseded attempt added no socket")
        XCTAssertFalse(sockets.all[1].wasCancelled, "and did not cancel the replacement")
    }

    func testARejectedRefreshOfASupersededAttemptDoesNotClobberTheNewConnectionsState() async {
        struct Rejected: Error {}
        let session = makeSession()
        let entered = expectation(description: "attempt is inside the token refresh")
        let gate = AsyncStream<Void>.makeStream()
        session.connect(
            appToken: "tok",
            tokenProvider: {
                entered.fulfill()
                for await _ in gate.stream { break }
                throw Rejected()
            },
            onTokenRejected: { _ in XCTFail("a superseded attempt must not report a rejection") }
        )
        await waitReceiving()
        sockets.all[0].fail()
        await fulfillment(of: [entered], timeout: 5)
        session.forceReconnect(appToken: "tok2")
        gate.continuation.yield()
        await settle()
        XCTAssertEqual(session.currentState, .connecting, "not .reauthRequired")
    }
}
