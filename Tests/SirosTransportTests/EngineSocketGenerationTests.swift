// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import SirosTransport

/// What the wallet relies on to refuse requests of a connection that is gone: the owner is told when a connection is
/// lost or replaced, requests carry the socket generation they were received on, and `invalidateBufferedRequests()`
/// marks what was received so far as obsolete. Driven through the single-flight tests' fake socket.
final class EngineSocketGenerationTests: XCTestCase {
    typealias FakeSocket = EngineSingleFlightTests.FakeSocket
    typealias Sockets = EngineSingleFlightTests.Sockets

    private var sockets = Sockets()
    override func setUp() { sockets = Sockets() }

    private func makeSession() -> WalletEngineSession {
        let box = sockets
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t", socketFactory: { _ in box.make() })
        session.baseReconnectDelayMs = 20
        return session
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock(); private var n = 0
        func bump() { lock.lock(); n += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    }

    private let handshakeComplete = #"{"type":"handshake_complete","session_id":"s1","capabilities":[]}"#
    private func signRequest(_ flow: String) -> String {
        #"{"type":"sign_request","flow_id":"\#(flow)","message_id":"m","action":"generate_proof","params":{"audience":"a","nonce":"n"}}"#
    }

    private func waitUntil(_ what: String, _ condition: () -> Bool) async {
        for _ in 0..<300 {
            if condition() { return }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out waiting for: \(what)")
    }

    private func waitReceiving(_ index: Int) async {
        await waitUntil("receive loop \(index)") { sockets.all.indices.contains(index) && sockets.all[index].isReceiving }
    }

    /// A lost connection tells the owner every time (also after a recovery), and the generation moves with the loss,
    /// so a request stamped before it never matches the current one.
    func testEachLossTellsTheOwnerAndAdvancesTheGeneration() async {
        let session = makeSession()
        let told = Counter()
        session.onSocketReplaced = { told.bump() }
        session.connect(appToken: "tok")
        await waitReceiving(0)
        sockets.all[0].deliver(handshakeComplete)
        await waitUntil("connected") { session.currentState == .connected }
        let stamped = session.socketGeneration
        sockets.all[0].fail()
        await waitUntil("first loss told") { told.value == 1 }
        XCTAssertNotEqual(session.socketGeneration, stamped, "the generation moved with the loss")
        await waitUntil("replacement opened") { self.sockets.all.count == 2 }
        await waitReceiving(1)
        sockets.all[1].deliver(handshakeComplete)
        await waitUntil("recovered") { session.currentState == .connected }
        sockets.all[1].fail()
        await waitUntil("second loss told") { told.value == 2 }
    }

    /// `forceReconnect` replaces a live socket: the owner is told, and the generation advances.
    func testForceReconnectTellsTheOwner() async {
        let session = makeSession()
        let told = Counter()
        session.onSocketReplaced = { told.bump() }
        session.connect(appToken: "tok")
        await waitReceiving(0)
        let before = session.socketGeneration
        session.forceReconnect(appToken: "tok2")
        XCTAssertEqual(told.value, 1)
        XCTAssertGreaterThan(session.socketGeneration, before)
    }

    /// A request is stamped with the generation of the socket that carried it, and a frame a replaced socket delivers
    /// after its replacement opened is dropped before dispatch.
    func testARequestIsStampedWithItsSocketAndAReplacedSocketsFrameIsDropped() async {
        let session = makeSession()
        session.connect(appToken: "tok")
        await waitReceiving(0)
        sockets.all[0].deferFailureOnCancel = true             // the cancelled socket can still deliver an in-flight frame
        session.forceReconnect(appToken: "tok2")
        await waitReceiving(1)
        var iterator = session.signRequests().makeAsyncIterator()
        sockets.all[0].deliver(signRequest("old"))             // obsolete: dropped
        sockets.all[1].deliver(signRequest("cur"))
        let delivered = await iterator.next()
        XCTAssertEqual(delivered?.flowId, "cur", "only the current socket's request is delivered")
        XCTAssertEqual(delivered?.socketGeneration, session.socketGeneration)
    }

    /// Requests received so far are obsolete after `invalidateBufferedRequests()`; later ones are not.
    func testInvalidatingBufferedRequestsStampsLaterOnesWithANewEpoch() async {
        let session = makeSession()
        session.connect(appToken: "tok")
        await waitReceiving(0)
        var iterator = session.signRequests().makeAsyncIterator()
        sockets.all[0].deliver(signRequest("before"))
        let before = await iterator.next()
        session.invalidateBufferedRequests()
        sockets.all[0].deliver(signRequest("after"))
        let after = await iterator.next()
        XCTAssertEqual(before?.requestEpoch, 0)
        XCTAssertEqual(after?.requestEpoch, session.requestEpoch)
        XCTAssertNotEqual(before?.requestEpoch, after?.requestEpoch)
    }

    /// A recovered connection starts a fresh retry budget.
    func testARecoveredConnectionGetsAFreshRetryBudget() async {
        let session = makeSession()
        session.connect(appToken: "tok")
        for index in 0..<7 {                                   // beyond the budget of 5, recovering in between
            await waitReceiving(index)
            sockets.all[index].deliver(handshakeComplete)
            await waitUntil("connected \(index)") { session.currentState == .connected }
            sockets.all[index].fail()
            await waitUntil("reconnecting after loss \(index)") { self.sockets.all.count == index + 2 }
        }
        XCTAssertNotEqual(session.currentState, .failed, "each recovery reset the budget")
    }
}
