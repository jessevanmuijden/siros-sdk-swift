// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
@testable import SirosTransport

/// The engine reports its issuer trust evaluation as a `trust_evaluated`
/// progress step; the wallet's issuance gate needs it when the flow completes.
/// The two arrive on separate streams, so the session joins them in frame order.
final class EngineIssuerTrustReportTests: XCTestCase {
    private func progress(flowId: String, trusted: Bool) -> String {
        #"{"type":"flow_progress","flow_id":"\#(flowId)","step":"trust_evaluated","payload":{"issuer_trust_evaluated":true,"trusted":\#(trusted),"issuer":"https://issuer.example","framework":"etsi-tl","reason":"r"}}"#
    }

    private func complete(flowId: String) -> String {
        #"{"type":"flow_complete","flow_id":"\#(flowId)","credentials":[]}"#
    }

    private func nextComplete(_ session: WalletEngineSession) async -> FlowCompleteMessage? {
        var it = session.flowComplete().makeAsyncIterator()
        return await it.next()
    }

    func testTheReportOfAFlowIsAttachedToThatFlowsCompletion() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        await session.handleMessage(progress(flowId: "a", trusted: false))
        await session.handleMessage(progress(flowId: "b", trusted: true))
        await session.handleMessage(complete(flowId: "a"))
        let msg = await nextComplete(session)
        XCTAssertEqual(msg?.flowId, "a")
        XCTAssertEqual(msg?.issuerTrust, IssuerTrustReport(
            issuer: "https://issuer.example", trusted: false, framework: "etsi-tl", reason: "r"
        ))
    }

    func testACompletionWithoutAReportCarriesNone() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        await session.handleMessage(complete(flowId: "a"))
        let msg = await nextComplete(session)
        XCTAssertNil(msg?.issuerTrust, "an absent report is not a negative one")
    }

    func testAReportIsUsedOnceAndNotCarriedToALaterFlowWithTheSameId() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        await session.handleMessage(progress(flowId: "a", trusted: false))
        await session.handleMessage(complete(flowId: "a"))
        await session.handleMessage(complete(flowId: "a"))
        var it = session.flowComplete().makeAsyncIterator()
        let first = await it.next()
        let second = await it.next()
        XCTAssertNotNil(first?.issuerTrust)
        XCTAssertNil(second?.issuerTrust)
    }

    func testAFlowErrorDiscardsItsReport() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        await session.handleMessage(progress(flowId: "a", trusted: false))
        await session.handleMessage(#"{"type":"flow_error","flow_id":"a","error":{"code":"x","message":"m"}}"#)
        await session.handleMessage(complete(flowId: "a"))
        let msg = await nextComplete(session)
        XCTAssertNil(msg?.issuerTrust)
    }

    func testOtherProgressStepsAndNonIssuerReportsAreNotRecorded() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        await session.handleMessage(#"{"type":"flow_progress","flow_id":"a","step":"trust_evaluated","payload":{"trusted":false}}"#)
        await session.handleMessage(#"{"type":"flow_progress","flow_id":"a","step":"other","payload":{"issuer_trust_evaluated":true,"trusted":false}}"#)
        await session.handleMessage(complete(flowId: "a"))
        let msg = await nextComplete(session)
        XCTAssertNil(msg?.issuerTrust)
    }

    // MARK: - Start tags (pair only when unambiguous)

    func testASingleUnansweredStartTagsItsFlow() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        session.startTags.enqueue(3)
        await session.handleMessage(progress(flowId: "A", trusted: true))
        await session.handleMessage(complete(flowId: "A"))
        let msg = await nextComplete(session)
        XCTAssertEqual(msg?.startTag, 3)
    }

    func testTwoUnansweredStartsCannotBeToldApartSoNeitherFlowGetsATag() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        // The engine runs each flow_start in its own goroutine: B's progress may come first.
        session.startTags.enqueue(0) // A
        session.startTags.enqueue(1) // B
        await session.handleMessage(progress(flowId: "B", trusted: true))
        await session.handleMessage(progress(flowId: "A", trusted: false))
        await session.handleMessage(complete(flowId: "A"))
        await session.handleMessage(complete(flowId: "B"))
        var it = session.flowComplete().makeAsyncIterator()
        let a = await it.next()
        let b = await it.next()
        XCTAssertNil(a?.startTag, "guessing FIFO here could hand A's tag to B")
        XCTAssertNil(b?.startTag)
    }

    func testStartsThatAreAnsweredOneAtATimeKeepTheirOwnTags() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        session.startTags.enqueue(0)
        await session.handleMessage(progress(flowId: "A", trusted: true))
        session.startTags.enqueue(1) // B starts only after A was answered
        await session.handleMessage(progress(flowId: "B", trusted: true))
        await session.handleMessage(complete(flowId: "A"))
        await session.handleMessage(complete(flowId: "B"))
        var it = session.flowComplete().makeAsyncIterator()
        let a = await it.next()
        let b = await it.next()
        XCTAssertEqual(a?.startTag, 0)
        XCTAssertEqual(b?.startTag, 1)
    }

    func testAFlowThatCompletesBeforeAnyProgressIsPairedUnderTheSameRule() {
        let tracker = StartTagTracker()
        tracker.enqueue(9)
        XCTAssertEqual(tracker.take(flowId: "A"), 9)
        let ambiguous = StartTagTracker()
        ambiguous.enqueue(1); ambiguous.enqueue(2)
        XCTAssertNil(ambiguous.take(flowId: "A"))
        XCTAssertNil(ambiguous.take(flowId: "B"))
    }

    /// Copilot's example: A(0), B(1) outstanding; B's first progress arrives and clears
    /// both; C(2) is enqueued; A's delayed first progress must not take C's tag.
    func testALateReplyOfADroppedStartDoesNotTakeANewerStartsTag() {
        let t = StartTagTracker()
        t.enqueue(0); t.enqueue(1)
        t.firstProgress(flowId: "B")
        XCTAssertTrue(t.isPoisoned, "A may still reply")
        t.enqueue(2)
        t.firstProgress(flowId: "A")
        XCTAssertNil(t.take(flowId: "A"), "A's late reply must not take C's tag")
        t.firstProgress(flowId: "C")
        XCTAssertNil(t.take(flowId: "C"), "C cannot be told from A's reply either: refused, never guessed")
        XCTAssertFalse(t.isPoisoned, "every outstanding reply is now accounted for")
        t.enqueue(3)
        t.firstProgress(flowId: "D")
        XCTAssertEqual(t.take(flowId: "D"), 3, "a clean tracker pairs again")
    }

    /// Copilot's second example: an unanswered start is never expired into a newer one.
    func testAStartTheEngineNeverAnsweredIsNotExpiredIntoANewerStart() {
        let t = StartTagTracker()
        t.enqueue(0) // A: never answered (or very late)
        t.enqueue(1) // B
        t.firstProgress(flowId: "B")
        XCTAssertNil(t.take(flowId: "B"))
        t.firstProgress(flowId: "A") // arbitrarily late: no timer ever hands its slot to a newer start
        XCTAssertNil(t.take(flowId: "A"))
        XCTAssertFalse(t.isPoisoned)
    }

    func testAReplyThatNamesNoFlowStillAnswersOneOutstandingStart() {
        let t = StartTagTracker()
        t.enqueue(0)
        t.discard(flowId: nil) // the engine refused the start with an error naming no flow
        XCTAssertFalse(t.isPoisoned)
        t.enqueue(1)
        t.firstProgress(flowId: "X")
        XCTAssertEqual(t.take(flowId: "X"), 1)
    }

    func testRetiringTheSocketClearsPoison() {
        let t = StartTagTracker()
        t.enqueue(0); t.enqueue(1)
        t.firstProgress(flowId: "B")
        XCTAssertTrue(t.isPoisoned)
        t.reset()
        XCTAssertFalse(t.isPoisoned)
    }

    func testAFlowWhoseProgressWasNeverSeenAndNoStartIsQueuedHasNoTag() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        await session.handleMessage(complete(flowId: "A"))
        let msg = await nextComplete(session)
        XCTAssertNil(msg?.startTag)
    }

    func testStartTagsQueuedForADeadSocketAreDropped() {
        let tracker = StartTagTracker()
        tracker.enqueue(7)
        tracker.reset()
        tracker.firstProgress(flowId: "A")
        XCTAssertNil(tracker.take(flowId: "A"), "a flow of the next socket must not take the dead socket's tag")
    }
}

