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

    // MARK: - Start tags (a flow keeps the tag of ITS flow_start)

    func testAFlowKeepsTheTagOfItsOwnStartEvenIfANewerFlowStartedBeforeItsFirstProgress() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        session.startTags.enqueue(0) // A started under epoch 0 ... and was cancelled
        session.startTags.enqueue(1) // ... B started under epoch 1 before A's first progress was handled
        await session.handleMessage(progress(flowId: "A", trusted: false)) // A's first progress arrives first
        await session.handleMessage(progress(flowId: "B", trusted: true))
        await session.handleMessage(complete(flowId: "A"))
        await session.handleMessage(complete(flowId: "B"))
        var it = session.flowComplete().makeAsyncIterator()
        let a = await it.next()
        let b = await it.next()
        XCTAssertEqual(a?.startTag, 0)
        XCTAssertEqual(b?.startTag, 1)
    }

    func testAFlowWhoseProgressWasNeverSeenHasNoTag() async {
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        session.startTags.enqueue(5)
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
