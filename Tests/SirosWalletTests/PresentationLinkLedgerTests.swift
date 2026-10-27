// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

final class PresentationLinkLedgerTests: XCTestCase {
    private final class Clock {
        var now = Date(timeIntervalSince1970: 0)
    }

    func testTheSameLinkIsRefusedWithinTheWindowAndAdmittedAgainAfterIt() {
        let clock = Clock()
        let ledger = PresentationLinkLedger(window: 60, now: { clock.now })
        XCTAssertTrue(ledger.admit("openid4vp://?client_id=x&nonce=1"), "first delivery starts a flow")
        XCTAssertFalse(ledger.admit("openid4vp://?client_id=x&nonce=1"), "redelivered within the window starts none")
        clock.now.addTimeInterval(59)
        XCTAssertFalse(ledger.admit("openid4vp://?client_id=x&nonce=1"), "still inside the window")
        clock.now.addTimeInterval(1.5)
        XCTAssertTrue(ledger.admit("openid4vp://?client_id=x&nonce=1"), "the window has passed")
    }

    func testADifferentLinkIsNeverAffectedByAnotherOnesAdmission() {
        let ledger = PresentationLinkLedger()
        XCTAssertTrue(ledger.admit("openid4vp://?client_id=x"))
        XCTAssertTrue(ledger.admit("openid4vp://?client_id=y"), "a different link is its own entry")
        XCTAssertFalse(ledger.admit("openid4vp://?client_id=x"))
        XCTAssertFalse(ledger.admit("openid4vp://?client_id=y"))
    }

    func testReleasingALinkAdmitsItAgainAtOnce() {
        let ledger = PresentationLinkLedger()
        XCTAssertTrue(ledger.admit("openid4vp://?client_id=x"))
        XCTAssertFalse(ledger.admit("openid4vp://?client_id=x"))
        ledger.release("openid4vp://?client_id=x")
        XCTAssertTrue(ledger.admit("openid4vp://?client_id=x"), "a failed start's link is not held against a retry")
    }

    func testReleasingAnUnknownOrAlreadyReleasedLinkIsHarmless() {
        let ledger = PresentationLinkLedger()
        ledger.release("never admitted")
        ledger.release("never admitted")
        XCTAssertTrue(ledger.admit("never admitted"))
    }

    /// At most `capacity` links are remembered; the oldest is evicted to make room for a new one.
    func testCapacityEvictsTheOldestEntry() {
        let ledger = PresentationLinkLedger(capacity: 2)
        XCTAssertTrue(ledger.admit("a"))
        XCTAssertTrue(ledger.admit("b"))
        XCTAssertTrue(ledger.admit("c"), "a new link is still admitted once capacity is full")
        XCTAssertTrue(ledger.admit("a"), "evicted to make room for c: admitted again, not refused")
        XCTAssertFalse(ledger.admit("c"), "c is still within its window")
    }

    func testReleaseAllForgetsEveryLink() {
        let ledger = PresentationLinkLedger()
        _ = ledger.admit("a")
        _ = ledger.admit("b")
        ledger.releaseAll()
        XCTAssertTrue(ledger.admit("a"))
        XCTAssertTrue(ledger.admit("b"))
    }
}
