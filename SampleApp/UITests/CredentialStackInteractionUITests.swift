// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest

/// Drives `CredentialStack` with real touch input on-device via
/// `XCUIApplication` - taps, long-presses and drags, not a simulated
/// callback invocation - because the whole point of this component is that
/// tap, long-press and drag resolve correctly against each other, and that
/// is exactly the kind of thing a plain unit test calling a gesture
/// callback directly cannot catch. Port of the Kotlin sample app's
/// `CredentialStackInteractionTest`
/// (`sample-app/src/androidTest/kotlin/org/siros/sdk/sample/
/// CredentialStackInteractionTest.kt`).
///
/// Two real bugs an on-device test like this one is what actually caught in
/// both implementations, neither visible from reading the gesture code in
/// isolation:
///
/// - Two independent gesture recognizers reaching for the same touch
///   silently starve one another (the Kotlin sample app's first attempt,
///   and this port's own first attempt at composing a per-card
///   `.gesture()` with `CredentialCardView`'s own tap handling, both hit
///   this). SwiftUI's version of the trap turned out to run one layer
///   deeper still: even with exactly ONE `.gesture()` per card and none on
///   `CredentialCardView` itself, SwiftUI did not arbitrate those
///   independent per-card recognizers across `ZStack` siblings by touch
///   point - only the single sibling considered topmost by `zIndex` ever
///   received a touch, anywhere in the deck, confirmed via raw
///   (non-element-relative) coordinate taps that bypassed XCUITest's own
///   convenience APIs entirely. `CredentialStack` resolves this with
///   exactly ONE recognizer for the WHOLE deck, doing its own hit-testing
///   arithmetic (`hitTestCard`) instead of relying on SwiftUI to arbitrate
///   several.
/// - A long-press timeout checked only when a touch-move event happens to
///   arrive never fires for a finger held perfectly still, since
///   `DragGesture.onChanged` delivers no further events between touch-down
///   and release when nothing moves.
///
/// Launches the real app with `SIROS_SAMPLE_APP_FIXTURE_CREDENTIALS=1`,
/// which seeds a plain 3-credential fixture set and skips straight past
/// login (see `WalletViewModel.fixtureCredentials`) - this exercises the
/// exact same `CredentialsView`/`CredentialStack` the user sees, wired up
/// exactly as production does, with no backend/wallet session/key material
/// needed, same as the Kotlin test renders `CredentialStack` directly over a
/// fixture list.
final class CredentialStackInteractionUITests: XCTestCase {
    private var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchEnvironment["SIROS_SAMPLE_APP_FIXTURE_CREDENTIALS"] = "1"
        app.launch()
        // Home, not Credentials, is the default landing tab (see HomeView) -
        // every test in this suite exercises CredentialStack directly, so
        // switch tabs before each one runs.
        app.buttons["nav-tab-credentials"].tap()
    }

    /// batch id 1 ("Alpha"), 2 ("Bravo"), 3 ("Charlie") - 3 starts frontmost.
    /// `.any` (not `.otherElements`) since SwiftUI doesn't guarantee which
    /// accessibility element type a plain view's `.accessibilityIdentifier`
    /// surfaces as.
    private func card(_ batchId: Int) -> XCUIElement {
        app.descendants(matching: .any)
            .matching(identifier: "credential-stack-card-\(batchId)")
            .firstMatch
    }

    /// A point within this card's OWN uncovered "peek" strip (its top ~32%
    /// of height) - NOT its geometric center. Every stacked card reports
    /// its full height as its accessibility/hit frame (so the WHOLE deck's
    /// single gesture recognizer can resolve a touch anywhere on a card to
    /// that card), but for a card that ISN'T frontmost, only its own top
    /// `CREDENTIAL_PEEK_FRACTION` (0.32) is actually uncovered - the rest of
    /// its frame is drawn over by whichever card is stacked in front, and
    /// `hitTestCard` (`CredentialStack.swift`) resolves a touch there to
    /// THAT card, front-to-back, exactly matching what a real user sees and
    /// would tap. dy 0.15 is comfortably inside that uncovered top band
    /// regardless of how many cards are stacked above or below.
    private func cardPoint(_ batchId: Int, dy: CGFloat = 0.15) -> XCUICoordinate {
        waitForDeckToSettle()
        return card(batchId).coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: dy))
    }

    /// Waits until the deck has stopped moving: the frames of all three cards are identical in two samples
    /// taken a quarter of a second apart (or `timeout` passes, and the test goes on as it always did).
    ///
    /// Every gesture below is computed from a card's frame at the moment the coordinate is taken, and the deck
    /// animates (a reorder springs, a launch lays the cards out). On a slow, cold CI simulator a coordinate
    /// taken mid-animation lands on a different card than the one asserted on, which showed up as a different
    /// one of the drag and long-press tests failing in different CI runs, and passing on re-run. A warm local
    /// simulator, also under CPU load, never reproduced it; waiting for the deck to be still removes the
    /// dependence on how fast the machine animates.
    private func waitForDeckToSettle(timeout: TimeInterval = 5) {
        func frames() -> [CGRect] { (1...3).map { card($0).exists ? card($0).frame : .zero } }
        let deadline = Date().addingTimeInterval(timeout)
        var previous = frames()
        while Date() < deadline {
            Thread.sleep(forTimeInterval: 0.25)
            let current = frames()
            if current == previous, !current.contains(.zero) { return }
            previous = current
        }
    }

    /// This app's i18n JSON loading (`L10n.swift`) does not resolve under
    /// every build/launch configuration this suite has been run under -
    /// confirmed pre-existing and unrelated to `CredentialStack` (it
    /// reproduces on the plain login screen, before any credential-stack
    /// code runs at all): a missing translation falls back to the raw dotted
    /// key itself (e.g. `"common.delete"` instead of "Delete"). Matching
    /// either form keeps this suite valid regardless of whether/when that
    /// separate, pre-existing issue is fixed.
    /// Whether `element` is gone within `timeout` (polling, so it does not depend on `waitForNonExistence` availability).
    private func waitForDisappearance(of element: XCUIElement, timeout: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if !element.exists { return true }
            Thread.sleep(forTimeInterval: 0.2)
        }
        return !element.exists
    }

    private func button(labeled candidates: String...) -> XCUIElement {
        let predicate = NSPredicate(
            format: candidates.map { _ in "label == %@" }.joined(separator: " OR "),
            argumentArray: candidates
        )
        return app.buttons.matching(predicate).firstMatch
    }

    func testTappingTheFrontmostCardOpensItDirectly() {
        XCTAssertTrue(card(3).waitForExistence(timeout: 5))
        cardPoint(3).tap()

        XCTAssertTrue(app.navigationBars["Charlie"].waitForExistence(timeout: 5),
                      "tapping the already-frontmost card must open its detail screen directly")
    }

    func testTappingABuriedCardBringsItForwardInsteadOfOpeningIt() {
        XCTAssertTrue(card(1).waitForExistence(timeout: 5))

        // 1 ("Alpha") starts at the back of the deck, not the front.
        cardPoint(1).tap()
        XCTAssertFalse(app.navigationBars["Alpha"].waitForExistence(timeout: 1),
                       "a tap on a buried card must not open it")

        // Tapping the SAME card again now opens it - proof the first tap
        // actually moved it to the front rather than doing nothing. Now
        // frontmost, its own center is safely inside its (fully uncovered)
        // frame too.
        cardPoint(1).tap()
        XCTAssertTrue(app.navigationBars["Alpha"].waitForExistence(timeout: 5),
                      "the second tap on the same card must open it now that it's frontmost")
        button(labeled: "Back", "nav.back").tap()
    }

    func testALongDragPullsABuriedCardToTheFront() {
        XCTAssertTrue(card(2).waitForExistence(timeout: 5))

        // Starts in 2's own uncovered peek band and travels 30% of its own
        // height - comfortably past CREDENTIAL_PULL_THRESHOLD_FRACTION
        // (0.18). Once a touch begins, subsequent move events stay owned by
        // that same gesture regardless of what the point later ends up
        // visually over.
        let start = cardPoint(2, dy: 0.15)
        let end = card(2).coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.45))
        start.press(forDuration: 0.05, thenDragTo: end)

        // The pull committed: 2 ("Bravo") is now frontmost, so a plain tap
        // opens it without a second tap being needed.
        cardPoint(2).tap()
        XCTAssertTrue(app.navigationBars["Bravo"].waitForExistence(timeout: 5),
                      "a long drag past the pull threshold must commit the reorder")
        button(labeled: "Back", "nav.back").tap()
    }

    func testAShortDragSpringsBackWithoutReorderingTheDeck() {
        XCTAssertTrue(card(1).waitForExistence(timeout: 5))

        // Past touch slop (registers as a drag, not a tap) but well under
        // CREDENTIAL_PULL_THRESHOLD_FRACTION (0.18) - only 5% of the card's
        // own height.
        let start = cardPoint(1, dy: 0.15)
        let end = card(1).coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.20))
        start.press(forDuration: 0.05, thenDragTo: end)

        // The drag did not reach the threshold, so the deck's front is
        // unchanged: 3 ("Charlie") still opens on the first tap...
        cardPoint(3).tap()
        XCTAssertTrue(app.navigationBars["Charlie"].waitForExistence(timeout: 5))
        button(labeled: "Back", "nav.back").tap()

        // ...and 1 ("Alpha"), which is what was actually dragged, is still
        // buried: one tap on it only brings it forward, exactly as if the
        // drag had never happened.
        cardPoint(1).tap()
        XCTAssertFalse(app.navigationBars["Alpha"].waitForExistence(timeout: 1),
                       "the short drag must not have brought Alpha to the front")
    }

    func testALongPressReportsLongClickWithoutOpeningOrReordering() {
        XCTAssertTrue(card(1).waitForExistence(timeout: 5))

        // Held perfectly still (no simulated movement at all) for longer
        // than `credentialLongPressDuration` (0.5s) - `press(forDuration:thenDragTo:)`
        // to the SAME point synthesizes a touch-down, an unmoving hold, then
        // a lift, which is exactly the case that distinguishes a real
        // timer-based long-press from one that only checks elapsed time
        // reactively when a touch-move event arrives (which a motionless
        // hold never delivers) - see this file's top doc comment. A
        // coordinate within 1's own peek band, not `XCUIElement.press(forDuration:)`
        // (which activates at the element's reported CENTER - covered by
        // whichever card is drawn on top there).
        let point = cardPoint(1)
        point.press(forDuration: 0.8, thenDragTo: point)

        // The long-press action menu appears (Renew/Delete/Cancel) - not a
        // reorder, not a detail open. Its title is the credential's own
        // name ("Alpha"), confirming it's actually for the card that was
        // pressed, not whichever card happened to be frontmost.
        XCTAssertTrue(app.staticTexts["Alpha"].waitForExistence(timeout: 5),
                      "the long-press action sheet must be for the card that was actually pressed")
        XCTAssertTrue(button(labeled: "Delete", "common.delete").waitForExistence(timeout: 5),
                      "a still, held long-press must fire the long-press action")
        XCTAssertFalse(app.navigationBars["Alpha"].exists, "a long-press must not open detail")
        // Dismiss by tapping outside the dialog rather than its "Cancel"
        // button - confirmed necessary on this iOS version/screen size:
        // `.confirmationDialog` renders as a popover anchored low on screen
        // here, and with three rows (name/Renew/Delete) plus Cancel, Cancel
        // itself is clipped below the visible screen edge and isn't in the
        // accessibility tree at all. Tapping outside is the standard way to
        // dismiss any popover-style presentation regardless.
        let deleteButton = button(labeled: "Delete", "common.delete")
        let outside = app.coordinate(withNormalizedOffset: .zero).withOffset(CGVector(dx: 40, dy: 60))
        outside.tap()
        // The dismissal is animated: a tap on the deck while the popover is still going away is swallowed by it (the
        // source of this test's flake on slow runners). Wait until the dialog is really gone - tapping outside again
        // once if the first tap did not dismiss it - and the deck has stopped moving before interacting with it.
        if !waitForDisappearance(of: deleteButton, timeout: 4) {
            outside.tap()
            XCTAssertTrue(waitForDisappearance(of: deleteButton, timeout: 6), "the long-press dialog must dismiss")
        }
        waitForDeckToSettle()

        // The deck's front is unaffected by a long-press: 3 ("Charlie")
        // still opens directly.
        cardPoint(3).tap()
        XCTAssertTrue(app.navigationBars["Charlie"].waitForExistence(timeout: 5),
                      "a long-press on a buried card must not have reordered the deck")
    }
}
