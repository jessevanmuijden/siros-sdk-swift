// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

/// Pure Swift, no CryptoKit - unlike `JweKeystore`/`WscdKeystoreAdapter`'s own `signVpToken` tests, this runs (and
/// is actually verified) on Linux too. Covers the nil-vs-empty decision `SdJwtDisclosureSelection.select` makes on
/// behalf of both keystores (review finding, go-wallet-backend#502): see its doc comment.
final class SdJwtDisclosureSelectionTests: XCTestCase {
    func testNilDisclosedClaimsSkipsTheFilterEntirely() {
        var filterCalls = 0
        let result = SdJwtDisclosureSelection.select(["a", "b"], disclosedClaims: nil) { ds, claims in
            filterCalls += 1
            return []
        }
        XCTAssertEqual(result, ["a", "b"], "nil means no filter was given at all - disclose everything")
        XCTAssertEqual(filterCalls, 0, "a nil disclosedClaims must never even reach the filter - it already means 'disclose all'")
    }

    /// Review finding: a non-nil EMPTY `disclosedClaims` used to take the SAME shortcut as `nil` (disclose
    /// everything). It must instead reach `filter`, like any other non-nil request - this is what actually fixes
    /// the bug, since `filter([...], [])` selects nothing.
    func testNonNilEmptyDisclosedClaimsStillReachesTheFilterRatherThanTakingTheNilShortcut() {
        var capturedClaims: [String]?
        let result = SdJwtDisclosureSelection.select(["a", "b"], disclosedClaims: []) { _, claims in
            capturedClaims = claims
            return []
        }
        XCTAssertEqual(capturedClaims, [], "an explicit empty array must reach the filter, not take the nil shortcut")
        XCTAssertEqual(result, [], "disclosing zero claims when explicitly asked for zero")
    }

    func testNonEmptyDisclosedClaimsIsPassedThroughToTheFilterUnchanged() {
        var capturedDisclosures: [String]?
        var capturedClaims: [String]?
        let result = SdJwtDisclosureSelection.select(["a", "b", "c"], disclosedClaims: ["given_name"]) { ds, claims in
            capturedDisclosures = ds
            capturedClaims = claims
            return ["a"]
        }
        XCTAssertEqual(capturedDisclosures, ["a", "b", "c"])
        XCTAssertEqual(capturedClaims, ["given_name"])
        XCTAssertEqual(result, ["a"], "the filter's own result is returned unchanged")
    }
}
