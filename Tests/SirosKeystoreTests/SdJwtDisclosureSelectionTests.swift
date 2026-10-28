// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
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

    /// Review finding (first pass): a non-nil EMPTY `disclosedClaims` used to take the SAME shortcut as `nil`
    /// (disclose everything).
    func testNonNilEmptyDisclosedClaimsSelectsNothing() {
        let result = SdJwtDisclosureSelection.select(["a", "b"], disclosedClaims: []) { _, _ in
            XCTFail("an explicit empty array must never reach a fail-open filter")
            return ["a", "b"]
        }
        XCTAssertEqual(result, [], "disclosing zero claims when explicitly asked for zero")
    }

    /// Review finding (second pass, go-wallet-backend#502): short-circuiting on `disclosedClaims == nil` alone is
    /// not enough - `filter` must never even be CALLED for an empty list either, because a real filter (like
    /// `JweKeystore.filterDisclosures`) fails open on a disclosure shape it cannot parse as a named claim (a
    /// two-element SD-JWT array-disclosure whose value isn't itself a string, e.g. `["salt", {"ssn": "..."}]`) -
    /// which would leak that disclosure through even with an empty `claimNames`. Reproduces that exact fail-open
    /// filter here to prove the empty case never reaches it, regardless of what a given `filter` would do with it.
    func testEmptyDisclosedClaimsNeverReachesAFailOpenFilterEvenForAnUnparseableDisclosure() {
        // `JweKeystore.filterDisclosures`, reproduced faithfully enough to matter: base64url-decode, parse as a
        // JSON array, and - the exact shape that leaked - treat a value that isn't itself a `String` (here, an
        // object, as a two-element SD-JWT array-disclosure's value can be) as "cannot tell", which it answers with
        // `true`, i.e. included no matter what `claimNames` says.
        func failOpenFilterLikeJweKeystore(_ disclosures: [String], claimNames: [String]) -> [String] {
            let requested = Set(claimNames)
            return disclosures.filter { disclosure in
                guard let data = Data(base64Encoded: disclosure),
                      let arr = try? JSONSerialization.jsonObject(with: data) as? [Any],
                      arr.count >= 2,
                      let claimName = arr[1] as? String else {
                    return true // include unparseable disclosures to be safe
                }
                return requested.contains(claimName)
            }
        }
        let twoElementValueIsAnObject = Data(#"["salt", {"ssn": "secret"}]"#.utf8).base64EncodedString()
        let result = SdJwtDisclosureSelection.select(
            [twoElementValueIsAnObject], disclosedClaims: [],
            filter: failOpenFilterLikeJweKeystore
        )
        XCTAssertEqual(result, [], "an empty request must win over any filter's fail-open behavior")
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
