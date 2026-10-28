// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class ConsentMatcherTests: XCTestCase {
    func testASubsetOfConsentedClaimsIsAllowedUnchanged() throws {
        let result = try ConsentMatcher.claimsToDisclose(
            disclosedClaims: ["given_name"], consented: ["given_name", "family_name"]
        )
        XCTAssertEqual(result, ["given_name"])
    }

    func testANilDisclosedClaimsIsReplacedByTheRecordedConsentNeverPassedThroughAsEverything() throws {
        let result = try ConsentMatcher.claimsToDisclose(disclosedClaims: nil, consented: ["given_name"])
        XCTAssertEqual(result, ["given_name"])
    }

    func testAClaimBeyondConsentRefuses() {
        XCTAssertThrowsError(
            try ConsentMatcher.claimsToDisclose(disclosedClaims: ["given_name", "ssn"], consented: ["given_name"])
        ) { XCTAssertTrue($0 is ConsentMismatch) }
    }

    func testNoRecordedConsentAtAllRefusesEvenForAnEmptyRequest() {
        XCTAssertThrowsError(try ConsentMatcher.claimsToDisclose(disclosedClaims: [], consented: nil)) {
            XCTAssertTrue($0 is ConsentMismatch, "cannot verify => refuse, never guessed")
        }
    }

    func testConsentedClaimsTakesTheLastSegmentOfEachPathDeduped() {
        let claims = ConsentMatcher.consentedClaims(
            requestedClaims: [["given_name"], ["eu.europa.ec.eudi.pid.1", "family_name"], ["given_name"]],
            credentialIds: ["7", "8"]
        )
        XCTAssertEqual(claims["7"], ["given_name", "family_name"])
        XCTAssertEqual(claims["8"], ["given_name", "family_name"])
    }
}
