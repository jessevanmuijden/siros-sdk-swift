// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore
import SirosCredentials

/// The EC TS12 SCA sign sequence (factors the sign applied, claimed in the signed payload).
final class ScaSignFlowTests: XCTestCase {
    private let can = SignerFactorCapability(canReachTwoCategories: true)
    private let remote = AuthenticationFactor(.possession, "key_in_remote_wscd")
    private let pin6 = AuthenticationFactor(.knowledge, "pin_6_or_more_digits")

    private final class Trace: @unchecked Sendable {
        var prompts = 0, payloads = 0, signs = 0
        var claimed: [AuthenticationFactor] = []
        var pinGivenToSign: Data?
    }

    private func run(
        plugin: String? = "r2ps", capability: SignerFactorCapability? = nil, pin: String = "123456",
        report: @escaping (Data) -> ScaSignReport? = { _ in nil }, trace: Trace = Trace()
    ) throws -> SignerScaOutcome {
        try ScaSignFlow.run(
            pluginId: plugin, capability: capability ?? can,
            promptPin: { trace.prompts += 1; return Data(pin.utf8) },
            payload: { factors in trace.payloads += 1; trace.claimed = factors; return Data("signing-input".utf8) },
            sign: { data, givenPin in
                trace.signs += 1
                trace.pinGivenToSign = givenPin
                return report(data) ?? ScaSignReport(signature: Data([9]), factors: [remote, pin6], satisfiesTwoCategories: true, shortfall: nil)
            }
        )
    }

    private func expectRefusal(_ file: StaticString = #filePath, line: UInt = #line, _ body: () throws -> Void) {
        XCTAssertThrowsError(try body(), file: file, line: line) {
            XCTAssertEqual(($0 as? TransactionDataError)?.reason, .insufficientAuthenticationFactors, "\($0)", file: file, line: line)
        }
    }

    func testTheHappyPathClaimsExactlyWhatTheSignReportedAndSignsThatPayload() throws {
        let t = Trace()
        let out = try run(trace: t)
        XCTAssertEqual(t.claimed, [remote, pin6])
        XCTAssertEqual(out.factors, [remote, pin6])
        XCTAssertEqual(out.signedData, Data("signing-input".utf8))
        XCTAssertEqual(t.payloads, 1)
        XCTAssertEqual(t.signs, 1)
        XCTAssertEqual(t.prompts, 1)
        XCTAssertEqual(t.pinGivenToSign, Data("123456".utf8), "the PIN typed for this sign is the one handed to the plugin")
    }

    func testFido2ClaimsAnExternalKey() throws {
        let t = Trace()
        let ext = AuthenticationFactor(.possession, "key_in_local_external_wscd")
        _ = try run(plugin: "fido2", report: { _ in ScaSignReport(signature: Data([1]), factors: [ext, self.pin6], satisfiesTwoCategories: true, shortfall: nil) }, trace: t)
        XCTAssertEqual(t.claimed, [ext, pin6])
    }

    /// Nothing is prompted, built or signed when the plugin cannot reach two categories.
    func testACapabilityShortfallRefusesFirst() {
        let t = Trace()
        expectRefusal { _ = try run(capability: .cannot("no"), trace: t) }
        XCTAssertEqual([t.prompts, t.payloads, t.signs], [0, 0, 0])
    }

    func testPluginsWithoutAFreshPinAuthenticationAreRefusedBeforeAnyPrompt() {
        for plugin in [nil, "softkey", "", "R2PS", "unknown"] {
            let t = Trace()
            expectRefusal { _ = try run(plugin: plugin, trace: t) }
            XCTAssertEqual([t.prompts, t.payloads, t.signs], [0, 0, 0], "\(String(describing: plugin))")
        }
    }

    func testAnEmptyOrNonUtf8SecretIsRefusedBeforeSigning() {
        for secret in [""] {
            let t = Trace()
            expectRefusal { _ = try run(pin: secret, trace: t) }
            XCTAssertEqual(t.signs, 0)
        }
        let t = Trace()
        expectRefusal {
            _ = try ScaSignFlow.run(pluginId: "r2ps", capability: can, promptPin: { Data([0xFF, 0xFE]) },
                                    payload: { _ in t.payloads += 1; return Data() }, sign: { _, _ in t.signs += 1; fatalError() })
        }
        XCTAssertEqual([t.payloads, t.signs], [0, 0])
    }

    /// The sign reporting something other than what the payload claims discards the signature.
    func testAMismatchBetweenClaimAndReportIsRefused() {
        let cases: [[AuthenticationFactor]] = [
            [remote, AuthenticationFactor(.knowledge, "pin_less_than_6_digits")],     // another PIN class
            [AuthenticationFactor(.possession, "key_in_local_external_wscd"), pin6],  // another possession
            [remote, pin6, AuthenticationFactor(.inherence, "face_device")],          // something extra
            [remote, pin6, pin6],                                                     // duplicated
            [pin6, AuthenticationFactor(.knowledge, "other")],                        // one category only
        ]
        for reported in cases {
            let t = Trace()
            expectRefusal {
                _ = try run(report: { _ in ScaSignReport(signature: Data([1]), factors: reported, satisfiesTwoCategories: true, shortfall: nil) }, trace: t)
            }
            XCTAssertEqual(t.signs, 1, "the sign ran; its result was discarded: \(reported)")
        }
    }

    func testAShortfallReportedByTheSignIsRefused() {
        expectRefusal {
            _ = try run(report: { _ in ScaSignReport(signature: Data([1]), factors: [self.remote], satisfiesTwoCategories: false, shortfall: "cached session") })
        }
        // Even matching factors do not count when the sign says it fell short.
        expectRefusal {
            _ = try run(report: { _ in ScaSignReport(signature: Data([1]), factors: [self.remote, self.pin6], satisfiesTwoCategories: false, shortfall: nil) })
        }
    }

    func testAnErrorFromThePayloadOrTheSignPropagates() {
        struct Boom: Error {}
        XCTAssertThrowsError(try ScaSignFlow.run(pluginId: "r2ps", capability: can, promptPin: { Data("1234".utf8) },
                                                  payload: { _ in throw Boom() }, sign: { _, _ in fatalError() })) { XCTAssertTrue($0 is Boom) }
        XCTAssertThrowsError(try ScaSignFlow.run(pluginId: "r2ps", capability: can, promptPin: { Data("1234".utf8) },
                                                  payload: { _ in Data() }, sign: { _, _ in throw Boom() })) { XCTAssertTrue($0 is Boom) }
    }

    /// The same boundaries the manager measures (`classify_secret` in siros-wscd-manager).
    func testSecretClassesAreMeasuredAtTheVocabularyBoundaries() {
        let cases: [(String, String?)] = [
            ("12345", "pin_less_than_6_digits"), ("123456", "pin_6_or_more_digits"), ("1234567890", "pin_6_or_more_digits"),
            ("abc123", "passphrase_less_than_8_chars"), ("abcdefg1", "passphrase_8_to_11_chars"),
            ("abcdefghij1", "passphrase_8_to_11_chars"), ("abcdefghijk1", "passphrase_12_or_more_chars"),
            ("1234567a", "passphrase_8_to_11_chars"), ("", nil),
        ]
        for (secret, expected) in cases {
            XCTAssertEqual(ScaSignFlow.classifySecret(Data(secret.utf8)), expected, secret)
        }
        XCTAssertNil(ScaSignFlow.classifySecret(Data([0xFF])))
        // Scalars, not grapheme clusters: seven scalars in one cluster is still under eight.
        XCTAssertEqual(ScaSignFlow.classifySecret(Data(("e" + String(repeating: "\u{0301}", count: 7)).utf8)), "passphrase_8_to_11_chars")
        // A leading BOM is a scalar the manager counts: "\u{FEFF}123456" is seven scalars and not all digits.
        XCTAssertEqual(ScaSignFlow.classifySecret(Data("\u{FEFF}123456".utf8)), "passphrase_less_than_8_chars")
        // Non-ASCII digits are not a PIN.
        XCTAssertEqual(ScaSignFlow.classifySecret(Data("١٢٣٤٥٦".utf8)), "passphrase_less_than_8_chars")
    }
}
