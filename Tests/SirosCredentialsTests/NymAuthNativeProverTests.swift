// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class NymAuthNativeProverTests: XCTestCase {
    private func request() -> NymAuthProveRequest {
        NymAuthProveRequest(
            system: "longfellow-libzk-v1", circuitId: "c", circuitParams: ["k": .int(1)], circuit: Data([1, 2, 3]),
            issuerSigned: Data([4]), secretSeed: Array(repeating: 0xAB, count: 16), issuerKeyX: Array(repeating: 1, count: 32),
            issuerKeyY: Array(repeating: 2, count: 32), time: "2026-10-20T00:00:00Z", earliest: "0000-00-00", cutoff: "9999-12-31",
            challengeDigest: Array(repeating: 3, count: 32), deviceSignature: Array(repeating: 4, count: 64),
            verifierInput: Array(repeating: 5, count: 32), transcriptSeed: [6])
    }

    private struct Fixed: NymAuthNativeProver {
        func prove(_ request: NymAuthProveRequest) async throws -> NymAuthProveResponse {
            NymAuthProveResponse(proof: [1], pseudonym: [2])
        }
    }

    func testTheDefaultRefusesEveryRequestAndSubstitutesNothing() async {
        let registry = NymAuthNativeProverRegistry()
        XCTAssertFalse(registry.canProve)
        do {
            _ = try await registry.prover.prove(request())
            XCTFail("must refuse")
        } catch let error as NymAuthNativeError {
            XCTAssertEqual(error, NymAuthNativeError(.noNativeProver))
        } catch { XCTFail("typed error expected: \(error)") }
    }

    func testARegisteredProverIsUsedAndCanBeRemoved() async throws {
        let registry = NymAuthNativeProverRegistry(Fixed())
        XCTAssertTrue(registry.canProve)
        let response = try await registry.prover.prove(request())
        XCTAssertEqual(response.proof, [1])
        registry.register(nil)
        XCTAssertFalse(registry.canProve)
    }

    func testRequestAndResponseNeverPrintTheirContent() {
        var dumped = ""
        dump(request(), to: &dumped)
        dump(NymAuthProveResponse(proof: [0xCD], pseudonym: [0xEF]), to: &dumped)
        let all = [dumped, "\(request())", "\(String(reflecting: request()))"].joined()
        for needle in ["171", "0xAB", "ab", "2026-10-20", "longfellow"] {
            XCTAssertFalse(all.contains(needle), needle)
        }
        XCTAssertEqual("\(request())", "NymAuthProveRequest(redacted)")
    }

    func testBindingErrorsMapToCoarseKindsWithoutAMessage() {
        XCTAssertEqual(NymAuthNativeError.vega(variant: "UnknownCircuit").kind, .unsupportedCircuit)
        XCTAssertEqual(NymAuthNativeError.vega(variant: "Refused", refusedCode: "SeedMismatch"), NymAuthNativeError(.refused, refusal: .seedMismatch))
        XCTAssertEqual(NymAuthNativeError.vega(variant: "Refused", refusedCode: "novel").refusal, .unsatisfied)
        XCTAssertEqual(NymAuthNativeError.vega(variant: "Whatever").kind, .internal)
        XCTAssertEqual(NymAuthNativeError.longfellow(variant: "Credential"), NymAuthNativeError(.refused, refusal: .credential))
        XCTAssertEqual(NymAuthNativeError.longfellow(variant: "Verification").kind, .proofInvalid)
        XCTAssertEqual(NymAuthNativeError.longfellow(variant: "?").kind, .internal)
        XCTAssertEqual(NymAuthNativeError(.refused, refusal: .unsatisfied).description, "nymauth native prover: refused (unsatisfied)")
    }
}
