// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

final class RemoteIDVClientTests: XCTestCase {

    private let fallback: (String) -> IDVError = { .verificationFailed(message: $0) }

    func testNfcCodeBecomesDocumentChipNotVerified() {
        for reason in [
            "nfc_skipped",
            "nfc_not_supported_by_document",
            "nfc_device_not_capable",
            "nfc_chip_read_failed",
            "nfc_not_authenticated",
        ] {
            let error = RemoteIDVClient.idvError(
                for422ErrorCode: reason,
                errorMessage: "NFC verification was skipped",
                responseBody: "{}",
                fallback: fallback
            )

            guard case let .documentChipNotVerified(gotReason, message) = error else {
                return XCTFail("\(reason): expected documentChipNotVerified, got \(error)")
            }
            XCTAssertEqual(gotReason, reason)
            XCTAssertEqual(message, "NFC verification was skipped")
            XCTAssertEqual(error.errorCode, "idv_\(reason)")
            XCTAssertEqual(error.errorDescription, "NFC verification was skipped")
        }
    }

    func testNfcCodeWithoutMessageFallsBackToBody() {
        let error = RemoteIDVClient.idvError(
            for422ErrorCode: "nfc_skipped", errorMessage: nil, responseBody: "raw body", fallback: fallback
        )

        XCTAssertEqual(error.errorDescription, "raw body")
    }

    func testOtherCodeKeepsStepErrorAndRawBody() {
        let body = #"{"error":"scan rejected by policy","error_code":"policy_rejected"}"#
        let error = RemoteIDVClient.idvError(
            for422ErrorCode: "policy_rejected", errorMessage: "scan rejected by policy", responseBody: body, fallback: fallback
        )

        guard case let .verificationFailed(message) = error else {
            return XCTFail("expected verificationFailed, got \(error)")
        }
        XCTAssertEqual(message, body)
        XCTAssertEqual(error.errorCode, "idv_verification_failed")
    }

    func testBodyWithoutCodeKeepsStepError() {
        let error = RemoteIDVClient.idvError(
            for422ErrorCode: nil, errorMessage: nil, responseBody: "not json", fallback: fallback
        )

        guard case .verificationFailed = error else {
            return XCTFail("expected verificationFailed, got \(error)")
        }
    }
}
