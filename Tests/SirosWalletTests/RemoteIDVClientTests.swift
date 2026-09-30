// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

final class RemoteIDVClientTests: XCTestCase {

    private let fallback: (String) -> IDVError = { .verificationFailed(message: $0) }

    func testNfcCodeBecomesDocumentChipNotVerified() {
        for reason in [
            "nfc_skipped",
            "nfc_not_requested",
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

    // MARK: - Through the real transport

    /// Posts `payload` to a loopback server answering `status` with `body`
    /// through `step`, and returns what it threw. These catch mistakes the
    /// mapping tests above cannot: the 422 check, the JSON field names, and
    /// which step's fallback applies.
    private func thrownError(
        status: Int,
        body: String,
        step: (RemoteIDVClient) async throws -> Void
    ) async throws -> IDVError {
        let server = try LoopbackServer(status: status, body: body)
        defer { server.stop() }
        let client = RemoteIDVClient(config: .init(serverUrl: "http://127.0.0.1:\(server.port)", authToken: "Bearer test"))
        do {
            try await step(client)
        } catch let error as IDVError {
            return error
        }
        XCTFail("expected an IDVError")
        return .cancelled
    }

    /// What facetec-api's `/v1/id-scan` answers for a scan without an
    /// authenticated chip: that path can only tell verified from not, so the
    /// code is always `nfc_skipped`.
    func testSubmitDocumentMapsNfcRefusal() async throws {
        let error = try await thrownError(
            status: 422,
            body: #"{"error":"NFC verification was skipped or failed","error_code":"nfc_skipped"}"#
        ) { _ = try await $0.submitDocument(payload: ["livenessSessionId": "s"]) }

        guard case let .documentChipNotVerified(reason, message) = error else {
            return XCTFail("expected documentChipNotVerified, got \(error)")
        }
        XCTAssertEqual(reason, "nfc_skipped")
        XCTAssertEqual(message, "NFC verification was skipped or failed")
        XCTAssertEqual(error.errorCode, "idv_nfc_skipped")
    }

    func testSubmitDocumentKeepsVerificationFailedForOtherCodes() async throws {
        let body = #"{"error":"scan rejected by policy","error_code":"policy_rejected"}"#
        let error = try await thrownError(status: 422, body: body) {
            _ = try await $0.submitDocument(payload: ["livenessSessionId": "s"])
        }

        guard case let .verificationFailed(message) = error else {
            return XCTFail("expected verificationFailed, got \(error)")
        }
        XCTAssertEqual(message, body)
    }

    func testSubmitBiometricKeepsLivenessFailed() async throws {
        let body = #"{"error":"liveness check did not pass","error_code":"liveness_failed"}"#
        let error = try await thrownError(status: 422, body: body) {
            _ = try await $0.submitBiometric(payload: ["faceScan": "x"])
        }

        guard case let .livenessFailed(message) = error else {
            return XCTFail("expected livenessFailed, got \(error)")
        }
        XCTAssertEqual(message, body)
    }

    func testNon422StaysANetworkError() async throws {
        let error = try await thrownError(
            status: 500,
            body: #"{"error":"x","error_code":"nfc_skipped"}"#
        ) { _ = try await $0.submitDocument(payload: ["livenessSessionId": "s"]) }

        guard case .networkError = error else {
            return XCTFail("expected networkError, got \(error)")
        }
    }
}
