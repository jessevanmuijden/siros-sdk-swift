// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosWallet
@testable import SirosSampleApp

/// Every refusal facetec-api v0.16.0 can answer with must reach the user as its
/// own localized message, not as the backend's raw description. The errors here
/// are the ones `FaceTecIDVProvider` produces for those codes.
///
/// The text is looked up through `L10n`, which does not resolve its JSON tables
/// under every build configuration (see `UITests`), so these tests read the
/// en/sv tables directly, like `MessageBannerTests`, instead of going through it.
@MainActor
final class IdvErrorMessageTests: XCTestCase {

    private let raw = "raw backend text"

    private var errors: [(code: String, error: IDVError)] {
        [
            ("liveness_failed", .livenessFailed(message: raw)),
            ("match_failed / document_unreadable / policy_rejected", .verificationFailed(message: raw)),
            ("session_expired", .sessionExpired(message: raw)),
            ("nfc_skipped", .documentChipNotVerified(reason: "nfc_skipped", message: raw)),
            ("nfc_not_requested", .documentChipNotVerified(reason: "nfc_not_requested", message: raw)),
            ("nfc_device_not_capable", .documentChipNotVerified(reason: "nfc_device_not_capable", message: raw)),
            ("nfc_chip_read_failed", .documentChipNotVerified(reason: "nfc_chip_read_failed", message: raw)),
            ("nfc_not_authenticated", .documentChipNotVerified(reason: "nfc_not_authenticated", message: raw)),
            ("chip_untrusted", .chipUntrusted(message: raw)),
            ("chip_photo_mismatch", .chipPhotoMismatch(message: raw)),
            ("document_expired", .documentExpired(message: raw)),
            ("issuance_failed", .providerError(code: "issuance_failed", message: raw)),
            ("internal_error", .providerError(code: "internal_error", message: raw)),
            ("initialization_failed", .providerError(code: "initialization_failed", message: raw)),
            ("unknown_internal_error", .providerError(code: "unknown_internal_error", message: raw)),
            ("no_session_result", .providerError(code: "no_session_result", message: raw)),
            ("locked_out", .providerError(code: "locked_out", message: raw)),
            ("request_aborted", .providerError(code: "request_aborted", message: raw)),
            ("cancelled", .cancelled),
            ("unavailable", .unavailable(reason: "x")),
            ("network_error", .networkError(underlying: URLError(.notConnectedToInternet))),
        ]
    }

    private func table(_ language: String) throws -> [String: Any] {
        // SampleApp/Tests/IdvErrorMessageTests.swift -> SampleApp/Resources/i18n/<language>.json
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("Resources/i18n/\(language).json")
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    private func text(_ key: String, in table: [String: Any]) -> String? {
        var current: Any = table
        for segment in key.split(separator: ".") {
            guard let next = (current as? [String: Any])?[String(segment)] else { return nil }
            current = next
        }
        return current as? String
    }

    func testEveryIdvErrorHasItsOwnKeyAndATranslation() throws {
        let en = try table("en")
        let sv = try table("sv")
        var keys = Set<String>()
        for (code, error) in errors {
            let key = WalletViewModel.idvErrorKey(for: error)
            keys.insert(key)
            XCTAssertNotNil(text(key, in: en), "\(code): \(key) missing from en.json")
            XCTAssertNotNil(text(key, in: sv), "\(code): \(key) missing from sv.json")
        }
        // match_failed, document_unreadable and policy_rejected share one typed
        // error (verificationFailed), so they share a key.
        XCTAssertEqual(keys.count, errors.count, "each error type has its own key")
    }

    func testMessageIsNeverEmpty() {
        for (code, error) in errors {
            XCTAssertFalse(WalletViewModel.idvErrorMessage(for: error).isEmpty, code)
        }
    }

    func testUnknownCodeFallsBackToTheErrorDescription() {
        let error = IDVError.providerError(code: "a_future_code", message: "something new")

        XCTAssertEqual(WalletViewModel.idvErrorMessage(for: error), "[a_future_code] something new")
    }

    func testUnresolvedDeviceKeyPlaceholderIsNotAKey() {
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: "$(FACETEC_DEVICE_KEY_IDENTIFIER)"), "")
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: "  "), "")
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: nil), "")
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: 7), "")
        XCTAssertEqual(WalletViewModel.deviceKeyIdentifier(fromInfoValue: " dev-key "), "dev-key")
    }
}
