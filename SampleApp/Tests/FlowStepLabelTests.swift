// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosSampleApp

/// Every client-side step the SDK publishes before the engine's first progress
/// event must have a label of its own - an unknown token falls back to the
/// generic "Processing..." one, which is the silent gap this state exists to
/// close. Kotlin twin: `FlowStepLabelTest` in siros-sdk-kotlin PR 277.
final class FlowStepLabelTests: XCTestCase {
    private let clientSideSteps = [
        "initializing", "connecting_engine", "establishing_session",
        "checking_entitlement", "preparing_issuance", "starting_flow",
    ]

    /// Holds whether or not the unit-test bundle carries the string table: an
    /// unmapped step yields the generic key (table absent) or its text (present).
    func testEveryPreEngineStepHasItsOwnLabel() {
        let unknown = L10n.string("flow.steps.unknown")
        for step in clientSideSteps {
            XCTAssertNotEqual(flowStepLabel(step), unknown, "\(step) fell back to the generic label")
        }
    }

    /// The table itself is read from the source tree (as `MessageBannerTests`
    /// does), since the test bundle may not carry it.
    func testInitializingIsInBothLanguageTables() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        for name in ["en", "sv"] {
            let data = try Data(contentsOf: root.appendingPathComponent("Resources/i18n/\(name).json"))
            let json = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
            let steps = try XCTUnwrap((json["flow"] as? [String: Any])?["steps"] as? [String: Any])
            XCTAssertFalse((steps["initializing"] as? String ?? "").isEmpty, "\(name).json has no flow.steps.initializing")
        }
    }

    func testPreEngineStepsHaveNoProgressFractionSoTheBarStaysIndeterminate() {
        for step in clientSideSteps {
            XCTAssertNil(flowStepProgress(flowType: "issuance", step: step))
        }
    }
}
