// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class PresentationConsentCoordinatorTests: XCTestCase {
    private func request(label: String = "Example RP", scope: PresentationConsentItem.PseudonymScope = .perVerifier) -> PresentationConsentRequest {
        PresentationConsentRequest(
            verifier: PresentationConsentVerifier(
                label: label, trustFramework: nil, trustIdentifier: nil, verifierId: "rp.example", verifierIdType: nil, intermediaryRisk: false),
            entries: [PresentationConsentEntry(
                credential: PresentationConsentCredential(name: "Nym", issuer: nil),
                items: [.pseudonym(config: "known-offender-matching-ssc", scope: scope, remappableByIssuer: true, crossSite: scope == .crossSite, verifierId: "rp.example", verifierContext: nil)])],
            requestSigned: true)
    }

    private func shown(_ coordinator: PresentationConsentCoordinator) async throws -> PresentationConsentCoordinator.Pending {
        for _ in 0..<400 {
            if let current = coordinator.current { return current }
            try await Task.sleep(nanoseconds: 5_000_000)
        }
        XCTFail("nothing was shown")
        throw CancellationError()
    }

    func testTheAppGetsTheSdkWordingAndAnswersOnce() async throws {
        let coordinator = PresentationConsentCoordinator(locale: Locale(identifier: "sv"))
        coordinator.onChange = { _ in }
        let asked = Task { try await coordinator.confirm(self.request()) }
        let pending = try await shown(coordinator)
        XCTAssertEqual(pending.request.screen.header, "Example RP ber dig bevisa:")
        XCTAssertEqual(pending.request.screen.shareLabel, "Dela")
        XCTAssertEqual(pending.request.request.verifier.label, "Example RP")
        XCTAssertTrue(pending.answer(true))
        XCTAssertFalse(pending.answer(false))
        let answer = try await asked.value
        XCTAssertTrue(answer)
        XCTAssertNil(coordinator.current)
    }

    func testDeclineDismissAndNoUiAreNeverConsent() async throws {
        let coordinator = PresentationConsentCoordinator()
        let withoutUi = try await coordinator.confirm(request())
        XCTAssertFalse(withoutUi, "nobody could show it")

        coordinator.onChange = { _ in }
        let declined = Task { try await coordinator.confirm(self.request()) }
        let pending = try await shown(coordinator)
        XCTAssertTrue(pending.decline())
        let first = try await declined.value
        XCTAssertFalse(first)

        let dismissed = Task { try await coordinator.confirm(self.request()) }
        _ = try await shown(coordinator)
        coordinator.dismiss()
        let second = try await dismissed.value
        XCTAssertFalse(second)
    }

    func testAnUnansweredRequestExpiresAsADecline() async throws {
        let coordinator = PresentationConsentCoordinator(timeout: 0.15)
        coordinator.onChange = { _ in }
        let answer = try await coordinator.confirm(request())
        XCTAssertFalse(answer)
        XCTAssertNil(coordinator.current)
    }

    func testARequestTheWordingDoesNotCoverIsDeclinedWithoutBeingShown() async throws {
        let coordinator = PresentationConsentCoordinator()
        let shownCount = Counter()
        coordinator.onChange = { if $0 != nil { shownCount.increment() } }
        let answer = try await coordinator.confirm(request(scope: .crossSite))
        XCTAssertFalse(answer)
        XCTAssertEqual(shownCount.value, 0, "the user is never asked to approve a screen that omits something")
    }

    func testANewRequestDeclinesThePendingOne() async throws {
        let coordinator = PresentationConsentCoordinator()
        coordinator.onChange = { _ in }
        let first = Task { try await coordinator.confirm(self.request(label: "First")) }
        let stale = try await shown(coordinator)
        let second = Task { try await coordinator.confirm(self.request(label: "Second")) }
        let firstAnswer = try await first.value
        XCTAssertFalse(firstAnswer)
        for _ in 0..<400 where coordinator.current?.request.request.verifier.label != "Second" { try await Task.sleep(nanoseconds: 5_000_000) }
        XCTAssertFalse(stale.answer(true), "the outgoing sheet cannot answer the new request")
        let fresh = try await shown(coordinator)
        XCTAssertTrue(fresh.answer(true))
        let secondAnswer = try await second.value
        XCTAssertTrue(secondAnswer)
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        func increment() { lock.withLock { n += 1 } }
        var value: Int { lock.withLock { n } }
    }
}
