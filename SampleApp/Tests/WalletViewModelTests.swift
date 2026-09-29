// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosWallet
import SirosCredentials
@testable import SirosSampleApp

/// Unit tests for WalletViewModel.
/// Mirrors the Kotlin sample-app's WalletViewModelTest coverage.
///
/// `WalletViewModel` is internal to the `SirosSampleApp` app target (not a
/// member of the `SirosWallet`/`SirosCredentials` SPM packages it consumes),
/// so it needs `@testable import SirosSampleApp` to be visible here - the
/// same fix applied to this file's sibling `MessageBannerTests.swift`.
@MainActor
final class WalletViewModelTests: XCTestCase {

    private func makeViewModel() -> WalletViewModel {
        WalletViewModel()
    }

    // MARK: - Configuration

    func testDefaultBackendAndTenant() {
        let vm = makeViewModel()
        #if DEBUG
        XCTAssertEqual(vm.backendUrl, "http://192.168.240.1:8090")
        #else
        XCTAssertEqual(vm.backendUrl, "https://wallet.sirosid.dev")
        #endif
        XCTAssertEqual(vm.tenantId, "default")
    }

    // MARK: - Error handling

    func testClearErrorResetsState() {
        let vm = makeViewModel()
        vm.errorMessage = "Something broke"
        vm.showError = true

        vm.clearError()

        XCTAssertNil(vm.errorMessage)
        XCTAssertFalse(vm.showError)
    }

    // MARK: - Navigation

    func testOpenAddCredentialSetsLoadingState() {
        let vm = makeViewModel()
        vm.openAddCredential()

        XCTAssertTrue(vm.showAddCredential)
        // isLoadingOffers starts true then async sets to false
    }

    func testCloseAddCredentialResetsFlag() {
        let vm = makeViewModel()
        vm.showAddCredential = true
        vm.closeAddCredential()
        XCTAssertFalse(vm.showAddCredential)
    }

    func testOpenCredentialDetailSetsSelection() {
        let vm = makeViewModel()
        let credential = StoredCredential(id: 1, format: "vc+sd-jwt", raw: "{}", batchId: 1, instanceId: 0)
        vm.openCredentialDetail(credential)
        XCTAssertEqual(vm.selectedCredential?.id, 1)
    }

    func testCloseCredentialDetailClearsSelection() {
        let vm = makeViewModel()
        vm.selectedCredential = StoredCredential(id: 1, format: "vc+sd-jwt", raw: "{}", batchId: 1, instanceId: 0)
        vm.closeCredentialDetail()
        XCTAssertNil(vm.selectedCredential)
    }

    func testOpenHistorySetsFlag() {
        let vm = makeViewModel()
        vm.openHistory()
        XCTAssertTrue(vm.showHistory)
    }

    func testCloseHistoryClearsFlag() {
        let vm = makeViewModel()
        vm.showHistory = true
        vm.closeHistory()
        XCTAssertFalse(vm.showHistory)
    }

    func testOpenActivateSetsFlag() {
        let vm = makeViewModel()
        vm.openActivate()
        XCTAssertTrue(vm.showActivate)
        XCTAssertEqual(vm.activateMode, .qr)
    }

    /// Exercises a real mode transition (unlike `testOpenActivateSetsFlag`,
    /// which starts from the default `.qr` and would pass even if
    /// `openActivate()` stopped resetting a previous mode) - per Copilot
    /// review.
    func testOpenActivateResetsModeToQrAfterASwitchToProximity() {
        let vm = makeViewModel()
        vm.openActivate()
        vm.switchActivateMode(.proximity)
        XCTAssertEqual(vm.activateMode, .proximity)
        vm.closeActivate()

        vm.openActivate()

        XCTAssertTrue(vm.showActivate)
        XCTAssertEqual(vm.activateMode, .qr, "reopening Activate must always start in QR mode, even after a prior session left it in proximity mode")
    }

    func testCloseActivateClearsFlag() {
        let vm = makeViewModel()
        vm.showActivate = true
        vm.closeActivate()
        XCTAssertFalse(vm.showActivate)
    }

    // MARK: - Disconnect

    func testDisconnectClearsState() {
        let vm = makeViewModel()
        vm.selectedTab = 2
        vm.showAddCredential = true
        vm.selectedCredential = StoredCredential(id: 2, format: "jwt", raw: "", batchId: 2, instanceId: 0)
        vm.showHistory = true
        vm.activateMode = .proximity
        vm.showActivate = true

        vm.disconnect()

        XCTAssertEqual(vm.selectedTab, 1)
        XCTAssertFalse(vm.showAddCredential)
        XCTAssertNil(vm.selectedCredential)
        XCTAssertFalse(vm.showHistory)
        XCTAssertFalse(vm.showActivate)
        XCTAssertTrue(vm.availableCredentials.isEmpty)
    }

    /// Regression test for a real bug found via an on-device UI test run:
    /// `MainTabView` used to own `selectedTab` as local `@State`, which reset
    /// to its default every time `ContentView`'s top-level switch tore it
    /// down and recreated it (e.g. opening then closing a credential's
    /// detail screen) - so returning from ANY sibling screen silently
    /// bounced the user back to Home regardless of which tab they were
    /// actually on. `selectedTab` living on the view model instead must
    /// survive exactly that round trip.
    func testSelectedTabSurvivesAcrossViewModelLifetime() {
        let vm = makeViewModel()
        XCTAssertEqual(vm.selectedTab, 1, "Home must be the default tab")
        vm.selectedTab = 0
        vm.selectedCredential = StoredCredential(id: 3, format: "jwt", raw: "", batchId: 3, instanceId: 0)
        vm.selectedCredential = nil
        XCTAssertEqual(vm.selectedTab, 0, "selectedTab must not reset just because a sibling screen opened and closed")
    }

    // MARK: - Auth redirect

    func testHandleAuthRedirectWithNoPendingFlowSetsError() {
        let vm = makeViewModel()
        // No pending flow ID — simulate receiving a redirect
        vm.handleDeepLink(URL(string: "siros-sample://callback?code=abc&state=xyz")!)

        // Should set error since no wallet is configured
        // The deep link classifier will match authCallback but wallet is nil
    }

    // MARK: - QR result routing

    /// Unclassified URIs are treated as a presentation-request fallback
    /// (matches DeepLinkClassifier's own `.unknown` case for plain
    /// https://...?request_uri= shapes it doesn't recognize) - closes the
    /// scanner and attempts `startPresentation` rather than surfacing an
    /// error immediately.
    func testHandleQrResultWithUnknownUriFallsBackToPresentation() {
        let vm = makeViewModel()
        vm.showActivate = true
        vm.handleQrResult("https://example.com/not-a-wallet-uri")
        XCTAssertFalse(vm.showActivate)
        XCTAssertNil(vm.errorMessage)
    }

    func testHandleQrResultClosesScanner() {
        let vm = makeViewModel()
        vm.showActivate = true
        vm.handleQrResult("openid-credential-offer://some-offer")
        XCTAssertFalse(vm.showActivate)
    }

    // MARK: - Flow starting interstitial

    /// `flowStarting` must be set synchronously (not after the Task hop) so
    /// the interstitial covers the entire gap starting the instant the scan
    /// is classified - not just from whenever the Task first gets scheduled.
    func testHandleQrResultSetsFlowStartingSynchronouslyForCredentialOffer() {
        let vm = makeViewModel()
        vm.handleQrResult("openid-credential-offer://some-offer")
        XCTAssertEqual(vm.flowStarting, "issuance")
    }

    func testHandleQrResultSetsFlowStartingForUnknownUriFallback() {
        let vm = makeViewModel()
        vm.handleQrResult("https://example.com/not-a-wallet-uri")
        XCTAssertEqual(vm.flowStarting, "presentation")
    }

    /// An auth-callback QR (or deep link) isn't an issuance/presentation
    /// handoff at all - no interstitial should appear for it.
    func testHandleQrResultDoesNotSetFlowStartingForAuthCallback() {
        let vm = makeViewModel()
        vm.handleQrResult("siros-sample://callback?code=abc&state=xyz")
        XCTAssertNil(vm.flowStarting)
    }

    func testCancelFlowStartingClearsFlag() {
        let vm = makeViewModel()
        vm.handleQrResult("openid-credential-offer://some-offer")
        XCTAssertEqual(vm.flowStarting, "issuance")

        vm.cancelFlowStarting()

        XCTAssertNil(vm.flowStarting)
    }

    // MARK: - Presentation consent

    func testAcceptPresentationClearsPending() {
        let vm = makeViewModel()
        let request = PresentationRequest(
            verifierName: "Test Verifier",
            candidates: [StoredCredential(id: 3, format: "jwt", raw: "", batchId: 3, instanceId: 0)]
        )
        vm.pendingPresentation = request

        vm.acceptPresentation([3])

        XCTAssertNil(vm.pendingPresentation)
    }

    func testDeclinePresentationClearsPending() {
        let vm = makeViewModel()
        let request = PresentationRequest(
            verifierName: "Test Verifier",
            candidates: [StoredCredential(id: 3, format: "jwt", raw: "", batchId: 3, instanceId: 0)]
        )
        vm.pendingPresentation = request

        vm.declinePresentation()

        XCTAssertNil(vm.pendingPresentation)
    }
}
