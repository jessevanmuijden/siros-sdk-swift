// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import UIKit
import SirosWallet
import SirosCredentials

/// FaceTec-backed PhotoID onboarding: the IDV preparation/consent screen
/// (`IDVPreparationView`) and the capture flow behind it (`startIDV()`).
/// `@Published showIDVPreparation`/`showPhotoIdOnboarding` state stays in
/// `WalletViewModel.swift`, since Swift extensions cannot add stored
/// properties; only the behaviour lives here, mirroring this app's existing
/// `WalletViewModel+Activate.swift`/`WalletViewModel+Devices.swift` split.
///
/// `showIDVPreparation` used to be `AddCredentialView`'s own local `@State`
/// (sheeted there only) - lifted to the ViewModel so Home's onboarding CTA
/// (see `HomeView`, gated by `showPhotoIdOnboarding`) can reach the same
/// screen directly, bypassing the Credentials tab/Add Credential list
/// entirely.
extension WalletViewModel {

    /// IDV server URL — defaults to facetec-api co-hosted behind /idv path.
    var idvServerUrl: String { backendUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/idv" }

    /// Shows the IDV preparation/consent screen - the real entry point for
    /// both the "Scan Physical ID card" row (`AddCredentialView`) and Home's
    /// PhotoID onboarding CTA (`HomeView`). Its own "Start Scan" action calls
    /// `startIDV()`.
    func openIDVPreparation() {
        showIDVPreparation = true
    }

    func closeIDVPreparation() {
        showIDVPreparation = false
    }

    func startIDV() {
        showAddCredential = false
        showIDVPreparation = false
        Task {
            do {
                isLoading = true
                guard let wallet else { throw SirosError.wallet(message: "Wallet is not connected") }
                let token = try await wallet.getAccessToken()
                let delegate = FaceTecCaptureDelegate()
                let client = RemoteIDVClient(config: RemoteIDVClient.Config(
                    serverUrl: idvServerUrl,
                    authToken: "Bearer \(token)"
                ))
                let provider = RemoteIDVProvider(client: client, delegate: delegate)
                let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene
                let rootViewController = windowScene?.windows.first?.rootViewController ?? UIViewController()
                try await wallet.verifyIdentityAndIssue(provider: provider, presentingViewController: rootViewController)
            } catch {
                // Per Copilot review: this must set `showError` too, not just
                // `errorMessage` - ContentView.syncBanner() only displays an
                // error when both are set, so a failure here previously sent
                // the user back to Home with no visible feedback at all.
                setError("IDV failed: \(error.localizedDescription)")
            }
            isLoading = false
        }
    }

    /// Whether `credentials` already includes the PhotoID credential (see
    /// `sirosIdCredentialConfigurationId`'s doc comment) - Home's onboarding
    /// CTA (gated by `showPhotoIdOnboarding`) only makes sense to offer when
    /// it's still missing.
    func hasPhotoIdCredential() -> Bool {
        credentials.contains { $0.credentialConfigurationId == sirosIdCredentialConfigurationId }
    }
}
