// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosAuth
import SirosCredentials
import SirosWallet

/// Settings → Devices: the actions behind `DevicesView` (the wallet instance
/// list, SID-AUTH-06, and deleting the account). Its `@Published` state stays in
/// `WalletViewModel.swift`, since Swift extensions cannot add stored
/// properties; only the behaviour lives here, mirroring the SDK's own
/// `SirosWallet+*.swift` split.
extension WalletViewModel {

    func openDevices() {
        deleteAccountError = nil
        showDevices = true
    }

    func closeDevices() {
        showDevices = false
        devicesError = nil
    }

    func refreshDevices() {
        Task { @MainActor in await loadDevices() }
    }

    /// The listing itself.
    @MainActor
    func loadDevices() async {
        guard let wallet else { return }
        devicesLoading = true
        devicesError = nil
        do {
            walletInstances = try await wallet.listWalletInstances()
        } catch {
            devicesError = error.localizedDescription
        }
        devicesLoading = false
    }

    /// Delete the account: the SDK asks for a passkey assertion (step-up),
    /// sends the typed confirmation and, when the backend accepts the
    /// deletion, wipes everything local, which returns the app to the
    /// logged-out screen. Any other outcome keeps the account and is shown in
    /// the sheet.
    func deleteAccount(confirmation: String) {
        Task { @MainActor in
            guard let wallet else { return }
            deletingAccount = true
            deleteAccountError = nil
            let result = await wallet.deleteAccount(confirmation: confirmation)
            deletingAccount = false
            switch result {
            case let .deleted(wipe):
                finishAccountDeletion(L10n.string("devices.deleteDone"), wipe: wipe)
            case let .cleanupPending(wipe):
                finishAccountDeletion(L10n.string("devices.deleteCleanupPending"), wipe: wipe)
            case let .operatorRequired(wipe):
                finishAccountDeletion(L10n.string("devices.deleteOperatorRequired"), wipe: wipe)
            case let .retryNeeded(reason):
                deleteAccountError = Self.message(for: reason)
            case let .failed(failure):
                deleteAccountError = Self.message(for: failure)
            }
        }
    }

    @MainActor
    private func finishAccountDeletion(_ message: String, wipe: LocalWipeReport) {
        resetDevicesNavigation()
        showAddCredential = false
        // `infoMessage` alone does not raise the banner - see `syncBanner()`.
        if wipe.isComplete {
            infoMessage = message
            showInfo = true
        } else {
            errorMessage = message + " " + L10n.string(
                "devices.deleteLocalIncomplete", wipe.failures.map(\.component).joined(separator: ", ")
            )
            showError = true
        }
    }

    private static func message(for reason: DeleteAccountRetryReason) -> String {
        switch reason {
        case .incomplete: return L10n.string("devices.deleteIncomplete")
        case .stepUpFailed, .stepUpRequired: return L10n.string("devices.deleteStepUpFailed")
        case .stepUpExpired: return L10n.string("devices.deleteStepUpExpired")
        }
    }

    private static func message(for failure: DeleteAccountFailure) -> String {
        switch failure {
        case .confirmationRequired: return L10n.string("devices.deleteConfirmationRequired")
        case .notLoggedIn, .sessionRejected: return L10n.string("devices.deleteNotLoggedIn")
        case .noPasskey: return L10n.string("devices.deleteNoPasskey")
        case .notPermitted: return L10n.string("devices.deleteNotPermitted")
        case let .stepUpAborted(message): return L10n.string("devices.deleteStepUpAborted", message)
        case .accountNotFound: return L10n.string("devices.deleteAccountNotFound")
        case let .requestFailed(message): return L10n.string("devices.deleteRequestFailed", message)
        }
    }

    /// Leaving the session must leave the Devices sub-screen: left set, it
    /// would be what the next login renders instead of the wallet tabs.
    func resetDevicesNavigation() {
        showDevices = false
        walletInstances = []
    }
}
