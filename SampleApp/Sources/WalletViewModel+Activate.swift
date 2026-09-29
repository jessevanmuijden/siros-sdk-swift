// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Home's merged Activate screen (QR scan + proximity/BLE): the actions
/// behind `ActivateView`. Its `@Published showActivate`/`activateMode` state
/// stays in `WalletViewModel.swift`, since Swift extensions cannot add
/// stored properties; only the behaviour lives here, mirroring the SDK's own
/// `SirosWallet+*.swift` split (and this app's existing
/// `WalletViewModel+Devices.swift`).
extension WalletViewModel {

    /// Opens Activate, defaulting to QR mode (the default engagement path).
    /// Pass `.proximity` for a direct shortcut into tap-to-share mode (see
    /// `HomeView`'s long-press gesture on the SIROS mark).
    func openActivate(mode: ActivateMode = .qr) {
        activateMode = mode
        showActivate = true
    }

    /// Switches an already-open Activate screen into proximity/BLE mode.
    func switchActivateMode(_ mode: ActivateMode) {
        activateMode = mode
    }

    /// Leaves Activate entirely, from either mode.
    func closeActivate() {
        showActivate = false
    }
}
