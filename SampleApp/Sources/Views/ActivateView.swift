// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// Merged QR scan + ISO 18013-5 proximity (BLE) engagement screen. QR
/// scanning is the default mode; a low-emphasis "use proximity instead" CTA
/// switches to `ProximityEngagementContent`. This view owns the single
/// `NavigationStack`/toolbar for both modes - `QRScannerContent` and
/// `ProximityEngagementContent` are embedded bar-less, so switching modes is
/// a plain in-place content swap with no double nav bar or back-stack churn.
/// Switching to proximity mode is forward-only: back/cancel from either mode
/// always means "leave Activate entirely," never "return to QR."
struct ActivateView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        NavigationStack {
            Group {
                switch viewModel.activateMode {
                case .qr:
                    QRScannerContent()
                case .proximity:
                    ProximityEngagementContent()
                }
            }
            .safeAreaInset(edge: .bottom) {
                if viewModel.activateMode == .qr {
                    Button(L10n.string("activate.useProximityInstead")) {
                        viewModel.switchActivateMode(.proximity)
                    }
                    .font(.subheadline)
                    .padding(.vertical, 8)
                    .frame(maxWidth: .infinity)
                    .background(.regularMaterial)
                }
            }
            .navigationTitle(viewModel.activateMode == .qr ? L10n.string("qr.title") : L10n.string("proximity.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(viewModel.activateMode == .qr ? L10n.string("common.cancel") : L10n.string("flow.closeButton")) {
                        viewModel.closeActivate()
                    }
                }
            }
        }
    }
}
