// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// The wallet's default landing screen: the SIROS mark itself, enlarged and
/// made tappable, IS the single primary CTA - a QR-scan symbol is painted
/// directly on it in white - so a first-time user has one obvious next step
/// instead of choosing up front between QR scanning and proximity/BLE
/// presentation. A long-press on the ball is a shortcut straight into
/// tap-to-share mode (see `ActivateView`'s "tap to share instead" secondary
/// CTA for the equivalent, less-discoverable in-screen path). When the
/// wallet has no credentials yet, a smaller secondary link to Add Credential
/// is also shown - it disappears once the wallet holds at least one
/// credential, since the Credentials tab's own "+" action (and its
/// empty-state card) cover that case from then on.
struct HomeView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            ZStack {
                SirosMarkView(size: 260)
                    .frame(width: 260, height: 260)
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(size: 42, weight: .semibold))
                    .foregroundColor(.white)
            }
            .contentShape(Circle())
            // `.onTapGesture` + `.onLongPressGesture` on the same view both
            // fire on a long-press release in SwiftUI (see
            // `AddCredentialView`'s identical fix) - `exclusively(before:)`
            // recognizes whichever gesture succeeds first and suppresses
            // the other, so a long-press can never also trigger the tap.
            .gesture(
                LongPressGesture(minimumDuration: 0.5)
                    .onEnded { _ in viewModel.openActivate(mode: .proximity) }
                    .exclusively(
                        before: TapGesture()
                            .onEnded { viewModel.openActivate() }
                    )
            )
            .accessibilityLabel(L10n.string("home.activateButton"))
            .accessibilityAddTraits(.isButton)
            // The raw LongPressGesture/TapGesture composition above has no
            // VoiceOver equivalent of its own - a real Copilot-review finding:
            // adding the .isButton trait alone only changes how this view is
            // ANNOUNCED, it doesn't give VoiceOver an activation action, so a
            // VoiceOver user could neither trigger the default QR scan nor
            // reach the long-press shortcut at all. The unnamed action below
            // is what VoiceOver's standard double-tap invokes; the named one
            // surfaces as an additional custom action (rotor/actions menu).
            .accessibilityAction { viewModel.openActivate() }
            .accessibilityAction(named: Text(L10n.string("activate.useProximityInstead"))) {
                viewModel.openActivate(mode: .proximity)
            }

            if viewModel.credentials.isEmpty {
                Button(L10n.string("home.addCredentialButton")) {
                    viewModel.openAddCredential()
                }
                .font(.subheadline)
                .foregroundColor(SirosTheme.onSurfaceVariant)
            }

            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(SirosTheme.background)
    }
}
