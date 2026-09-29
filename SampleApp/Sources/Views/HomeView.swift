// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// The wallet's default landing screen: the SIROS mark and a single primary
/// CTA - a QR-scan symbol - so a first-time user has one obvious next step
/// instead of choosing up front between QR scanning and proximity/BLE
/// presentation (see `ActivateView`, which offers that choice one level in
/// via its own "use proximity instead" secondary CTA). When the wallet has
/// no credentials yet, a smaller secondary link to Add Credential is also
/// shown - it disappears once the wallet holds at least one credential,
/// since the Credentials tab's own "+" action (and its empty-state card)
/// cover that case from then on.
struct HomeView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        VStack(spacing: 24) {
            Spacer()

            SirosMarkView(size: 112)
                .frame(width: 112, height: 112)

            Button(action: { viewModel.openActivate() }) {
                Image(systemName: "qrcode.viewfinder")
                    .font(.system(size: 32, weight: .semibold))
                    .frame(width: 80, height: 80)
            }
            .buttonStyle(.borderedProminent)
            .tint(SirosTheme.brand)
            .clipShape(Circle())
            .accessibilityLabel(L10n.string("home.activateButton"))

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
