// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

/// The wallet's default landing screen: the SIROS mark and a single primary
/// "Activate" CTA, so a first-time user has one obvious next step instead of
/// choosing up front between QR scanning and proximity/BLE presentation (see
/// `ActivateView`, which offers that choice one level in). When the wallet
/// has no credentials yet, a smaller secondary link to Add Credential is also
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
                Text(L10n.string("home.activateButton"))
                    .font(.title3.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .frame(height: 48)
            }
            .buttonStyle(.borderedProminent)
            .tint(SirosTheme.brand)
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .padding(.horizontal, 32)

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
