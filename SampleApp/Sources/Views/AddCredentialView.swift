// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

/// Credential picker list — shows available credentials from all issuers.
struct AddCredentialView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var detailOffer: CredentialOffer?

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.isLoadingOffers {
                    VStack(spacing: 12) {
                        ProgressView()
                        Text(L10n.string("credentials.addLoading"))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    // The "Scan Physical ID card" row is always shown here,
                    // regardless of whether `availableCredentials` (the
                    // generic issuer-offer list, with the plain SIROS ID
                    // offer filtered out - see `openAddCredential`) is
                    // empty. A real bug this replaced: showing the plain
                    // "No credentials available" empty state instead of
                    // this List whenever SIROS ID was a tenant's only
                    // offer completely hid the one path meant to actually
                    // issue it, since this row previously lived only in
                    // the "offers non-empty" branch.
                    List {
                        Section {
                            Button(action: { viewModel.openIDVPreparation() }) {
                                HStack(spacing: 12) {
                                    ZStack {
                                        RoundedRectangle(cornerRadius: 8)
                                            .fill(Color.accentColor.opacity(0.15))
                                            .frame(width: 40, height: 40)
                                        Image(systemName: "camera")
                                            .foregroundColor(.accentColor)
                                    }
                                    VStack(alignment: .leading) {
                                        Text(L10n.string("credentials.scanPhysicalIdTitle"))
                                            .font(.body)
                                            .fontWeight(.medium)
                                        Text(L10n.string("credentials.scanPhysicalIdSubtitle"))
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                    Spacer()
                                    Image(systemName: "chevron.right")
                                        .foregroundColor(.secondary)
                                }
                            }
                            .buttonStyle(.plain)
                        }

                        if viewModel.availableCredentials.isEmpty {
                            Section {
                                Text(L10n.string("credentials.addEmpty"))
                                    .font(.body)
                                    .foregroundStyle(.secondary)
                            }
                        } else {
                            Section {
                                ForEach(viewModel.availableCredentials, id: \.offerIdentity) { offer in
                                    CredentialOfferRow(offer: offer)
                                        .contentShape(Rectangle())
                                        // `.onTapGesture` + `.onLongPressGesture` on the
                                        // same view both fire on a long-press release in
                                        // SwiftUI (a real bug this replaced: tapping to add
                                        // a credential could immediately follow opening its
                                        // detail sheet) - `exclusively(before:)` recognizes
                                        // whichever gesture succeeds first and suppresses
                                        // the other.
                                        .gesture(
                                            LongPressGesture(minimumDuration: 0.5)
                                                .onEnded { _ in detailOffer = offer }
                                                .exclusively(
                                                    before: TapGesture()
                                                        .onEnded { viewModel.selectCredentialOffer(offer) }
                                                )
                                        )
                                }
                            }
                        }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle(L10n.string("credentials.addTitle"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("nav.back")) { viewModel.closeAddCredential() }
                }
            }
            .alert(L10n.string("credentials.addConfirmTitle"), isPresented: showIssuanceConsent) {
                Button(L10n.string("credentials.addConfirmAccept")) { viewModel.confirmIssuance() }
                Button(L10n.string("common.cancel"), role: .cancel) { viewModel.cancelIssuance() }
            } message: {
                if let offer = viewModel.pendingIssuanceOffer {
                    Text(L10n.string("credentials.addConfirmMessage", offer.credentialName, offer.issuerName))
                }
            }
        }
        .sheet(isPresented: showDetailOffer) {
            if let offer = detailOffer {
                CredentialOfferDetailView(
                    offer: offer,
                    onAdd: {
                        detailOffer = nil
                        viewModel.selectCredentialOffer(offer)
                    },
                    onClose: { detailOffer = nil }
                )
            }
        }
    }

    private var showDetailOffer: Binding<Bool> {
        Binding(
            get: { detailOffer != nil },
            set: { if !$0 { detailOffer = nil } }
        )
    }

    private var showIssuanceConsent: Binding<Bool> {
        Binding(
            get: { viewModel.pendingIssuanceOffer != nil },
            set: { if !$0 { viewModel.cancelIssuance() } }
        )
    }
}

// MARK: - Credential Offer Row

struct CredentialOfferRow: View {
    let offer: CredentialOffer

    var body: some View {
        HStack(spacing: 12) {
            // Initial badge
            let bgColor = offer.backgroundColor.flatMap { Color(hex: $0) } ?? .accentColor
            Circle()
                .fill(bgColor)
                .frame(width: 40, height: 40)
                .overlay(
                    Text(offer.credentialName.prefix(1).uppercased())
                        .font(.headline.bold())
                        .foregroundStyle(.white)
                )

            VStack(alignment: .leading, spacing: 2) {
                Text(offer.credentialName)
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                Text(offer.issuerName)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }
}

// MARK: - Credential Offer Detail (long-press modal)

/// Detail modal shown on long-press of a `CredentialOfferRow` - lets the
/// user inspect the issuer name and (if published) the credential's
/// description before committing to the issuance-consent dialog, without
/// the row's own tap target already starting that flow.
struct CredentialOfferDetailView: View {
    let offer: CredentialOffer
    let onAdd: () -> Void
    let onClose: () -> Void

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                Text(offer.issuerName)
                    .font(.headline)
                if let description = offer.credentialDescription {
                    Text(description)
                        .font(.body)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding()
            .navigationTitle(offer.credentialName)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("credentials.rowActionClose")) { onClose() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.string("credentials.rowActionAdd")) { onAdd() }
                }
            }
        }
    }
}
