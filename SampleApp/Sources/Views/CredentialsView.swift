// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

struct CredentialsView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    /// One entry per batch (see `StoredCredential.batchId`) instead of one
    /// per issued copy - mirrors wallet-frontend's `fetchVcData` grouping
    /// (and the Kotlin sample app's `CredentialsTab`) so a 5-copy batch
    /// issuance shows as a single card with a remaining-copies ribbon, not
    /// five swipeable duplicates.
    private var grouped: [CredentialWithInstances] {
        CredentialUtils.groupForDisplay(
            credentials: viewModel.credentials,
            presentationHistory: viewModel.currentPresentationHistory
        )
    }

    /// Long-press action menu (Renew/Delete), driven by `CredentialStack`'s
    /// `onCredentialLongClick` rather than SwiftUI's native `.contextMenu` -
    /// see `CredentialStack.swift`'s doc comment for why a native
    /// `.contextMenu` (this screen's previous long-press mechanism, before
    /// the stack) can't be reused here: it's a self-contained system
    /// interaction with its own gesture recognizer, not something that can
    /// be triggered imperatively from a hand-rolled one, and layering it
    /// alongside a custom drag/tap recognizer on the same card reproduces
    /// the same two-recognizers-starve-each-other problem the stack's own
    /// gesture handling was written specifically to avoid. Same two actions,
    /// same two-step confirmation for Delete, only a bottom action sheet
    /// instead of the native popup.
    @State private var actionMenuFor: StoredCredential?
    @State private var pendingDeleteFor: StoredCredential?

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(L10n.string("nav.credentials"))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button(action: { viewModel.openAddCredential() }) {
                            Image(systemName: "plus")
                        }
                    }
                }
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(L10n.string("credentials.welcome", viewModel.displayName ?? L10n.string("credentials.unknownUser")))
                .font(.title2)
                .fontWeight(.semibold)
                .padding(.horizontal, 16)

            Text(credentialCountText)
                .font(.subheadline)
                .foregroundColor(SirosTheme.onSurfaceVariant)
                .padding(.horizontal, 16)

            Spacer().frame(height: 16)

            let entries = grouped
            if entries.isEmpty {
                emptyState
                Spacer()
            } else {
                // A partially-overlapping, interactive deck instead of a
                // plain scrolling list - see `CredentialStack.swift`'s doc
                // comment. It owns its own scrolling (a card's drag and a
                // plain vertical scroll are the same gesture, so it has to
                // arbitrate between them itself) and its own reorder state,
                // so there's nothing further to wrap it in here.
                CredentialStack(
                    entries: entries,
                    onCredentialClick: { viewModel.openCredentialDetail($0) },
                    onCredentialLongClick: { actionMenuFor = $0 },
                    onRenewCredential: { viewModel.renewCredential($0) }
                )
                .padding(.horizontal, 16)
            }
        }
        .padding(.top, 12)
        .confirmationDialog(
            actionMenuFor.map { $0.metadata?.name ?? $0.format } ?? "",
            isPresented: Binding(
                get: { actionMenuFor != nil },
                set: { if !$0 { actionMenuFor = nil } }
            ),
            titleVisibility: .visible,
            presenting: actionMenuFor
        ) { credential in
            Button(L10n.string("credentials.renew")) {
                viewModel.renewCredential(credential)
                actionMenuFor = nil
            }
            Button(L10n.string("common.delete"), role: .destructive) {
                pendingDeleteFor = credential
                actionMenuFor = nil
            }
            Button(L10n.string("common.cancel"), role: .cancel) {
                actionMenuFor = nil
            }
        }
        .confirmationDialog(
            L10n.string("credentials.deleteConfirmTitle"),
            isPresented: Binding(
                get: { pendingDeleteFor != nil },
                set: { if !$0 { pendingDeleteFor = nil } }
            ),
            titleVisibility: .visible,
            presenting: pendingDeleteFor
        ) { credential in
            Button(L10n.string("common.delete"), role: .destructive) {
                viewModel.deleteCredential(credential.id)
                pendingDeleteFor = nil
            }
            Button(L10n.string("common.cancel"), role: .cancel) {
                pendingDeleteFor = nil
            }
        } message: { credential in
            Text(L10n.string("credentials.deleteConfirmMessage", credential.metadata?.name ?? credential.format))
        }
    }

    private var credentialCountText: String {
        let count = grouped.count
        switch count {
        case 0: return L10n.string("credentials.countZero")
        case 1: return L10n.string("credentials.countOne")
        default: return L10n.string("credentials.countOther", count)
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "plus.circle.fill")
                .font(.system(size: 48))
                .foregroundColor(SirosTheme.brand)
            Text(L10n.string("credentials.emptyTitle"))
                .font(.headline)
                .fontWeight(.medium)
            Text(L10n.string("credentials.emptySubtitle"))
                .font(.subheadline)
                .foregroundColor(SirosTheme.onSurfaceVariant)
                .multilineTextAlignment(.center)
            Spacer()
        }
        .frame(maxWidth: .infinity)
        .padding(32)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(SirosTheme.surfaceVariant)
        )
        .padding(.horizontal, 16)
        .onTapGesture {
            viewModel.openAddCredential()
        }
    }
}
