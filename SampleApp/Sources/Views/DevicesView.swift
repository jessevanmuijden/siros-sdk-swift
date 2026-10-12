// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosAuth
import SirosCredentials

/// Settings → Devices: the wallet instances this user has in this tenant
/// (SID-AUTH-06, go-wallet-backend#319), and the one thing a user can do about
/// them: delete the account.
///
/// A thin consumer, deliberately: the step-up, the backend outcomes and the
/// local wipe all live in `SirosWallet.deleteAccount`. This view only renders
/// what `listWalletInstances()` returned and collects the typed confirmation.
struct DevicesView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showDeleteSheet = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    if viewModel.walletInstances.isEmpty {
                        Text(viewModel.devicesLoading
                            ? L10n.string("devices.loading")
                            : L10n.string("devices.empty"))
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    } else {
                        ForEach(viewModel.walletInstances, id: \.id) { instance in
                            DeviceRow(instance: instance)
                        }
                    }
                } header: {
                    Text(L10n.string("devices.title"))
                } footer: {
                    Text(L10n.string("devices.description"))
                }

                if let error = viewModel.devicesError {
                    Section {
                        Text(error).font(.subheadline).foregroundStyle(.red)
                    }
                }

                Section {
                    Button(role: .destructive, action: { showDeleteSheet = true }) {
                        Text(L10n.string("devices.deleteButton"))
                    }
                    .disabled(viewModel.deletingAccount)
                } header: {
                    Text(L10n.string("devices.deleteTitle"))
                } footer: {
                    Text(L10n.string("devices.deleteDescription"))
                }
            }
            .navigationTitle(L10n.string("devices.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(action: { viewModel.closeDevices() }) {
                        Image(systemName: "chevron.left")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button(action: { viewModel.refreshDevices() }) {
                        Image(systemName: "arrow.clockwise")
                    }
                    .disabled(viewModel.devicesLoading)
                }
            }
            .onAppear { viewModel.refreshDevices() }
            .sheet(isPresented: $showDeleteSheet) {
                DeleteAccountSheet()
            }
        }
    }
}

private struct DeviceRow: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let instance: WalletInstance

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(instance.deviceLabel).font(.body).fontWeight(.semibold)
                Spacer()
                StatusPill(status: instance.status)
            }
            if instance.isThisDevice {
                Text(L10n.string("devices.thisDevice"))
                    .font(.caption)
                    .foregroundStyle(Color.accentColor)
            }
            LabeledContent(L10n.string("devices.instanceId"), value: instance.id)
                .font(.caption)
            if !instance.wscdType.isEmpty {
                LabeledContent(L10n.string("devices.wscdType"), value: instance.wscdType).font(.caption)
            }
            if let lastAttested = instance.lastAttestedAt, !lastAttested.isEmpty {
                LabeledContent(L10n.string("devices.lastAttested"), value: lastAttested).font(.caption)
            }
            if let reason = instance.statusReason, !reason.isEmpty {
                LabeledContent(L10n.string("devices.statusReason"), value: reason).font(.caption)
            }
        }
        .padding(.vertical, 4)
    }
}

/// The typed confirmation for deleting the account. The SDK asks for the
/// passkey assertion once this is confirmed.
private struct DeleteAccountSheet: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var typed = ""

    private var confirmWord: String { "DELETE" }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(L10n.string("devices.deleteConfirmMessage", confirmWord))
                        .font(.subheadline)
                    TextField(confirmWord, text: $typed)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.characters)
                }
                if let error = viewModel.deleteAccountError {
                    Section {
                        Text(error).font(.subheadline).foregroundStyle(.red)
                    }
                }
                Section {
                    Button(role: .destructive) {
                        viewModel.deleteAccount(confirmation: typed)
                    } label: {
                        Text(L10n.string("devices.deleteButton"))
                    }
                    // The SDK requires the exact word; the button says so
                    // before the passkey prompt rather than after.
                    .disabled(typed != confirmWord || viewModel.deletingAccount)
                }
            }
            .navigationTitle(L10n.string("devices.deleteConfirmTitle"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("devices.cancel")) { dismiss() }
                }
            }
        }
    }
}

private struct StatusPill: View {
    let status: WalletInstance.Status

    var body: some View {
        Text(label)
            .font(.caption)
            .padding(.horizontal, 10)
            .padding(.vertical, 2)
            .background(color.opacity(0.12), in: Capsule())
            .foregroundStyle(color)
    }

    private var label: String {
        switch status {
        case .active: return L10n.string("devices.statusActive")
        case .suspended: return L10n.string("devices.statusSuspended")
        case .revoked: return L10n.string("devices.statusRevoked")
        }
    }

    private var color: Color {
        switch status {
        case .active: return .accentColor
        case .suspended: return .orange
        case .revoked: return .red
        }
    }
}

private extension WalletInstance {
    /// Something short enough to name a device in a confirmation dialog. The
    /// backend has no display name for an instance - the id is a JWK
    /// thumbprint - so this is the key storage type when there is one, plus a
    /// truncated id.
    var deviceLabel: String {
        let head = String(id.prefix(10))
        return wscdType.isEmpty ? "\(head)…" : "\(wscdType) · \(head)…"
    }
}

/// The screen for `WalletState.lifecycleBlocked`: the backend refuses this
/// installation and no amount of retrying the same login changes that until
/// someone else acts. A suspended instance can be reactivated from another
/// device, so the offer is to try again later; a revoked instance ends this
/// device only, and a deactivated wallet ends everything - both need a new
/// enrollment, but only the second means the user's other devices are gone
/// too, so they get their own wording.
struct WalletBlockedView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let reason: SirosError.WalletLifecycleRefusal
    let message: String?

    private var suspended: Bool { reason == .suspended }

    /// The `walletBlocked.*` key suffix for this refusal.
    private var key: String {
        switch reason {
        case .suspended: return "suspended"
        case .revoked: return "revoked"
        case .deactivated: return "deactivated"
        }
    }

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: suspended ? "pause.circle" : "xmark.octagon")
                .font(.system(size: 48))
                .foregroundStyle(suspended ? Color.orange : Color.red)
            Text(L10n.string("walletBlocked.\(key)Title"))
                .font(.title2)
                .fontWeight(.semibold)
                .multilineTextAlignment(.center)
            // The backend's own text when it sent one - it is written for the
            // user and may say more than the app can (who suspended it, why).
            Text(message ?? L10n.string("walletBlocked.\(key)Message"))
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                guard !viewModel.isLoading else { return }
                if suspended {
                    viewModel.login()
                } else {
                    // A revoked instance leaves the cached account in place
                    // (the user's other devices still work) and a deactivated
                    // wallet has already had it forgotten by the SDK; either
                    // way, disconnecting is what puts the app back on the
                    // login/register screen where enrollment starts.
                    viewModel.disconnect()
                }
            } label: {
                Text(L10n.string(suspended ? "walletBlocked.retry" : "walletBlocked.enrollAgain"))
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            // A login is already in flight; the single action here must not
            // start a second - two WebAuthn ceremonies would race.
            .disabled(viewModel.isLoading)
            .padding(.top, 8)
        }
        .padding(32)
    }
}
