// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials

struct SettingsView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showDeleteConfirm = false

    var body: some View {
        NavigationStack {
            List {
                // Account section
                Section("Account") {
                    LabeledContent("Signed in as", value: viewModel.displayName ?? viewModel.userId ?? "—")
                    LabeledContent("Backend", value: viewModel.backendUrl)
                    LabeledContent("Tenant", value: viewModel.tenantId)
                    LabeledContent("ZK Circuit Hosting", value: viewModel.zkCircuitUrls.joined(separator: ", "))
                    LabeledContent("Credentials", value: "\(viewModel.credentials.count)")
                    LabeledContent("Transport", value: viewModel.useWmpProtocol ? "WMP (JSON-RPC 2.0)" : "Legacy")
                    // Which interoperability profiles this wallet can speak.
                    // Deliberately a fact, not a control: which one is used is
                    // negotiated per issuer from its advertised
                    // `cryptographic_binding_methods_supported`, so there is
                    // nothing here for a user to choose (and no way they could
                    // reasonably know the answer for an issuer they just
                    // scanned).
                    LabeledContent(
                        L10n.string("settings.interopProfiles"),
                        value: "HAIP \u{00b7} DIIP \(viewModel.diipProfile.version.uppercased())"
                    )
                }

                // Credential consumption policy section
                Section {
                    Picker(selection: $viewModel.credentialConsumptionPolicy) {
                        ForEach(CredentialConsumptionPolicy.allCases, id: \.self) { policy in
                            Text(policy.localizedLabel).tag(policy)
                        }
                    } label: {
                        EmptyView()
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                } header: {
                    Text(L10n.string("settings.credentialConsumptionTitle"))
                } footer: {
                    Text(L10n.string("settings.credentialConsumptionDescription"))
                }

                // WSCD (security key/keystore) settings - a single entry
                // point into the consolidated `WscdSettingsView`, which now
                // owns everything that used to be spread across four
                // separate sections here (Security Key Choices/TOFU,
                // Preferred Security Key, Per-Issuer Overrides, WSCD
                // Lifecycle/Enroll) plus the old standalone "WSCA Developer"
                // screen - see `WscdSettingsView.swift`'s doc comment for the
                // full consolidation. Enroll/Rotate/Destroy/Refresh live in
                // that screen's collapsible Developer section, since they're
                // diagnostic/test actions, not something an end user taps
                // routinely.
                Section {
                    Button(action: { viewModel.openWscaDeveloper() }) {
                        Label("WSCD Settings", systemImage: "key")
                    }
                } header: {
                    Text("Security Key (WSCD)")
                } footer: {
                    Text("Which secure key storage (software, R2PS remote HSM, or a FIDO2 security key) backs each credential, plus enrollment and developer diagnostics.")
                }

                // Devices (wallet instances, SID-AUTH-06) - one entry point
                // into `DevicesView`, which owns the list and the two
                // actions; this section stays a link, like the WSCD one above.
                Section {
                    Button(action: { viewModel.openDevices() }) {
                        Label(L10n.string("devices.manageButton"), systemImage: "iphone")
                    }
                } header: {
                    Text(L10n.string("devices.title"))
                } footer: {
                    Text(L10n.string("devices.description"))
                }

                // Passkeys section
                Section("Passkeys") {
                    if viewModel.passkeys.isEmpty {
                        Text("No passkeys registered")
                            .foregroundStyle(.secondary)
                            .font(.subheadline)
                    } else {
                        ForEach(viewModel.passkeys, id: \.credentialId) { passkey in
                            PasskeyRow(
                                passkey: passkey,
                                onRename: { nickname in
                                    viewModel.renamePasskey(credentialId: passkey.credentialId, nickname: nickname)
                                }
                            )
                        }
                    }
                }

                // Other accounts
                if viewModel.cachedAccounts.count > 1 {
                    Section("Other Accounts") {
                        let otherAccounts = viewModel.cachedAccounts.filter {
                            $0.accountId != "\(viewModel.tenantId):\(viewModel.userId ?? "")"
                        }
                        ForEach(otherAccounts, id: \.accountId) { account in
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(account.displayName)
                                    Text(account.tenantId)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button(action: {
                                    viewModel.forgetAccount(account.accountId)
                                }) {
                                    Image(systemName: "xmark")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.borderless)
                            }
                        }
                    }
                }

                // EC TS12 payment SCA: the runtime switch and the log.
                Section {
                    Toggle(L10n.string("settings.transactionDataToggle"), isOn: $viewModel.transactionDataEnabled)
                    Button(action: { viewModel.openTransactionLog() }) {
                        Label(L10n.string("settings.transactionLogButton"), systemImage: "list.bullet.rectangle")
                    }
                } footer: {
                    Text(L10n.string("settings.transactionDataDescription"))
                }

                // Activity
                Section("Activity") {
                    Button(action: { viewModel.openHistory() }) {
                        HStack {
                            Label("Presentation History", systemImage: "clock")
                            Spacer()
                            Text("\(viewModel.presentationHistory.count)")
                                .foregroundStyle(.secondary)
                        }
                    }
                }

                // Disconnect
                Section {
                    Button(role: .destructive, action: { viewModel.disconnect() }) {
                        Label("Disconnect", systemImage: "rectangle.portrait.and.arrow.right")
                    }

                    Button(role: .destructive, action: { showDeleteConfirm = true }) {
                        Label("Delete Account", systemImage: "trash")
                    }
                    .alert("Delete Account?", isPresented: $showDeleteConfirm) {
                        Button("Delete", role: .destructive) {
                            viewModel.disconnect()
                        }
                        Button("Cancel", role: .cancel) {}
                    } message: {
                        Text("This will remove all local data, credentials, and passkeys. This cannot be undone.")
                    }
                }
            }
            .navigationTitle("Settings")
            .navigationBarTitleDisplayMode(.inline)
            .onAppear {
                viewModel.listPasskeysForUI()
            }
        }
    }
}

// MARK: - Passkey Row with inline rename

struct PasskeyRow: View {
    let passkey: CachedPasskey
    let onRename: (String) -> Void

    @State private var editing = false
    @State private var nickname: String

    init(passkey: CachedPasskey, onRename: @escaping (String) -> Void) {
        self.passkey = passkey
        self.onRename = onRename
        _nickname = State(initialValue: passkey.nickname)
    }

    var body: some View {
        if editing {
            HStack {
                TextField("Nickname", text: $nickname)
                    .textFieldStyle(.roundedBorder)
                Button(action: {
                    onRename(nickname)
                    editing = false
                }) {
                    Image(systemName: "checkmark")
                }
                .buttonStyle(.borderless)
                Button(action: {
                    nickname = passkey.nickname
                    editing = false
                }) {
                    Image(systemName: "xmark")
                }
                .buttonStyle(.borderless)
            }
        } else {
            HStack {
                VStack(alignment: .leading) {
                    Text(passkey.nickname.isEmpty ? "Passkey \(passkey.credentialId.prefix(8))..." : passkey.nickname)
                        .font(.body)
                    Text("ID: \(passkey.credentialId.prefix(16))...")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button(action: { editing = true }) {
                    Image(systemName: "pencil")
                        .font(.caption)
                }
                .buttonStyle(.borderless)
            }
        }
    }
}

// Re-export for use in views
import SirosWallet

/// Localized display label for a `CredentialConsumptionPolicy` value.
extension CredentialConsumptionPolicy {
    var localizedLabel: String {
        switch self {
        case .consumeAll: return L10n.string("settings.credentialConsumptionConsumeAll")
        case .consumeNonZkp: return L10n.string("settings.credentialConsumptionConsumeNonZkp")
        case .neverConsume: return L10n.string("settings.credentialConsumptionNeverConsume")
        }
    }
}
