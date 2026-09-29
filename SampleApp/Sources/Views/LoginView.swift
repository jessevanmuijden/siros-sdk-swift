// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI

struct LoginView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var showRegister = false
    @State private var showOtherLogin = false
    @State private var registerName = ""
    @State private var showBackendInfo = false
    @State private var showSettingsSheet = false

    /// Whether pre-login settings are available. Set via build config.
    var showPreLoginSettings: Bool = true

    var body: some View {
        ZStack(alignment: .topTrailing) {
            // Settings gear icon
            if showPreLoginSettings {
                Button(action: { showSettingsSheet = true }) {
                    Image(systemName: "gearshape")
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                        .padding(16)
                }
                .zIndex(1)
            }

        ScrollView {
            VStack(spacing: 16) {
                Spacer().frame(height: 24)

                // Logo — matches Android ic_siros_mark
                SirosMarkView()
                    .frame(width: 56, height: 56)

                Spacer().frame(height: 8)

                Text(L10n.string("login.title"))
                    .font(.title)
                    .fontWeight(.bold)

                // Info toggle — matches Android: tap to reveal backend URL
                Button(action: { showBackendInfo.toggle() }) {
                    HStack(spacing: 4) {
                        Image(systemName: "info.circle")
                            .font(.caption2)
                        Text(showBackendInfo ? viewModel.backendUrl : L10n.string("app.tagline"))
                            .font(.caption)
                    }
                    .foregroundColor(SirosTheme.onSurfaceVariant)
                }
                .buttonStyle(.plain)

                Spacer().frame(height: 20)

                VStack(spacing: 12) {
                    if showBackendInfo {
                        TextField(L10n.string("settings.backendUrl"), text: $viewModel.backendUrl)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .disabled(viewModel.isLoading)

                        TextField(L10n.string("settings.tenantId"), text: $viewModel.tenantId)
                            .textFieldStyle(.roundedBorder)
                            .autocorrectionDisabled()
                            .textInputAutocapitalization(.never)
                            .disabled(viewModel.isLoading)
                    }

                    loginContent
                }
                .padding(20)
                .background(
                    RoundedRectangle(cornerRadius: 16)
                        .fill(SirosTheme.surface)
                        .shadow(color: .black.opacity(0.05), radius: 2, y: 1)
                )
            }
            .padding(.horizontal, 32)
        }
        .background(SirosTheme.background)
        }
        .sheet(isPresented: $showSettingsSheet) {
            PreLoginSettingsView()
                .environmentObject(viewModel)
        }
    }

    @ViewBuilder
    private var loginContent: some View {
        if showRegister {
            // Mode C: Registration
            Text(L10n.string("login.createAccount"))
                .font(.headline)
                .fontWeight(.semibold)

            TextField(L10n.string("login.displayNameLabel"), text: $registerName)
                .textFieldStyle(.roundedBorder)
                .autocorrectionDisabled()
                .disabled(viewModel.isLoading)

            Text(L10n.string("login.displayNameCount", registerName.utf8.count))
                .font(.caption)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .trailing)

            Button(action: {
                viewModel.register(displayName: registerName)
            }) {
                HStack {
                    if viewModel.isLoading {
                        ProgressView()
                            .tint(.white)
                    }
                    Text(L10n.string("login.signUpButton"))
                }
                .frame(maxWidth: .infinity)
                .frame(height: 48)
            }
            .buttonStyle(.borderedProminent)
            .tint(SirosTheme.brand)
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .disabled(viewModel.isLoading || registerName.isEmpty || registerName.utf8.count > 64)

            Button(L10n.string("login.alreadyHaveAccount")) {
                showRegister = false
            }
            .font(.subheadline)

        } else if !viewModel.cachedAccounts.isEmpty && !showOtherLogin {
            // Mode A: Cached accounts picker
            Text(L10n.string("login.welcomeBack"))
                .font(.headline)
                .fontWeight(.semibold)

            ForEach(viewModel.cachedAccounts, id: \.accountId) { account in
                HStack(spacing: 8) {
                    Button(action: {
                        viewModel.loginWithAccount(account)
                    }) {
                        HStack {
                            if viewModel.isLoading {
                                ProgressView()
                                    .tint(.white)
                            }
                            Text(account.displayName)
                                .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 48)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(SirosTheme.brand)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .disabled(viewModel.isLoading)

                    Button(action: {
                        viewModel.forgetAccount(account.accountId)
                    }) {
                        Image(systemName: "xmark")
                            .foregroundStyle(.secondary)
                    }
                    .buttonStyle(.borderless)
                }
            }

            Button(L10n.string("login.useOtherAccount")) {
                showOtherLogin = true
            }
            .font(.subheadline)

        } else {
            // Mode B: Generic passkey login
            Button(action: viewModel.login) {
                HStack {
                    if viewModel.isLoading {
                        ProgressView()
                            .tint(.white)
                    }
                    Text(L10n.string("login.signInButton"))
                }
                .frame(maxWidth: .infinity)
                .frame(height: 48)
            }
            .buttonStyle(.borderedProminent)
            .tint(SirosTheme.brand)
            .clipShape(RoundedRectangle(cornerRadius: 12))
            .disabled(viewModel.isLoading)

            Button(L10n.string("login.newHere")) {
                showRegister = true
            }
            .font(.subheadline)

            if !viewModel.cachedAccounts.isEmpty {
                Button(L10n.string("login.backToSavedAccounts")) {
                    showOtherLogin = false
                }
                .font(.subheadline)
            }
        }
    }
}

// MARK: - Pre-Login Settings Sheet

struct PreLoginSettingsView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @Environment(\.dismiss) private var dismiss
    /// Editable, newline-joined form of `viewModel.zkCircuitUrls` - SwiftUI
    /// has no stock list-of-strings editor, so a plain multi-line
    /// `TextEditor` stands in for one, one URL per line. Split back into
    /// the array (trimmed, blank lines dropped) on every edit.
    @State private var zkCircuitUrlsText: String = ""

    var body: some View {
        NavigationStack {
            Form {
                Section(L10n.string("settings.connectionSection")) {
                    TextField(L10n.string("settings.backendUrl"), text: $viewModel.backendUrl)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    TextField(L10n.string("settings.tenantId"), text: $viewModel.tenantId)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                }

                Section(L10n.string("settings.zkCircuitHostingSection")) {
                    Text(L10n.string("settings.zkCircuitHostingDescription"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                    TextEditor(text: $zkCircuitUrlsText)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .frame(minHeight: 80)
                        .onAppear { zkCircuitUrlsText = viewModel.zkCircuitUrls.joined(separator: "\n") }
                        .onChange(of: zkCircuitUrlsText) { _, newValue in
                            viewModel.zkCircuitUrls = newValue
                                .split(separator: "\n", omittingEmptySubsequences: false)
                                .map { $0.trimmingCharacters(in: .whitespaces) }
                                .filter { !$0.isEmpty }
                        }
                }

                Section(L10n.string("settings.transportProtocolSection")) {
                    Toggle(L10n.string("settings.wmpProtocolToggle"), isOn: $viewModel.useWmpProtocol)
                    Text(viewModel.useWmpProtocol ? L10n.string("settings.wmpProtocolOn") : L10n.string("settings.wmpProtocolOff"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                // RICAL reader-trust local fallback (Geneva 2026 interop
                // event) - off by default: the remote go-trust `mdocrical`
                // AuthZEN call is preferred since only it honors RICAL's
                // temporary/dynamic trust roots. See
                // WalletConfig.preferLocalReaderTrustEvaluation.
                Section("Reader Trust (RICAL)") {
                    Toggle("Evaluate reader trust locally", isOn: $viewModel.preferLocalReaderTrustEvaluation)
                    Text("Skip the remote RICAL trust check and validate proximity readers only against the root certificate below.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                    TextField("RICAL root certificate (PEM)", text: $viewModel.readerTrustRootCertificatePem, axis: .vertical)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                        .lineLimit(3...6)
                }

                Section(L10n.string("common.developer")) {
                    Toggle(L10n.string("settings.credentialDetailsToggle"), isOn: $viewModel.showCredentialDetails)
                    Text(L10n.string("settings.credentialDetailsDescription"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                    Toggle(L10n.string("settings.diagnosticMessagesToggle"), isOn: $viewModel.showDiagnosticMessages)
                    Text(L10n.string("settings.diagnosticMessagesDescription"))
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
            }
            .navigationTitle(L10n.string("settings.connectionSettingsTitle"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.string("common.done")) { dismiss() }
                }
            }
        }
    }
}

// MARK: - SIROS Mark (brand logo)

/// SwiftUI rendering of the SIROS mark (ic_siros_mark).
/// Uses the same path data as the Android vector drawable.
struct SirosMarkView: View {
    /// Diameter of the mark's circle - the inner glyph scales with it so the
    /// mark still looks right whether it's a 28pt top-bar accent or a much
    /// larger Home-screen logo.
    var size: CGFloat = 56

    var body: some View {
        ZStack {
            // Navy background circle
            Circle()
                .fill(SirosTheme.brand)

            // Simplified SIROS star/compass mark in white
            Image(systemName: "sparkle")
                .font(.system(size: size * 0.43, weight: .bold))
                .foregroundColor(.white)
        }
    }
}
