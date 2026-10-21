// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet
import SirosCredentials

/// What a `RequestWscdChoice` prompt asks - fired only when more than one registered WSCD plugin
/// (`WalletConfig.availableKeystores`) meets a credential type's declared key-storage requirement and neither TOFU
/// nor `WalletConfig.defaultWscdMapping` resolved it automatically (see `WscdSelectionPolicy.resolve`).
struct WscdChoiceQuestion: Sendable {
    let issuer: String
    let credentialType: String
    let eligiblePluginIds: [String]
}

/// One in-flight prompt: the SDK's `ConsentPrompt` question (`Identifiable`, so it drives `.sheet(item:)`).
/// `answer(.chosen(...))` approves, `decline()` cancels.
typealias PendingWscdChoice = ConsentPrompt<WscdChoiceQuestion, WscdChoiceResult>.Pending

/// Sheet shown when `RequestWscdChoice` fires - a plain button-per-eligible-
/// plugin-ID chooser. Unlike `ProximityConsentSheet`, the SDK only asks
/// about eligible PLUGIN IDS here, not `KeystoreManager` instances or
/// credential families (`WalletConfig.availableKeystores` already holds the
/// concrete instances), so there's no credential preview to render - just
/// the choice itself.
struct WscdChoiceSheet: View {
    let choice: PendingWscdChoice

    /// Defaults to "Remember for this issuer" - the TOFU behavior this
    /// sheet always had before `WscdRememberScope` existed, so leaving the
    /// picker untouched keeps the same outcome as before this feature.
    @State private var rememberScope: WscdRememberScope = .thisIssuer

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 12) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 28))
                        .foregroundColor(SirosTheme.brand)
                    Text(L10n.string("wscdChoice.title"))
                        .font(.title2.bold())
                }

                Text(L10n.string("wscdChoice.description", choice.request.credentialType, choice.request.issuer))
                    .font(.body)
                    .foregroundColor(SirosTheme.onSurfaceVariant)

                VStack(spacing: 8) {
                    ForEach(choice.request.eligiblePluginIds, id: \.self) { pluginId in
                        Button(action: { choice.answer(.chosen(pluginId: pluginId, rememberScope: rememberScope)) }) {
                            HStack {
                                Text(pluginId)
                                    .font(.body.weight(.medium))
                                Spacer()
                                Image(systemName: "chevron.right")
                                    .font(.caption)
                                    .foregroundColor(SirosTheme.onSurfaceVariant)
                            }
                            .padding(.horizontal, 16)
                            .padding(.vertical, 12)
                            .background(
                                RoundedRectangle(cornerRadius: 10)
                                    .fill(SirosTheme.surfaceVariant)
                            )
                        }
                        .buttonStyle(.plain)
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text(L10n.string("wscdChoice.rememberLabel"))
                        .font(.caption)
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                    Picker(L10n.string("wscdChoice.rememberLabel"), selection: $rememberScope) {
                        Text(L10n.string("wscdChoice.rememberOnce")).tag(WscdRememberScope.once)
                        Text(L10n.string("wscdChoice.rememberThisIssuer")).tag(WscdRememberScope.thisIssuer)
                        Text(L10n.string("wscdChoice.rememberAlways")).tag(WscdRememberScope.allIssuers)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }

                Spacer()

                Button(action: { choice.decline() }) {
                    Text(L10n.string("common.cancel"))
                        .frame(maxWidth: .infinity)
                        .frame(height: 48)
                }
                .buttonStyle(.bordered)
                .tint(.red)
            }
            .padding()
            .navigationTitle(L10n.string("wscdChoice.navTitle"))
            .navigationBarTitleDisplayMode(.inline)
        }
        // The sheet going away (swiped, or replaced) cancels ITS OWN question only: the handle is a no-op once
        // answered, so an outgoing sheet can never cancel the question that replaced it.
        .onDisappear { choice.decline() }
    }
}
