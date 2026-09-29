// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet

struct ContentView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    /// Current transient toast, derived from `viewModel`'s error/info flags
    /// (see `syncBanner`). Held as its own piece of state, rather than
    /// computed inline in `body`, so `BannerMessage.id` stays stable across
    /// re-renders while the same message is showing - `MessageBannerView`'s
    /// auto-dismiss countdown (keyed on that `id`) would otherwise restart
    /// on every unrelated body re-evaluation.
    @State private var banner: BannerMessage?
    /// Measured height of `MainTabView`'s bottom tab bar (0 on every other
    /// screen) - see `BottomBarHeightKey`. Lets the banner float above the
    /// tab bar instead of covering it.
    @State private var bottomBarHeight: CGFloat = 0

    var body: some View {
        Group {
            switch viewModel.walletState {
            case .disconnected, .connecting:
                LoginView()
            case .ready:
                if let flowType = viewModel.flowStarting {
                    FlowStartingView(flowType: flowType)
                } else if viewModel.pendingPresentation != nil {
                    PresentationConsentView()
                } else if let credential = viewModel.selectedCredential {
                    CredentialDetailView(credential: credential)
                } else if viewModel.showHistory {
                    PresentationHistoryView()
                } else if viewModel.showActivate {
                    switch viewModel.activateMode {
                    case .qr:
                        QRScannerView()
                    case .proximity:
                        ProximityEngagementScreen()
                    }
                } else if viewModel.showAddCredential {
                    AddCredentialView()
                } else if viewModel.showWscaDeveloper {
                    WscdSettingsView()
                } else if viewModel.showDevices {
                    DevicesView()
                } else {
                    MainTabView()
                }
            case .flowActive(let flowType, let status):
                FlowActiveView(flowType: flowType, status: status)
            case .lifecycleBlocked(let reason, let message):
                WalletBlockedView(reason: reason, message: message)
            case .error(let message):
                ErrorView(message: message)
            }
        }
        // Non-blocking dismissable banner, replacing the blocking `.alert()`
        // this used to show for errorMessage/infoMessage - see
        // `MessageBanner.swift`'s doc comment (mirrors siros-sdk-kotlin
        // PR #106's identical fix).
        //
        // `.onAppear` covers the case where `viewModel` already has an
        // error/info message set the first time `ContentView` renders (e.g.
        // one raised during startup before this view existed) - `.onChange`
        // alone only fires on a SUBSEQUENT change, so without this the old
        // `.alert(isPresented:)`'s "presents immediately" behavior would be
        // lost for that one case.
        .onAppear { syncBanner() }
        .onChange(of: viewModel.showError) { syncBanner() }
        .onChange(of: viewModel.showInfo) { syncBanner() }
        .onChange(of: viewModel.errorMessage) { syncBanner() }
        .onChange(of: viewModel.infoMessage) { syncBanner() }
        .onPreferenceChange(BottomBarHeightKey.self) { bottomBarHeight = $0 }
        .messageBanner(banner, bottomInset: bottomBarHeight) {
            dismissBanner()
        }
        // Attached at this top level (not inside a specific screen) since a
        // `RequestWscdChoice` prompt can fire during credential issuance
        // regardless of which screen happens to be showing underneath -
        // mirrors how the error/info alerts above are handled globally.
        .sheet(item: $viewModel.pendingWscdChoice, onDismiss: {
            // Covers the sheet being dismissed WITHOUT the user tapping a
            // plugin or Cancel (e.g. swiping it away) - see
            // `WalletViewModel.dismissWscdChoice`'s doc comment, mirroring
            // `ProximityEngagementScreen`'s identical `onDismiss` handling.
            viewModel.dismissWscdChoice()
        }) { choice in
            WscdChoiceSheet(choice: choice)
        }
        // Same top-level rationale as `pendingWscdChoice` above - a FIDO2
        // ClientPin prompt (see `SampleAppAuthProvider.requestPin`) can fire
        // during any signing operation regardless of which screen is
        // showing underneath.
        .sheet(item: $viewModel.pendingFido2PinEntry, onDismiss: {
            viewModel.dismissFido2PinEntry()
        }) { pending in
            Fido2PinEntryView(pending: pending)
        }
        // Same top-level rationale as `pendingWscdChoice`/`pendingFido2PinEntry`
        // above - offered once right after a successful login, regardless of
        // which screen is showing underneath (mirrors the Kotlin sample
        // app's AutoEnrollOfferDialog).
        .alert(
            "Use this security key for signing?",
            isPresented: Binding(
                get: { viewModel.pendingAutoEnrollOffer != nil },
                set: { isPresented in
                    if !isPresented { viewModel.respondToAutoEnrollOffer(accept: false) }
                }
            )
        ) {
            Button("Enable") { viewModel.respondToAutoEnrollOffer(accept: true) }
            Button("Not now", role: .cancel) { viewModel.respondToAutoEnrollOffer(accept: false) }
        } message: {
            Text("The security key you just used to log in may also support signing credentials directly, instead of relying on a software key. Set it up now?")
        }
    }

    // MARK: - Banner state

    /// Recomputes `banner` from `viewModel`'s current error/info flags.
    /// Error takes priority when (unusually) both are set at once - matches
    /// the old `.alert()`'s behavior, since only one `Bool` binding could
    /// ever be presenting at a time there too.
    private func syncBanner() {
        if viewModel.showError, let message = viewModel.errorMessage {
            banner = BannerMessage(kind: .error, text: message)
        } else if viewModel.showInfo, let message = viewModel.infoMessage {
            banner = BannerMessage(kind: .info, text: message)
        } else {
            banner = nil
        }
    }

    /// Clears both the banner itself and whichever of
    /// `viewModel`'s error/info flags is currently driving it - called from
    /// the banner's explicit dismiss (X) button as well as its auto-dismiss
    /// timeout, so either path leaves `viewModel` in a consistent
    /// "acknowledged" state, not just this view's local `banner`.
    private func dismissBanner() {
        guard let banner else { return }
        switch banner.kind {
        case .error: viewModel.clearError()
        case .info: viewModel.clearInfo()
        }
        self.banner = nil
    }
}

// MARK: - Flow Starting View

/// Interstitial shown the instant a QR-scanned (or pasted/deep-linked)
/// offer/request URI is handed off to the SDK's issuance/presentation start
/// call, and cleared the moment the engine's first real flow-progress state
/// arrives (see `WalletViewModel.flowStarting`). Covers the network-bound gap
/// (VCTM fetch, issuer metadata, client attestation) before `FlowActiveView`
/// below has anything to show - without it, a slow issuer left the screen
/// looking unchanged long enough that a user could reasonably conclude the
/// scan hadn't registered.
struct FlowStartingView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let flowType: String

    private var messageKey: String {
        flowType == "presentation" ? "flow.starting.presentation" : "flow.starting.issuance"
    }

    var body: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)
                .tint(SirosTheme.brand)
            Text(L10n.string(messageKey))
                .font(.body)
                .foregroundColor(SirosTheme.onSurfaceVariant)
            Button(L10n.string("flow.cancelButton")) {
                viewModel.cancelFlowStarting()
            }
            .buttonStyle(.bordered)
            .tint(SirosTheme.brand)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(SirosTheme.background)
    }
}

// MARK: - Flow Active View

struct FlowActiveView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let flowType: String
    let status: String

    // Guard against a visible backward jump: real execution order can
    // deviate slightly from the canonical step list (e.g. a step retried
    // after a transient error), but the bar should never un-progress.
    @State private var maxProgress: Double = 0

    private var stepProgress: Double? { flowStepProgress(flowType: flowType, step: status) }

    var body: some View {
        VStack(spacing: 16) {
            if let stepProgress {
                ProgressView(value: maxProgress)
                    .tint(SirosTheme.brand)
                    .onAppear { maxProgress = max(maxProgress, stepProgress) }
                    .onChange(of: stepProgress) { _, newValue in
                        maxProgress = max(maxProgress, newValue)
                    }
            } else {
                ProgressView()
                    .scaleEffect(1.5)
                    .tint(SirosTheme.brand)
            }
            Text(flowStepLabel(status))
                .font(.body)
                .foregroundColor(SirosTheme.onSurfaceVariant)
            if viewModel.showDiagnosticMessages {
                Text(L10n.string("flow.diagnosticLabel", status))
                    .font(.caption)
                    .foregroundColor(SirosTheme.onSurfaceVariant.opacity(0.7))
            }
            Button(L10n.string("flow.cancelButton")) {
                viewModel.cancelCurrentFlow()
            }
            .buttonStyle(.bordered)
            .tint(SirosTheme.brand)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(SirosTheme.background)
    }
}

// MARK: - Error View

struct ErrorView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundColor(SirosTheme.error)
            Text(L10n.string("error.title"))
                .font(.title2.bold())
            Text(message)
                .font(.body)
                .foregroundColor(SirosTheme.onSurfaceVariant)
                .multilineTextAlignment(.center)
            Button(L10n.string("error.retryButton")) {
                viewModel.disconnect()
            }
            .buttonStyle(.borderedProminent)
            .tint(SirosTheme.brand)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(SirosTheme.background)
    }
}

// MARK: - Main Tab View

struct MainTabView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            // Top bar matching Android
            HStack {
                SirosMarkView()
                    .frame(width: 28, height: 28)
                Spacer().frame(width: 10)
                Text(L10n.string("app.name"))
                    .font(.headline)
                    .fontWeight(.semibold)
                Spacer()
                Button(action: {
                    viewModel.activateMode = .proximity
                    viewModel.showActivate = true
                }) {
                    Image(systemName: "wave.3.right")
                        .font(.title3)
                        .foregroundColor(SirosTheme.onSurface)
                }
                Button(action: { viewModel.openActivate() }) {
                    Image(systemName: "qrcode.viewfinder")
                        .font(.title3)
                        .foregroundColor(SirosTheme.onSurface)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(SirosTheme.surface)

            Divider()

            // Content area
            Group {
                switch selectedTab {
                case 0:
                    CredentialsView()
                case 2:
                    SettingsView()
                default:
                    EmptyView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()

            // Bottom tab bar matching Android
            HStack {
                tabButton(
                    icon: "wallet.pass",
                    label: L10n.string("nav.credentials"),
                    tag: 0
                )
                Spacer()
                tabButton(
                    icon: "plus",
                    label: L10n.string("nav.add"),
                    tag: 1,
                    action: {
                        selectedTab = 1
                        viewModel.openAddCredential()
                    }
                )
                Spacer()
                tabButton(
                    icon: "gear",
                    label: L10n.string("nav.settings"),
                    tag: 2
                )
            }
            .padding(.horizontal, 32)
            .padding(.vertical, 8)
            .background(SirosTheme.surfaceVariant)
            // Reports this bar's real height (see `BottomBarHeightKey`) so
            // ContentView's message banner can float above it instead of
            // covering it - only present while MainTabView (i.e. this bar)
            // is actually on screen.
            .background(
                GeometryReader { proxy in
                    Color.clear.preference(key: BottomBarHeightKey.self, value: proxy.size.height)
                }
            )
        }
        .background(SirosTheme.background)
    }

    @ViewBuilder
    private func tabButton(icon: String, label: String, tag: Int, action: (() -> Void)? = nil) -> some View {
        let isSelected = selectedTab == tag
        Button(action: {
            if let action {
                action()
            } else {
                selectedTab = tag
            }
        }) {
            VStack(spacing: 2) {
                Image(systemName: icon)
                    .font(.system(size: 20))
                Text(label)
                    .font(.caption2)
            }
            .foregroundColor(isSelected ? SirosTheme.brand : SirosTheme.onSurfaceVariant)
        }
        .buttonStyle(.plain)
    }
}
