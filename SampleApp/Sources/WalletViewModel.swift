// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import CryptoKit
import Foundation
import SwiftUI
import SirosWallet
import SirosCredentials
import SirosAuth
import SirosKeystore
#if canImport(siros_wscd_managerFFI)
import siros_wscd_managerFFI
#endif

#if DEBUG
private let defaultBackendUrl = "http://192.168.240.1:8090"
#else
private let defaultBackendUrl = "https://wallet.sirosid.dev"
#endif

private let defaultTenantId = "default"
private let defaultR2psUrl = "http://192.168.240.1:9000"
private let redirectScheme = "siros-sample"

/// OID4VCI `credential_configuration_id` for the SIROS ID credential (see
/// vc-issuer's config: `credential_configurations.siros_id`) - used to hide
/// the plain issuer offer from `openAddCredential()`'s list in favor of the
/// "Scan Physical ID card" / IDV row, which is the one path meant to
/// actually issue this credential.
private let sirosIdCredentialConfigurationId = "siros_id"

/// Sample app ViewModel.
///
/// The entire wallet lifecycle — auth, key management, engine protocol,
/// credential storage — is handled by `SirosWallet`. This ViewModel only
/// needs to expose UI-level state and forward user actions.
@MainActor
final class WalletViewModel: ObservableObject {

    // MARK: - Configuration

    @Published var backendUrl: String {
        didSet { UserDefaults.standard.set(backendUrl, forKey: "siros_backend_url") }
    }
    @Published var tenantId: String {
        didSet { UserDefaults.standard.set(tenantId, forKey: "siros_tenant_id") }
    }

    /// Ordered list of go-zk-circuits `/v1` catalog hosting URLs (mirrors of
    /// the same catalog, tried in order - see `ZkCircuitClient`'s doc
    /// comment), mirroring `backendUrl`'s settings pattern. JSON-encoded
    /// into a single UserDefaults string, the same technique
    /// `wscdDefaultMapping` below uses for its `[String: String]`.
    @Published var zkCircuitUrls: [String] {
        didSet {
            guard let data = try? JSONEncoder().encode(zkCircuitUrls),
                  let json = String(data: data, encoding: .utf8) else { return }
            UserDefaults.standard.set(json, forKey: "siros_zk_circuit_urls_json")
        }
    }
    @Published var useWmpProtocol: Bool {
        didSet { UserDefaults.standard.set(useWmpProtocol, forKey: "siros_use_wmp_protocol") }
    }
    @Published var showCredentialDetails: Bool {
        didSet { UserDefaults.standard.set(showCredentialDetails, forKey: "siros_show_credential_details") }
    }
    /// Show the raw backend step token alongside the friendly progress label
    /// during a flow. Default false - opt-in debugging aid, not shown by
    /// default since it duplicates the localized label.
    @Published var showDiagnosticMessages: Bool {
        didSet { UserDefaults.standard.set(showDiagnosticMessages, forKey: "siros_show_diagnostic_messages") }
    }
    /// See `WalletConfig.preferLocalReaderTrustEvaluation`'s doc comment.
    @Published var preferLocalReaderTrustEvaluation: Bool {
        didSet { UserDefaults.standard.set(preferLocalReaderTrustEvaluation, forKey: "siros_prefer_local_reader_trust_evaluation") }
    }
    /// A single PEM-encoded RICAL root certificate for local reader-trust
    /// fallback (see `WalletConfig.readerTrustRootCertificatesPem`) - blank
    /// means none configured, matching that config field defaulting to an
    /// empty list.
    @Published var readerTrustRootCertificatePem: String {
        didSet { UserDefaults.standard.set(readerTrustRootCertificatePem, forKey: "siros_reader_trust_root_certificate_pem") }
    }
    @Published var r2psEnabled: Bool = false
    @Published var r2psServerUrl: String = defaultR2psUrl
    /// PEM-encoded P-256 R2PS SERVER public key, for the R2PS message
    /// envelope's JWE encryption (`R2psConfig.serverPublicKeyPem` - see its
    /// doc comment: this must be the server's key, never the client's own).
    /// No real R2PS dev server key is available to hardcode in this sample
    /// app's current dev configuration (unlike `r2psServerUrl`, there's no
    /// established dev endpoint here to fetch one from) - defaults to empty
    /// so `buildWscdSigner`'s R2PS registration fails loudly (caught,
    /// logged, and skipped - the existing best-effort path) instead of
    /// silently substituting the wrong key. A dev wiring up a real R2PS
    /// server should paste its actual public key here (or via the
    /// "R2PS Server Public Key" field in `WscdSettingsView`).
    @Published var r2psServerPublicKeyPem: String = ""
    /// Core wallet policy (not a UI-only preference like the toggles above) -
    /// persisted here, but enforced by `SirosWallet` itself (see
    /// `SirosWallet.credentialConsumptionPolicy`'s doc comment). Applied to
    /// `wallet` both immediately on change (`didSet`) and again whenever
    /// `rebuildWalletIfNeeded()` creates a fresh instance.
    @Published var credentialConsumptionPolicy: CredentialConsumptionPolicy {
        didSet {
            UserDefaults.standard.set(credentialConsumptionPolicy.rawValue, forKey: "siros_credential_consumption_policy")
            wallet?.credentialConsumptionPolicy = credentialConsumptionPolicy
        }
    }

    /// Dev/host-app config for `WscdSelectionPolicy`'s multi-plugin
    /// selection (`WalletConfig.availableKeystores`) - gated behind an
    /// explicit developer toggle (`WscdSettingsView`'s "WSCD Selection
    /// Policy" section) rather than always building a `KeystoreManager` for
    /// every known plugin ID: a plain single-plugin run only ever needs
    /// `selectedPluginId`'s one plugin, so constructing the others
    /// unconditionally would be pure overhead for a feature most runs never
    /// exercise. Requires a fresh `rebuildWalletIfNeeded()` to take effect
    /// (like `selectedPluginId`/`r2psServerUrl` above), so it's read-only
    /// dev config, not something toggled mid-session.
    @Published var wscdMultiPluginEnabled: Bool {
        didSet { UserDefaults.standard.set(wscdMultiPluginEnabled, forKey: "siros_wscd_multi_plugin_enabled") }
    }

    /// Host-app-supplied `WalletConfig.defaultWscdMapping` - dev config
    /// (`WscdSettingsView`'s "WSCD Selection Policy" section), not an
    /// end-user Settings toggle, since it's a shortcut for an integrator
    /// that already knows the right plugin for a given (issuer,
    /// credentialType) pair to skip the `RequestWscdChoice` prompt entirely
    /// - not a preference an end user would ever set for themselves. Keyed
    /// the same way the SDK does (`"\(issuer)|\(credentialType)"`, see
    /// `WscdSelectionPolicy.tofuKey`).
    @Published var wscdDefaultMapping: [String: String] {
        didSet {
            guard let data = try? JSONEncoder().encode(wscdDefaultMapping),
                  let json = String(data: data, encoding: .utf8) else { return }
            UserDefaults.standard.set(json, forKey: "siros_wscd_default_mapping_json")
        }
    }

    // MARK: - Wallet state

    @Published var walletState: WalletViewState = .disconnected
    @Published var credentials: [StoredCredential] = []
    @Published var displayName: String?
    @Published var userId: String?

    // MARK: - Multi-account

    @Published var cachedAccounts: [CachedAccount] = []

    // MARK: - Passkeys

    @Published var passkeys: [CachedPasskey] = []

    // MARK: - Navigation state

    /// Which of `MainTabView`'s three tabs is showing (0 = Credentials,
    /// 1 = Home, 2 = Settings). Lives here rather than as `MainTabView`'s own
    /// local `@State`: `ContentView.body`'s top-level switch structurally
    /// replaces `MainTabView` with a sibling screen (credential detail,
    /// history, Activate, ...) and back again, which destroys and recreates
    /// `MainTabView` - a local `@State` would silently reset to its default
    /// every time, so returning from a credential's detail screen would land
    /// back on Home instead of wherever the user actually was. Confirmed via
    /// a real on-device UI test failure
    /// (`CredentialStackInteractionUITests.testAShortDragSpringsBackWithoutReorderingTheDeck`),
    /// not just reasoned about - the same class of screen round-trip that
    /// test exercises.
    @Published var selectedTab = 1
    @Published var showAddCredential = false
    @Published var showHistory = false
    @Published var showWscaDeveloper = false
    @Published var showDevices = false
    /// Which mode the merged Activate screen (QR scan / proximity engagement)
    /// is showing - only meaningful while `showActivate` is true.
    enum ActivateMode { case qr, proximity }
    @Published var showActivate = false
    @Published var activateMode: ActivateMode = .qr
    @Published var selectedCredential: StoredCredential?
    @Published var pendingPresentation: PresentationRequest?
    /// Non-nil while a `RequestWscdChoice` prompt (see `requestWscdChoice`)
    /// is awaiting the user's answer - drives `WscdChoiceSheet` via
    /// `.sheet(item:)` in `ContentView`, mirroring `pendingPresentation`'s
    /// pattern above.
    @Published var pendingWscdChoice: PendingWscdChoice?
    /// Non-nil while a FIDO2 ClientPin prompt (see `SampleAppAuthProvider.requestPin`)
    /// is awaiting the user's PIN - drives `Fido2PinEntryView` via
    /// `.sheet(item:)` in `ContentView`, mirroring `pendingWscdChoice`'s
    /// pattern above.
    @Published var pendingFido2PinEntry: PendingFido2PinEntry?
    /// Which plugin ID (if any) is currently offering to auto-enroll after a
    /// successful login - see `maybeOfferWscdAutoEnroll()`. Drives a
    /// two-button `.alert` in `ContentView` (a plain confirm/decline, not
    /// `.sheet(item:)`, since there's no picker involved).
    @Published var pendingAutoEnrollOffer: String?

    /// Set the instant a QR-scanned (or pasted/deep-linked) offer/request URI
    /// is classified and handed off to the SDK's issuance/presentation start
    /// call - `"issuance"`, `"presentation"`, or `nil` when nothing is
    /// starting. Cleared the moment any real subsequent wallet state update
    /// arrives (`updateState` clears it unconditionally on every state, since
    /// `SirosWallet.setState` re-emits without a dedup check - see its doc
    /// comment), or immediately on a synchronous handoff failure.
    ///
    /// Covers the silent network-bound gap (VCTM fetch, issuer metadata,
    /// client attestation) between a successful scan and the engine's first
    /// real flow-progress state, which against a slow issuer is long enough
    /// that a user could reasonably conclude the scan didn't register. Pure
    /// sample-app UI state built entirely on the existing wallet-state
    /// stream - no SDK API involved.
    @Published var flowStarting: String?

    // MARK: - Add credential state

    @Published var availableCredentials: [CredentialOffer] = []
    @Published var isLoadingOffers = false

    // MARK: - Presentation history

    @Published var presentationHistory: [PresentationRecord] = []

    // MARK: - WSCD lifecycle

    @Published var selectedPluginId: String = "softkey"
    @Published var lifecycleState: LifecycleState?
    @Published var lifecycleStatus: LifecycleStatus?
    @Published var enrollmentInProgress = false
    @Published var wscdKeys: [SignerKeyInfo] = []
    /// Every registered WSCD plugin ID this session actually has a signer
    /// for (mirrors Kotlin's `_availableWscdPluginIds`), set from
    /// `rebuildWalletIfNeeded()`'s local `availableKeystores` dict. Used by
    /// `maybeOfferWscdAutoEnroll()` to check the hinted plugin is actually
    /// usable in this session before offering it.
    @Published var availableWscdPluginIds: [String] = []
    @Published var wscdKeySecurityProps: [String: SignerSecurityProperties] = [:]
    /// Snapshot of `SirosWallet.wscdTofuMapping`, refreshed on demand
    /// (`refreshWscdTofuMapping()`) - the SDK doesn't publish TOFU changes
    /// as wallet-state stream events (they're a side effect of credential
    /// issuance, not a first-class state transition), so this is an
    /// imperative refresh like `listPasskeysForUI()`/`wscdKeys` rather than
    /// always-live.
    @Published var wscdTofuMappingSnapshot: [String: String] = [:]
    /// Snapshot of `SirosWallet.wscdUserOverrides` - deliberate per-(issuer,
    /// credentialType) user preferences, distinct from the TOFU snapshot
    /// above (see `WscdRememberScope`'s doc comment). Refreshed the same
    /// imperative way.
    @Published var wscdUserOverridesSnapshot: [String: String] = [:]
    /// Snapshot of `SirosWallet.wscdGlobalOverride` - the single global user
    /// preference, or `nil` for "no preference."
    @Published var wscdGlobalOverrideSnapshot: String?

    // MARK: - TS11 registry discovery (best-effort, see WscdSettingsView.WscdMappingCard)

    /// Result of the last `discoverTs11Schemas()` call, for
    /// `WscdSettingsView`'s common (not per-plugin) "Discover from TS11
    /// Registry" action - mirrors Kotlin's `WalletViewModel.ts11DiscoveredCredentials`.
    /// Each entry has already been enriched with a real display identity by
    /// `Ts11CredentialDiscovery` - a raw registry entry only carries an
    /// opaque `Ts11SchemaMeta.id`, which is not something worth surfacing
    /// directly to the user.
    @Published var ts11DiscoveredCredentials: [Ts11DiscoveredCredential] = []
    @Published var ts11DiscoveryInProgress = false

    /// Queries `registry.siros.org` (via `Ts11CredentialDiscovery`) for
    /// every published credential type and stores the result in
    /// `ts11DiscoveredCredentials` for `WscdMappingCard` to offer as
    /// candidates. Best-effort: network/parse failures degrade to whatever
    /// subset of entries resolved, never surfaced as an app-level error -
    /// mirrors Kotlin's `discoverTs11Schemas()`.
    func discoverTs11Schemas() {
        guard !ts11DiscoveryInProgress else { return }
        ts11DiscoveryInProgress = true
        Task {
            defer { ts11DiscoveryInProgress = false }
            ts11DiscoveredCredentials = await Ts11CredentialDiscovery().discover()
        }
    }

    // MARK: - Loading / error

    @Published var isLoading = false
    @Published var errorMessage: String?
    @Published var showError = false

    // MARK: - Info (non-error, transient confirmations e.g. batch receipt)

    @Published var infoMessage: String?
    @Published var showInfo = false

    // MARK: - Wallet instance

    // `private(set)` rather than `private`: the Devices actions live in
    // `WalletViewModel+Devices.swift` (Swift extensions cannot hold stored
    // properties, so only the behaviour moved) and need to read it. Still
    // assigned only here.
    private(set) var wallet: SirosWallet?
    private var stateTask: Task<Void, Never>?
    private var pendingAuthFlowId: String?
    /// The flow type of the most recent `.flowActive` state, captured in
    /// `updateState` while the flow is still active. `onFlowComplete` needs
    /// this to distinguish issuance from presentation, but its own body runs
    /// in a deferred `Task { @MainActor in ... }` - by the time that runs,
    /// the wallet's state may have already transitioned to `.ready`, so it
    /// can't just read `wallet?.state` at completion time.
    private var lastFlowType: String?
    /// Credentials received so far in the current flow. Flows in this app
    /// run one at a time, so a plain counter reset on consumption (in
    /// onFlowComplete) is enough - no need to key it by flowId, which
    /// onCredentialReceived doesn't carry anyway.
    private var receivedCredentialCount = 0
    #if canImport(siros_wscd_managerFFI)
    /// Stored reference to the UniFFISigner for `listKeys()`/
    /// `securityProperties(keyId:)` calls only - these aren't part of
    /// `WscdManager` at all (they're generic `Signer`/`KeystoreManager`
    /// surface). Everything else (lifecycle, plugin registration) goes
    /// through `wallet.wscdManager`.
    private var wscdSigner: UniFFISigner?
    #endif
    private var lifecycleContextId: String?
    /// The continuation box backing the CURRENTLY shown `pendingWscdChoice`,
    /// if any - see `requestWscdChoice`'s doc comment.
    private var wscdChoiceContinuationBox: WscdChoiceContinuationBox?
    /// Offered at most once per process - a user who dismisses it isn't
    /// re-nagged every time `.ready` re-emits (e.g. after a token refresh),
    /// and one who accepts doesn't need it again once `enrollWscd()` runs.
    private var autoEnrollOffered = false

    init() {
        let defaults = UserDefaults.standard
        var backendUrl = defaults.string(forKey: "siros_backend_url") ?? defaultBackendUrl
        var tenantId = defaults.string(forKey: "siros_tenant_id") ?? defaultTenantId
        #if DEBUG
        // Debug-only test-environment override, the closest Swift/iOS analog
        // to Android's `adb shell am start --es backend_url ... --es tenant_id ...`:
        // set via `SIMCTL_CHILD_SIROS_BACKEND_URL=... xcrun simctl launch <udid> <bundle-id>`.
        // Session-scoped only - not persisted to UserDefaults.
        let env = ProcessInfo.processInfo.environment
        if let overrideBackendUrl = env["SIROS_BACKEND_URL"] { backendUrl = overrideBackendUrl }
        if let overrideTenantId = env["SIROS_TENANT_ID"] { tenantId = overrideTenantId }
        #endif
        self.backendUrl = backendUrl
        self.tenantId = tenantId
        self.useWmpProtocol = defaults.bool(forKey: "siros_use_wmp_protocol")
        if let storedShowDetails = defaults.object(forKey: "siros_show_credential_details") as? Bool {
            self.showCredentialDetails = storedShowDetails
        } else {
            #if DEBUG
            self.showCredentialDetails = true
            #else
            self.showCredentialDetails = false
            #endif
        }
        // Raw FlowStep tokens shown alongside the friendly progress label -
        // default false: seeing both together in practice is redundant, the
        // localized label alone is enough. Kept as an opt-in toggle for
        // debugging (was default true during initial rollout).
        self.showDiagnosticMessages = defaults.object(forKey: "siros_show_diagnostic_messages") as? Bool ?? false
        self.credentialConsumptionPolicy = defaults.string(forKey: "siros_credential_consumption_policy")
            .flatMap { CredentialConsumptionPolicy(rawValue: $0) } ?? .neverConsume
        self.wscdMultiPluginEnabled = defaults.bool(forKey: "siros_wscd_multi_plugin_enabled")
        self.wscdDefaultMapping = defaults.string(forKey: "siros_wscd_default_mapping_json")
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONDecoder().decode([String: String].self, from: $0) } ?? [:]
        self.zkCircuitUrls = defaults.string(forKey: "siros_zk_circuit_urls_json")
            .flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONDecoder().decode([String].self, from: $0) }
            .flatMap { $0.isEmpty ? nil : $0 } ?? [ZkCircuitClient.defaultZkCircuitUrl]
        self.preferLocalReaderTrustEvaluation = defaults.bool(forKey: "siros_prefer_local_reader_trust_evaluation")
        self.readerTrustRootCertificatePem = defaults.string(forKey: "siros_reader_trust_root_certificate_pem") ?? ""
        #if DEBUG
        applyFixtureCredentialsIfRequested()
        #endif
    }

    // MARK: - Public actions

    func login() {
        rebuildWalletIfNeeded()
        guard let wallet else { return }
        isLoading = true
        Task {
            do {
                try await wallet.login()
            } catch {
                setError(error.localizedDescription)
            }
            isLoading = false
        }
    }

    func loginWithAccount(_ account: CachedAccount) {
        rebuildWalletIfNeeded()
        guard let wallet else { return }
        isLoading = true
        Task {
            do {
                try await wallet.login()
            } catch {
                setError(error.localizedDescription)
            }
            isLoading = false
        }
    }

    func register(displayName: String) {
        rebuildWalletIfNeeded()
        guard let wallet else { return }
        isLoading = true
        Task {
            do {
                try await wallet.register(displayName: displayName)
            } catch {
                setError(error.localizedDescription)
            }
            isLoading = false
        }
    }

    func forgetAccount(_ accountId: String) {
        wallet?.forgetAccount(accountId: accountId)
        cachedAccounts.removeAll { $0.accountId == accountId }
    }

    func listPasskeysForUI() {
        passkeys = wallet?.listPasskeys() ?? []
    }

    func renamePasskey(credentialId: String, nickname: String) {
        wallet?.renamePasskey(credentialId: credentialId, nickname: nickname)
        listPasskeysForUI()
    }

    func disconnect() {
        wallet?.logout()
        selectedTab = 1
        showAddCredential = false
        availableCredentials = []
        selectedCredential = nil
        showHistory = false
        showActivate = false
        showWscaDeveloper = false
        resetDevicesNavigation()
    }

    func cancelCurrentFlow() {
        wallet?.cancelCurrentFlow()
    }

    // MARK: - WSCD lifecycle actions

    func selectPlugin(_ pluginId: String) {
        selectedPluginId = pluginId
        if pluginId == "r2ps" {
            r2psEnabled = true
        } else if selectedPluginId == "r2ps" {
            r2psEnabled = false
        }
    }

    func enrollWscd() {
        #if canImport(siros_wscd_managerFFI)
        guard let manager = wallet?.wscdManager else {
            setError("WSCD signer not initialized")
            return
        }
        enrollmentInProgress = true
        Task {
            do {
                let pluginId = selectedPluginId
                let contextId = "ctx-\(Int(Date().timeIntervalSince1970 * 1000))"
                let factorKind: FactorKind = pluginId == "r2ps" ? .opaque : .rawSign

                let regOutcome = try await manager.registerLifecycle(
                    request: RegisterLifecycleRequest(
                        pluginId: pluginId,
                        contextId: contextId,
                        factorKind: factorKind
                    )
                )
                lifecycleState = regOutcome.state

                let actOutcome = try await manager.activateLifecycle(
                    request: ActivateLifecycleRequest(
                        pluginId: pluginId,
                        contextId: contextId
                    )
                )
                lifecycleState = actOutcome.state
                lifecycleContextId = contextId

                // Persist the FIDO2 plugin's key metadata via privatedata so
                // this key stays addressable on any device sharing this
                // account - CTAP2 roaming authenticators (e.g. a YubiKey)
                // aren't tied to the device that enrolled them. Only wallet
                // exists by this point (unlike buildWscdSigner's initial,
                // eager keystore construction, which runs before `wallet`
                // does and so can't restore saved state the same way -
                // a real, accepted limitation mirrored from the Kotlin SDK,
                // not something newly introduced here).
                if pluginId == "fido2" {
                    do {
                        let stateData = try manager.exportFido2State()
                        // Stored as a UTF-8 string, not base64 - matches the
                        // Kotlin SDK's convention (exportFido2State's Data is
                        // already the plugin's JSON state encoded as UTF-8;
                        // registerFido2PluginWithState expects the same
                        // encoding back).
                        if let stateString = String(data: stateData, encoding: .utf8) {
                            await wallet?.saveWscdCredentials(pluginId: "fido2", state: stateString)
                        } else {
                            print("FIDO2 plugin state was not valid UTF-8 - not saving")
                        }
                    } catch {
                        print("Failed to export/save FIDO2 plugin state: \(error)")
                    }
                }
            } catch {
                setError("Enrollment failed: \(error.localizedDescription)")
            }
            enrollmentInProgress = false
        }
        #else
        setError("WSCD not available (siros_wscd_managerFFI not linked)")
        #endif
    }

    func rotateLifecycle() {
        #if canImport(siros_wscd_managerFFI)
        guard let manager = wallet?.wscdManager, let ctxId = lifecycleContextId else {
            setError("WSCD not enrolled")
            return
        }
        Task {
            do {
                let outcome = try await manager.rotateLifecycle(
                    request: RotateLifecycleRequest(
                        pluginId: selectedPluginId,
                        contextId: ctxId
                    )
                )
                lifecycleState = outcome.state
                refreshWscdInfo()
            } catch {
                setError("Rotation failed: \(error.localizedDescription)")
            }
        }
        #endif
    }

    func destroyLifecycle(mode: DestroyMode) {
        #if canImport(siros_wscd_managerFFI)
        guard let manager = wallet?.wscdManager, let ctxId = lifecycleContextId else {
            setError("WSCD not enrolled")
            return
        }
        Task {
            do {
                let outcome = try await manager.destroyLifecycle(
                    request: DestroyLifecycleRequest(
                        pluginId: selectedPluginId,
                        contextId: ctxId,
                        mode: mode
                    )
                )
                lifecycleState = outcome.state
                lifecycleContextId = nil
                refreshWscdInfo()
            } catch {
                setError("Destruction failed: \(error.localizedDescription)")
            }
        }
        #endif
    }

    // MARK: - Devices (wallet instance lifecycle, SID-AUTH-06)

    @Published var walletInstances: [WalletInstance] = []
    @Published var devicesLoading = false
    /// The instance whose status write is in flight, so its row can show a spinner.
    @Published var devicesBusyInstanceId: String?
    @Published var devicesError: String?
    @Published var deactivating = false
    /// What the last `deactivateWallet` call reported. Kept so the screen can
    /// say whether the backend confirmed the erasure - an incomplete one still
    /// deactivated the wallet, but leaves residual server-side data for an
    /// administrator, and the user should be told which of the two happened.
    @Published var deactivationOutcome: DeactivationOutcome?

    func openWscaDeveloper() {
        showWscaDeveloper = true
        refreshWscdInfo()
    }

    func closeWscaDeveloper() {
        showWscaDeveloper = false
    }

    func refreshWscdInfo() {
        #if canImport(siros_wscd_managerFFI)
        Task {
            if let signer = wscdSigner {
                do {
                    let keys = try await signer.listKeys()
                    wscdKeys = keys
                    var props: [String: SignerSecurityProperties] = [:]
                    for key in keys {
                        if let p = try? await signer.securityProperties(keyId: key.keyId) {
                            props[key.keyId] = p
                        }
                    }
                    wscdKeySecurityProps = props
                } catch {
                    print("Failed to list keys: \(error)")
                }
            }
            guard let manager = wallet?.wscdManager, let ctxId = lifecycleContextId else { return }
            do {
                let status = try await manager.lifecycleStatus(pluginId: selectedPluginId, contextId: ctxId)
                lifecycleStatus = status
                lifecycleState = status.state
            } catch {
                print("Failed to get lifecycle status: \(error)")
            }
        }
        #endif
    }

    // MARK: - WSCD selection policy (TOFU mapping + default mapping)

    /// Refreshes `wscdTofuMappingSnapshot` from `SirosWallet.wscdTofuMapping`
    /// - call on appear, like `listPasskeysForUI()`.
    func refreshWscdTofuMapping() {
        wscdTofuMappingSnapshot = wallet?.wscdTofuMapping ?? [:]
    }

    /// Clears one persisted WSCD TOFU entry - `key` must be exactly one of
    /// `wscdTofuMappingSnapshot`'s keys.
    func clearWscdTofuMapping(forKey key: String) {
        wallet?.clearWscdTofuMapping(forKey: key)
        refreshWscdTofuMapping()
    }

    /// Clears every persisted WSCD TOFU entry.
    func clearAllWscdTofuMappings() {
        wallet?.clearAllWscdTofuMappings()
        refreshWscdTofuMapping()
    }

    // MARK: - WSCD user overrides (explicit preferences, distinct from TOFU)

    /// Refreshes `wscdUserOverridesSnapshot`/`wscdGlobalOverrideSnapshot`
    /// from the SDK - call on appear, like `refreshWscdTofuMapping()`.
    func refreshWscdUserOverrides() {
        wscdUserOverridesSnapshot = wallet?.wscdUserOverrides ?? [:]
        wscdGlobalOverrideSnapshot = wallet?.wscdGlobalOverride
    }

    /// Sets (or overwrites) an explicit per-issuer WSCD preference from
    /// Settings - outranks TOFU and the global override for this exact pair.
    func setWscdUserOverride(issuer: String, credentialType: String, pluginId: String) {
        wallet?.setWscdUserOverride(issuer: issuer, credentialType: credentialType, pluginId: pluginId)
        refreshWscdUserOverrides()
    }

    /// Clears one per-issuer WSCD preference. Deliberately takes `issuer`/
    /// `credentialType` separately rather than one of
    /// `wscdUserOverridesSnapshot`'s combined `"issuer|credentialType"` keys
    /// - either half could itself contain the `"|"` separator, so there's
    /// no unambiguous way to split a combined key back into its parts (see
    /// `WscdSelectionPolicy.clearUserOverride`'s equivalent signature).
    func clearWscdUserOverride(issuer: String, credentialType: String) {
        wallet?.clearWscdUserOverride(issuer: issuer, credentialType: credentialType)
        refreshWscdUserOverrides()
    }

    /// Sets (or overwrites) the single global WSCD preference from Settings.
    func setWscdGlobalOverride(pluginId: String) {
        wallet?.setWscdGlobalOverride(pluginId: pluginId)
        refreshWscdUserOverrides()
    }

    /// Clears the global WSCD preference ("No preference").
    func clearWscdGlobalOverride() {
        wallet?.clearWscdGlobalOverride()
        refreshWscdUserOverrides()
    }

    // MARK: - WSCD auto-enroll offer

    /// Checked every time the wallet becomes `.ready` (right after a
    /// successful login, and on later reconnects). If the login provider's
    /// `WscdAutoEnrollHint` suggests this might be a WSCD-capable device,
    /// that plugin is available in this session, and nothing is enrolled for
    /// it yet, offers the user a one-tap prompt to enroll it.
    private func maybeOfferWscdAutoEnroll() {
        guard !autoEnrollOffered, let wallet else { return }
        guard let hint = wallet.wscdAutoEnrollHint(), hint.suggestsWscdCapableDevice() else { return }
        let pluginId = hint.hintedWscdPluginId
        guard availableWscdPluginIds.contains(pluginId) else { return }
        // Mark as handled *before* the async check below, not after -
        // otherwise a second `.ready` re-emission (e.g. a fast reconnect)
        // racing the first Task's `await` could still see `autoEnrollOffered
        // == false`, pass the guard above again, and double-schedule the
        // offer.
        autoEnrollOffered = true
        Task { @MainActor in
            guard await wallet.wscdCredentials(pluginId: pluginId) == nil else { return }
            pendingAutoEnrollOffer = pluginId
        }
    }

    /// The user's answer to `pendingAutoEnrollOffer`. Accepting switches to
    /// that plugin's tab and starts the normal enroll flow - same PIN-first +
    /// present-key sequence as the manual Enroll button, since accepting
    /// this offer is still only a HINT that the device supports signing.
    func respondToAutoEnrollOffer(accept: Bool) {
        guard let pluginId = pendingAutoEnrollOffer else { return }
        pendingAutoEnrollOffer = nil
        if accept {
            selectPlugin(pluginId)
            enrollWscd()
        }
    }

    /// Adds/overwrites one `WalletConfig.defaultWscdMapping` entry - dev
    /// config (`WscdSettingsView`), not persisted TOFU state. Requires a
    /// fresh `rebuildWalletIfNeeded()` (e.g. next login) to actually take
    /// effect, same as `selectedPluginId`.
    func addWscdDefaultMapping(issuer: String, credentialType: String, pluginId: String) {
        guard !issuer.isEmpty, !credentialType.isEmpty, !pluginId.isEmpty else { return }
        wscdDefaultMapping["\(issuer)|\(credentialType)"] = pluginId
    }

    /// Removes one `WalletConfig.defaultWscdMapping` entry - `key` must be
    /// exactly one of `wscdDefaultMapping`'s keys.
    func removeWscdDefaultMapping(key: String) {
        wscdDefaultMapping.removeValue(forKey: key)
    }

    /// Bridges `RequestWscdChoice`'s async callback (see `WalletConfig.requestWscdChoice`)
    /// to `WscdChoiceSheet`: suspends the caller until the user taps a
    /// plugin or Cancel. Mirrors `ProximityEngagementContent.requestConsent`'s
    /// identical bridge for `RequestProximityConsent`.
    nonisolated func requestWscdChoice(
        issuer: String,
        credentialType: String,
        eligiblePluginIds: [String]
    ) async -> WscdChoiceResult {
        await withCheckedContinuation { (continuation: CheckedContinuation<WscdChoiceResult, Never>) in
            let box = WscdChoiceContinuationBox()
            box.set(continuation)
            Task { @MainActor in
                self.wscdChoiceContinuationBox = box
                self.pendingWscdChoice = PendingWscdChoice(
                    issuer: issuer,
                    credentialType: credentialType,
                    eligiblePluginIds: eligiblePluginIds,
                    respond: { chosenPluginId, rememberScope in
                        // Triggers `.sheet(item:onDismiss:)`'s onDismiss too
                        // (setting the bound item to nil dismisses the
                        // sheet) - that's fine: `box.resumeOnce` below
                        // already wins the race, so onDismiss's own
                        // `dismissWscdChoice` call is a harmless no-op by
                        // the time it runs. See `ProximityEngagementContent
                        // .requestConsent`'s identical comment.
                        self.pendingWscdChoice = nil
                        let result = chosenPluginId.map { WscdChoiceResult.chosen(pluginId: $0, rememberScope: rememberScope) } ?? .cancelled
                        box.resumeOnce(result)
                    }
                )
            }
        }
    }

    /// Resolves `pendingWscdChoice` as `.cancelled` if the sheet is
    /// dismissed without the user tapping a plugin or Cancel (e.g. swiping
    /// it away) - the genuine Swift equivalent of the gap
    /// `ProximityEngagementContent`'s own `onDismiss` handles for
    /// `RequestProximityConsent`; without it this continuation would
    /// otherwise hang forever. `resumeOnce` is a no-op if the user already
    /// tapped a plugin/Cancel (`respond` already resumed it).
    func dismissWscdChoice() {
        pendingWscdChoice = nil
        wscdChoiceContinuationBox?.resumeOnce(.cancelled)
        wscdChoiceContinuationBox = nil
    }

    /// Resolves `pendingFido2PinEntry` as cancelled if the sheet is
    /// dismissed without the user tapping Submit/Cancel (e.g. swiping it
    /// away) - see `dismissWscdChoice`'s identical rationale. `respond` is
    /// safe to call more than once here since `SampleAppAuthProvider`
    /// signals its semaphore at most once regardless (matching
    /// `WscdChoiceContinuationBox.resumeOnce`'s guard, just inlined instead
    /// of boxed since this callback is synchronous, not a continuation).
    func dismissFido2PinEntry() {
        let pending = pendingFido2PinEntry
        pendingFido2PinEntry = nil
        pending?.respond(nil)
    }

    /// Start issuance from a credential offer URI (for testing/automation).
    func startIssuance(_ offerUri: String) {
        Task {
            do {
                try await wallet?.startIssuance(offerUri: offerUri)
            } catch {
                setError(error.localizedDescription)
            }
        }
    }

    /// Start presentation from a request URI (for testing/automation).
    func startPresentation(_ requestUri: String) {
        Task {
            do {
                try await wallet?.startPresentation(requestUri: requestUri)
            } catch {
                setError(error.localizedDescription)
            }
        }
    }

    // MARK: - Credential operations

    func openAddCredential() {
        showAddCredential = true
        isLoadingOffers = true
        Task {
            do {
                let offers = try await wallet?.getAvailableCredentials() ?? []
                availableCredentials = offers.filter { $0.credentialConfigurationId != sirosIdCredentialConfigurationId }
            } catch {
                print("Failed to load available credentials: \(error)")
                availableCredentials = []
            }
            isLoadingOffers = false
        }
    }

    func closeAddCredential() {
        showAddCredential = false
        pendingIssuanceOffer = nil
    }

    // MARK: - Issuance consent

    @Published var pendingIssuanceOffer: CredentialOffer?

    func selectCredentialOffer(_ offer: CredentialOffer) {
        pendingIssuanceOffer = offer
    }

    func confirmIssuance() {
        guard let offer = pendingIssuanceOffer else { return }
        pendingIssuanceOffer = nil
        showAddCredential = false
        Task {
            try? await wallet?.startIssuanceByOffer(offer)
        }
    }

    func cancelIssuance() {
        pendingIssuanceOffer = nil
    }

    // MARK: - Identity Verification (FaceTec IDV)

    /// IDV server URL — defaults to facetec-api co-hosted behind /idv path.
    var idvServerUrl: String { backendUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/")) + "/idv" }

    func startIDV() {
        Task {
            do {
                isLoading = true
                guard let wallet else { throw SirosError.wallet(message: "Wallet is not connected") }
                let token = try await wallet.getAccessToken()
                let delegate = FaceTecCaptureDelegate()
                let client = RemoteIDVClient(config: RemoteIDVClient.Config(
                    serverUrl: idvServerUrl,
                    authToken: "Bearer \(token)"
                ))
                let provider = RemoteIDVProvider(client: client, delegate: delegate)
                let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene
                let rootViewController = windowScene?.windows.first?.rootViewController ?? UIViewController()
                try await wallet.verifyIdentityAndIssue(provider: provider, presentingViewController: rootViewController)
            } catch {
                errorMessage = "IDV failed: \(error.localizedDescription)"
            }
            isLoading = false
        }
    }

    func openCredentialDetail(_ credential: StoredCredential) {
        guard showCredentialDetails else { return }
        selectedCredential = credential
    }

    func closeCredentialDetail() {
        selectedCredential = nil
    }

    func deleteCredential(_ id: Int64) {
        Task {
            await wallet?.deleteCredential(id)
            selectedCredential = nil
        }
    }

    // MARK: - Presentation

    func acceptPresentation(_ selectedIds: [Int64]) {
        pendingPresentation = nil
        presentationContinuation?.resume(returning: selectedIds)
        presentationContinuation = nil
    }

    func declinePresentation() {
        pendingPresentation = nil
        presentationContinuation?.resume(returning: [])
        presentationContinuation = nil
    }

    // MARK: - History

    func openHistory() {
        showHistory = true
        presentationHistory = wallet?.presentationHistory ?? []
    }

    func closeHistory() {
        showHistory = false
    }

    // MARK: - Activate (QR scan + proximity engagement)

    /// Opens Activate, always starting in QR mode (the default engagement path).
    func openActivate() {
        activateMode = .qr
        showActivate = true
    }

    /// Switches an already-open Activate screen into proximity/BLE mode.
    func switchActivateMode(_ mode: ActivateMode) {
        activateMode = mode
    }

    /// Leaves Activate entirely, from either mode.
    func closeActivate() {
        showActivate = false
    }

    // MARK: - Proximity (ISO 18013-5 BLE) presentation dependencies

    /// Mirrors `SirosWallet.getCredentials` - passed to `BlePeripheralServer`
    /// so it can match a request's docType without depending on this view
    /// model or `SirosWallet` directly.
    func getCredentialsForProximity() async -> [StoredCredential] {
        await wallet?.getCredentials() ?? []
    }

    /// Mirrors `SirosWallet.signMdocPresentationForProximity` - passed to
    /// `BlePeripheralServer`.
    func signMdocPresentationForProximity(
        credentialId: Int64,
        disclosedClaims: [String]?,
        sessionTranscriptBytes: Data
    ) async throws -> Data {
        guard let wallet else {
            throw SirosError.wallet(message: "Wallet is not connected")
        }
        return try await wallet.signMdocPresentationForProximity(
            credentialId: credentialId,
            disclosedClaims: disclosedClaims,
            sessionTranscriptBytes: sessionTranscriptBytes
        )
    }

    /// The wallet's presentation history, read live (unlike `presentationHistory`
    /// above, which is only refreshed when the History screen opens) - for
    /// callers like `CredentialsView`/`filterEligibleForProximity` that need
    /// an up-to-date view to compute `CredentialUtils.eligibleInstances`
    /// on every render/decision rather than a possibly-stale cached copy.
    var currentPresentationHistory: [PresentationRecord] {
        wallet?.presentationHistory ?? []
    }

    /// `SirosWallet.eligibleInstances(from:)` bound to `wallet`'s current
    /// `credentialConsumptionPolicy`/`presentationHistory`/live key set -
    /// passed to `BlePeripheralServer`/`BleCentralClient` and
    /// `ProximityConsentSheet` so a family the user approves can't be signed
    /// with (or picked for) an exhausted instance, or one whose signing key
    /// has silently gone missing. Without a wallet there is no keystore to
    /// sign with, so nothing is eligible.
    func filterEligibleForProximity(_ instances: [StoredCredential]) -> [StoredCredential] {
        wallet?.eligibleInstances(from: instances) ?? []
    }

    /// Mirrors `SirosWallet.evaluateReaderTrust` - passed to
    /// `BlePeripheralServer`/`BleCentralClient`'s `evaluateReaderTrust`
    /// dependency. Adapts `TrustResult` (shared with the verifier/issuer
    /// trust paths) down to `MdocProximitySession`'s narrower
    /// `ReaderTrustResult`.
    func evaluateReaderTrustForProximity(_ x5chain: [[UInt8]]) async -> ReaderTrustResult {
        guard let wallet else {
            return ReaderTrustResult(trusted: false, reason: "Wallet is not connected")
        }
        let result = await wallet.evaluateReaderTrust(x5chain)
        return ReaderTrustResult(trusted: result.trusted, reason: result.reason, entityName: result.entityName)
    }

    /// Same as `filterEligibleForProximity`, generalized for the redirect/DC
    /// API presentation consent screen (`PresentationConsentView`) - a query
    /// is unsatisfiable if every candidate that matched it has already been
    /// used up under the active consumption policy (see
    /// `CredentialUtils.eligibleInstances`). The SDK itself refuses to sign
    /// with an exhausted instance regardless (defense in depth), but the
    /// user shouldn't be let all the way to "Share" only to have it silently
    /// fail.
    func eligibleCredentialIds(from candidates: [StoredCredential]) -> [Int64] {
        filterEligibleForProximity(candidates).map(\.id)
    }

    /// Renew `credential`'s batch, for `CredentialCardView`'s "Renew" action
    /// (always shown - credential re-issuance/renewal plan §4.4: the user
    /// never sees whether a silent refresh_token-based renewal or a full
    /// re-issuance is what actually happens, only that "renew" worked or
    /// didn't).
    ///
    /// Tries `SirosWallet.renewCredential(batchId:)` (silent OID4VCI
    /// `refresh_token` grant) first. If that fails - no refresh_token was
    /// ever captured for this batch, or it's already been consumed - falls
    /// back to a full re-issuance from the credential's own issuer/config
    /// (already stored on it - see
    /// `StoredCredential.credentialIssuerIdentifier`/`StoredCredential.credentialConfigurationId`),
    /// skipping the generic issuer-browsing screen entirely. Only shows the
    /// "No refresh possible" error for the residual case where even that
    /// fallback isn't possible (issuer info missing entirely).
    func renewCredential(_ credential: StoredCredential) {
        Task {
            do {
                try await wallet?.renewCredential(batchId: credential.batchId)
                return
            } catch SirosError.renewalUnavailable {
                // The one specifically recoverable case - fall through to
                // full re-issuance below. Any other failure (not connected,
                // another issuance already in progress, network error) is
                // surfaced directly instead, since silently attempting a
                // full re-issuance would misreport a transient failure as
                // if refresh-based renewal simply weren't available.
            } catch {
                setError(error.localizedDescription)
                return
            }
            guard let issuerId = credential.credentialIssuerIdentifier,
                  let configId = credential.credentialConfigurationId else {
                setError("No refresh possible")
                return
            }
            let offer = CredentialOffer(
                credentialConfigurationId: configId,
                credentialIssuerIdentifier: issuerId,
                credentialName: credential.metadata?.name ?? credential.format,
                issuerName: credential.metadata?.issuer?.name ?? issuerId
            )
            do {
                try await wallet?.startIssuanceByOffer(offer)
            } catch {
                setError(error.localizedDescription)
            }
        }
    }

    func handleQrResult(_ code: String) {
        closeActivate()
        let linkType = DeepLinkClassifier.classify(code)
        switch linkType {
        case .credentialOffer(let uri):
            startFlow(type: "issuance") { try await self.wallet?.startIssuance(offerUri: uri) }
        case .presentationRequest(let uri):
            startFlow(type: "presentation") { try await self.wallet?.startPresentation(requestUri: uri) }
        case .authCallback(let authCode, let state):
            handleAuthRedirect(code: authCode, state: state)
        case .unknown(let uri):
            // Fallback: treat unclassified URIs as presentation requests -
            // covers plain https://...?request_uri= patterns from QR codes
            // that DeepLinkClassifier doesn't recognize by shape.
            startFlow(type: "presentation") { try await self.wallet?.startPresentation(requestUri: uri) }
        }
    }

    /// Cancel affordance for the "Contacting issuer/verifier..." interstitial
    /// shown while `flowStarting != nil`. Best-effort: `cancelCurrentFlow()`
    /// is a guarded no-op unless the engine has already reported
    /// `.flowActive` (see its doc comment), which may not have happened yet
    /// at this point - clearing `flowStarting` locally is what actually
    /// dismisses the interstitial either way.
    func cancelFlowStarting() {
        flowStarting = nil
        wallet?.cancelCurrentFlow()
    }

    /// Sets `flowStarting` synchronously before kicking off `body`, clearing
    /// it again immediately if `body` throws synchronously (e.g. "not
    /// connected"). Any error surfaced later via the engine's own event/state
    /// stream instead (bad offer/request content, network failure) is
    /// cleared by `updateState`'s unconditional clear-on-every-state, not here.
    private func startFlow(type: String, _ body: @escaping () async throws -> Void) {
        flowStarting = type
        Task {
            do {
                try await body()
            } catch {
                flowStarting = nil
                setError(error.localizedDescription)
            }
        }
    }

    // MARK: - Deep links

    func handleDeepLink(_ url: URL) {
        let linkType = DeepLinkClassifier.classify(url.absoluteString)
        switch linkType {
        case .authCallback(let code, let state):
            handleAuthRedirect(code: code, state: state)
        case .credentialOffer(let uri):
            startFlow(type: "issuance") { try await self.wallet?.startIssuance(offerUri: uri) }
        case .presentationRequest(let uri):
            startFlow(type: "presentation") { try await self.wallet?.startPresentation(requestUri: uri) }
        case .unknown(let uri):
            // Fallback: treat unclassified URIs as presentation requests -
            // matches handleQrResult's fallback for the same URI shapes
            // arriving via a same-device link instead of a QR scan.
            startFlow(type: "presentation") { try await self.wallet?.startPresentation(requestUri: uri) }
        }
    }

    // MARK: - Error handling

    func clearError() {
        errorMessage = nil
        showError = false
    }

    func clearInfo() {
        infoMessage = nil
        showInfo = false
    }

    // MARK: - Private

    private var presentationContinuation: CheckedContinuation<[Int64], Never>?

    private func setError(_ message: String) {
        errorMessage = message
        showError = true
    }

    private func handleAuthRedirect(code: String, state: String) {
        guard let flowId = pendingAuthFlowId else {
            setError("Authorization failed: no pending flow")
            return
        }
        pendingAuthFlowId = nil
        wallet?.completeAuthorization(flowId: flowId, code: code, state: state)
    }

    #if canImport(siros_wscd_managerFFI)
    /// Lazily-created so it can hold a weak reference back to `self`
    /// without `buildWscdSigner` needing to construct a fresh one per call
    /// (every plugin's `UniFFISigner` shares this one instance, matching
    /// how a single Kotlin `AuthProvider` object backs every plugin there
    /// too).
    private lazy var wscdAuthProvider = SampleAppAuthProvider(viewModel: self)

    /// Builds a WSCD-backed `Signer` for a single plugin ID, using exactly
    /// the `FfiWscdConfig`/`UniFFISigner`/R2PS-registration construction
    /// `rebuildWalletIfNeeded` always used for its one `selectedPluginId`
    /// signer - factored out here so `WalletConfig.availableKeystores` can
    /// reuse it once per known plugin ID instead of duplicating it, per
    /// `WscdSelectionPolicy`'s multi-plugin selection feature.
    private func buildWscdSigner(forPlugin pluginId: String) -> UniFFISigner? {
        do {
            let wscdConfig = FfiWscdConfig(defaultPlugin: pluginId)
            let signer = try UniFFISigner(config: wscdConfig, authProvider: wscdAuthProvider)

            if pluginId == "fido2" {
                // No USB HID host mode is available to third-party iOS
                // apps (a real platform constraint, not a gap to fix), so
                // unlike the Kotlin sample app's USB/NFC race
                // (CompositeCtap2Transport), there's only one real
                // transport to register here.
                try signer.registerFido2Plugin(transport: NfcCtap2Transport())
            }

            if pluginId == "r2ps" {
                // Ephemeral P-256 key pair for the R2PS message envelope
                // (JWS/JWE identity) - required regardless of auth mode.
                let clientKey = P256.Signing.PrivateKey()
                // `serverPublicKeyPem` MUST be the R2PS SERVER's own public
                // key (for JWE envelope encryption TO the server) - never
                // the client's own key, which would break the security
                // model entirely (encrypting to a key the client itself
                // holds the private half of defeats the point). See
                // `r2psServerPublicKeyPem`'s doc comment: no real dev server
                // key is available to hardcode here, so this is left as an
                // explicit dev-configurable placeholder rather than
                // silently substituting `clientKey.publicKey` again.
                let r2psConfig = R2psConfig(
                    serverUrl: r2psServerUrl,
                    clientId: "sample-app",
                    context: "wallet",
                    clientKeyPem: clientKey.pemRepresentation,
                    serverPublicKeyPem: r2psServerPublicKeyPem,
                    authMode: .opaque
                )
                let transport = URLSessionR2psTransport(serverUrl: r2psServerUrl)
                try signer.registerR2psPlugin(config: r2psConfig, transport: transport)
            }

            return signer
        } catch {
            print("WSCD setup failed for plugin \(pluginId): \(error). Skipping.")
            return nil
        }
    }
    #endif

    private func rebuildWalletIfNeeded() {
        // Rebuild if wallet doesn't exist or is in Disconnected/Error state
        let needsRebuild: Bool
        if wallet == nil {
            needsRebuild = true
        } else {
            switch walletState {
            case .disconnected, .error:
                wallet?.destroy()
                wallet = nil
                needsRebuild = true
            default:
                needsRebuild = false
            }
        }

        guard needsRebuild else { return }

        // Build WSCD-backed keystore with selected plugin
        var keystore: KeystoreManager?
        var availableKeystores: [String: KeystoreManager] = [:]
        #if canImport(siros_wscd_managerFFI)
        // Only construct a signer for every known plugin ID when the dev has
        // explicitly opted into multi-plugin selection
        // (`wscdMultiPluginEnabled`, see its doc comment) - otherwise (the
        // common case) this must build exactly the one `selectedPluginId`
        // signer, matching this method's behavior before `availableKeystores`
        // existed. "r2ps" additionally needs a reachable server URL to
        // register successfully, so it's only attempted when the dev has
        // separately turned it on (matches its existing gating below).
        let pluginIdsToTry: [String]
        if wscdMultiPluginEnabled {
            pluginIdsToTry = selectedPluginId == "r2ps" || r2psEnabled
                ? Array(WscdPluginCapabilities.pluginTiers.keys)
                : WscdPluginCapabilities.pluginTiers.keys.filter { $0 != "r2ps" }
        } else {
            pluginIdsToTry = [selectedPluginId]
        }

        for pluginId in pluginIdsToTry {
            guard let signer = buildWscdSigner(forPlugin: pluginId) else { continue }
            // Exactly one `WscdKeystoreAdapter` per signer, reused as both
            // the main `keystore` (for `selectedPluginId`) and its
            // `availableKeystores` entry - never two separate adapter
            // instances wrapping the same underlying signer, which would
            // let their independent `_isUnlocked`/credentials state drift
            // apart if `WscdSelectionPolicy.resolve` ever picked
            // `selectedPluginId` back out of `availableKeystores` (its doc
            // comment treats a `nil` result, not a same-as-default result,
            // as "no change" - a same-ID resolution is possible whenever
            // more than one plugin is eligible and the user/TOFU/default
            // mapping happens to pick the one that's already the default).
            let adapter = WscdKeystoreAdapter(signer: signer)
            if pluginId == selectedPluginId {
                self.wscdSigner = signer
                keystore = adapter
            }
            // Only populate `availableKeystores` beyond the selected plugin
            // when the dev has explicitly opted into multi-plugin selection
            // (`WscdSettingsView`'s toggle) - see `wscdMultiPluginEnabled`'s
            // doc comment for why this isn't unconditional.
            if pluginId == selectedPluginId || wscdMultiPluginEnabled {
                availableKeystores[pluginId] = adapter
            }
        }
        #endif
        availableWscdPluginIds = availableKeystores.keys.sorted()

        // Broken out into separately-typed statements rather than inlined
        // directly in the `WalletConfig(...)` call below - the combination
        // of ternaries plus an inline `@Sendable` async closure literal in
        // one expression hit a real Swift type-checker limit ("failed to
        // produce diagnostic for expression") when compiled via Xcode.
        let resolvedAvailableKeystores: [String: KeystoreManager]? =
            (wscdMultiPluginEnabled && !availableKeystores.isEmpty) ? availableKeystores : nil
        let resolvedDefaultWscdMapping: [String: String]? =
            (wscdMultiPluginEnabled && !wscdDefaultMapping.isEmpty) ? wscdDefaultMapping : nil
        let resolvedRequestWscdChoice: RequestWscdChoice?
        if wscdMultiPluginEnabled {
            resolvedRequestWscdChoice = { [weak self] issuer, credentialType, eligiblePluginIds in
                await self?.requestWscdChoice(
                    issuer: issuer,
                    credentialType: credentialType,
                    eligiblePluginIds: eligiblePluginIds
                ) ?? .cancelled
            }
        } else {
            resolvedRequestWscdChoice = nil
        }

        let config = WalletConfig(
            backendUrl: backendUrl,
            tenantId: tenantId,
            redirectUri: "\(redirectScheme)://callback",
            useWmpProtocol: useWmpProtocol,
            availableKeystores: resolvedAvailableKeystores,
            defaultWscdMapping: resolvedDefaultWscdMapping,
            requestWscdChoice: resolvedRequestWscdChoice,
            zkCircuitUrls: zkCircuitUrls,
            readerTrustRootCertificatesPem: readerTrustRootCertificatePem.isEmpty ? [] : [readerTrustRootCertificatePem],
            preferLocalReaderTrustEvaluation: preferLocalReaderTrustEvaluation
        )

        // ASAuthorizationAuthProvider is the real, OS-backed passkey provider
        // (Face ID/Touch ID/roaming security keys) and is used on every
        // platform it supports (iOS 18+ and macOS 15+, matching Package.swift's
        // declared platforms). LocalAuthProvider is an explicit, clearly
        // labeled dev/test-only fallback for anything else — never a silent
        // per-platform default for a "supported" platform.
        #if os(iOS)
        let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene
        let anchor = windowScene?.windows.first ?? UIWindow()
        let authProvider = ASAuthorizationAuthProvider(presentationAnchor: anchor)
        #elseif os(macOS)
        let anchor = NSApplication.shared.windows.first ?? NSWindow()
        let authProvider = ASAuthorizationAuthProvider(presentationAnchor: anchor)
        #else
        let authProvider = LocalAuthProvider()
        #endif
        wallet = SirosWallet(
            config: config,
            authProvider: authProvider,
            sessionStore: KeychainSessionStore(),
            keystore: keystore
        )
        wallet?.credentialConsumptionPolicy = credentialConsumptionPolicy
        wallet?.setEventListener(self)
        observeState()
    }

    private func observeState() {
        stateTask?.cancel()
        stateTask = Task { [weak self] in
            guard let self, let wallet = self.wallet else { return }
            for await state in wallet.stateStream() {
                guard !Task.isCancelled else { break }
                self.updateState(state)
            }
        }
    }

    private func updateState(_ state: WalletState) {
        // Every call here is a real state update from the engine (or a
        // reconnect/logout) - whatever the QR-scan/deep-link handoff was
        // waiting on has now either progressed (flowActive), failed
        // (.error), or otherwise resolved, so the "Contacting issuer/
        // verifier..." interstitial no longer applies.
        flowStarting = nil
        switch state {
        case .disconnected(let accounts):
            walletState = .disconnected
            credentials = []
            displayName = nil
            userId = nil
            cachedAccounts = accounts
        case .connecting:
            walletState = .connecting
        case .ready(let uid, let name, let creds, let accounts):
            walletState = .ready
            credentials = creds
            displayName = name
            userId = uid
            cachedAccounts = accounts
            listPasskeysForUI()
            maybeOfferWscdAutoEnroll()
        case .keystoreLocked(_, let name):
            walletState = .connecting
            displayName = name
        case .flowActive(_, _, _, let flowType, let status, let creds):
            walletState = .flowActive(flowType: flowType, status: status)
            credentials = creds
            lastFlowType = flowType
        case .lifecycleBlocked(let reason, let message, let accounts):
            walletState = .lifecycleBlocked(reason: reason, message: message)
            credentials = []
            displayName = nil
            userId = nil
            cachedAccounts = accounts
            showDevices = false
        case .error(let message):
            walletState = .error(message: message)
        }
    }
}

// MARK: - WalletEventListener

extension WalletViewModel: WalletEventListener {
    nonisolated func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] {
        await withCheckedContinuation { continuation in
            Task { @MainActor in
                self.presentationContinuation = continuation
                self.pendingPresentation = request
            }
        }
    }

    nonisolated func onCredentialReceived(credential: StoredCredential) {
        Task { @MainActor in
            self.receivedCredentialCount += 1
        }
    }

    nonisolated func onFlowComplete(flowId: String, redirectUri: String?) {
        Task { @MainActor in
            if self.receivedCredentialCount > 0 {
                self.infoMessage = L10n.string("flow.credentialsReceived", self.receivedCredentialCount)
                self.showInfo = true
                self.receivedCredentialCount = 0
            } else if self.lastFlowType == "presentation" {
                // Presentation has no analogous per-item count, so a plain
                // confirmation is the equivalent "something happened" signal
                // for a flow whose whole point is watching this screen after
                // a QR scan.
                self.infoMessage = L10n.string("flow.presentationSent")
                self.showInfo = true
            }

            // Some verifiers (e.g. verifier.multipaz.org) return a
            // redirect_uri with their direct_post.jwt response so the
            // user's browser can be sent back to the verifier's own result
            // page. Without this, the flow just silently ends on the
            // wallet side with no way back to the verifier.
            self.openVerifierRedirect(redirectUri)
        }
    }

    nonisolated func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) {
        Task { @MainActor in
            self.receivedCredentialCount = 0
            self.setError(errorMessage)

            // Mirrors onFlowComplete above - a verifier can return a
            // redirect_uri from its error-response endpoint too (e.g. on
            // user-decline), so the user isn't left stranded in the wallet
            // just because the flow ended in an error rather than success.
            self.openVerifierRedirect(redirectUri)
        }
    }

    /// Opens a verifier-provided redirect_uri (from flow completion or decline) in the browser.
    @MainActor
    private func openVerifierRedirect(_ redirectUri: String?) {
        guard let redirectUri, let url = URL(string: redirectUri) else { return }
        #if canImport(UIKit)
        UIApplication.shared.open(url)
        #endif
    }

    nonisolated func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String) {
        Task { @MainActor in
            self.pendingAuthFlowId = flowId
            guard let url = URL(string: authorizationUrl) else { return }
            #if canImport(UIKit)
            UIApplication.shared.open(url)
            #endif
        }
    }

    nonisolated func onTxCodeRequired(flowId: String, description: String?) -> String? {
        // Auto-extract PIN from description for testing
        guard let desc = description else { return nil }
        let pattern = #/<(\d+)>/#
        if let match = desc.firstMatch(of: pattern) {
            return String(match.1)
        }
        return nil
    }
}

// MARK: - View State

enum WalletViewState: Equatable {
    case disconnected
    case connecting
    case ready
    /// The wallet instance this installation logs in with is suspended, or the
    /// wallet was deactivated and its data erased (SID-AUTH-06). Not an error
    /// to retry - only someone else can lift it - so it gets its own screen.
    case lifecycleBlocked(reason: SirosError.WalletLifecycleRefusal, message: String?)
    case flowActive(flowType: String, status: String)
    case error(message: String)
}
