// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@preconcurrency import SwiftCBOR
import SirosCredentials
import SirosTransport
import SirosAuth
import SirosKeystore
import SirosFlow
#if canImport(os)
import os
#endif

#if canImport(os)
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

/// Authorization context captured at `authorization_required` time, needed to
/// resume an OID4VCI issuance flow via a fresh `flow_start` once the OAuth
/// browser redirect returns. See `SirosWallet.completeAuthorization`.
// Not `private`: `SirosWallet+Engine.swift`'s `connectEngine` needs it too -
// same cross-file-extension-access reason as `keystore` above.
struct PendingAuthorization: Sendable {
    let offer: String?
    let credentialOfferUri: String?
    let redirectUri: String?
    let codeVerifier: String?
    let state: String
    /// The issuance epoch the ORIGINATING flow started under (its start tag), carried
    /// to the resume instead of re-sampling the current epoch after the browser
    /// round-trip and the token/connection awaits. Nil when the session could not
    /// tie the flow to its start: the resume is then refused.
    let startEpoch: Int?
}

/// Main entry point for the SIROS Wallet SDK (cross-platform).
///
/// Provides a single, self-contained API for wallet apps:
///
/// ```swift
/// let wallet = SirosWallet(
///     config: WalletConfig(backendUrl: "https://wallet.sirosid.dev"),
///     authProvider: myAuthProvider,
///     sessionStore: mySessionStore
/// )
/// try await wallet.login()
/// for await state in wallet.stateStream { /* drive UI */ }
/// ```
///
/// The SDK handles WebAuthn authentication with PRF extension, HKDF key
/// derivation, JWE keystore unlock, encrypted private-data sync with the
/// backend, and the engine WebSocket session for issuance/presentation flows.
public final class SirosWallet: @unchecked Sendable {

    // MARK: - Public state

    let lock = NSLock()
    // Not `private`: `setState` (in `SirosWallet+Lifecycle.swift`, a
    // separate file, same module) needs it too - Swift's `private` is
    // file-scoped, not module-scoped, matching this file's existing
    // `keystore`/`activeOffer` etc. convention.
    var _state: WalletState = .disconnected()
    var stateContinuations: [String: AsyncStream<WalletState>.Continuation] = [:]

    // EC TS12 payment SCA (`transaction_data`): state here, behaviour in `SirosWallet+TransactionData*.swift`.
    var transactionDataEnabledValue: Bool
    var transactionConsentHandlerStorage: (any TransactionConsentHandler)?
    var transactionLogStoreStorage: (any TransactionLogStore)?
    // Enablement records per flow / WMP session, consent flows in progress, log-store bookkeeping.
    var legacyFlowSnapshotQueue: [(effective: Bool, at: Date)] = []
    var legacyFlowSnapshots: [String: Bool] = [:]
    var wmpSessionSnapshot = false
    var transactionTasks: [UUID: (flowId: String, cancel: @Sendable () -> Void)] = [:]
    var transactionLogStoreIsDefault = false
    var transactionLogGeneration = 0
    var transactionTaskEpoch = 0
    var flowEndSeq: [String: Int] = [:]
    let keystorePersistMutex = AsyncMutex()
    var transactionDataLocaleStorage: String = Locale.preferredLanguages.first ?? "en"
    var transactionDataConsentTimeout: TimeInterval = TransactionDataService.defaultConsentTimeout
    // Test hooks: how referenced documents and type metadata are fetched.
    var transactionResourceGet: @Sendable (URL, Int) async -> Data? = SirosWallet.secureResourceGet
    lazy var transactionMetadataFetch: @Sendable (String, String?, Int) async -> String? = { [weak self] v, p, l in await self?.fetchTypeMetadata(vct: v, expectedIntegrity: p, maxBytes: l) }

    /// Current wallet state (thread-safe read).
    public var state: WalletState {
        lock.lock(); defer { lock.unlock() }
        return _state
    }

    /// AsyncStream of state changes.
    public func stateStream() -> AsyncStream<WalletState> {
        let id = UUID().uuidString
        return AsyncStream<WalletState> { [weak self] continuation in
            guard let self else { return }
            self.lock.lock()
            self.stateContinuations[id] = continuation
            let current = self._state
            self.lock.unlock()
            continuation.yield(current)
            continuation.onTermination = { [weak self] _ in
                self?.lock.lock()
                self?.stateContinuations.removeValue(forKey: id)
                self?.lock.unlock()
            }
        }
    }

    /// All known accounts across all tenants. Survives logout.
    public func listAccounts() -> [CachedAccount] { accountRegistry.listAccounts() }

    /// Accounts that have passkeys and can log in.
    public func listLoginableAccounts() -> [CachedAccount] { accountRegistry.listLoginableAccounts() }

    /// Get a valid access token for authenticated API calls (e.g., IDV backend).
    /// Returns the raw JWT string. Throws if no session is active.
    public func getAccessToken() async throws -> String {
        lock.lock()
        let tokens = authTokens
        lock.unlock()
        guard let tokens else { throw SirosError.auth(message: "No active session") }
        let token = try await tokens.ensureBackendToken()
        return token.raw
    }

    /// Remove a cached account (forgets it from the login screen).
    public func forgetAccount(accountId: String) {
        // Decide before removing: AccountRegistry.removeAccount clears the
        // active id when it points at this account, so checking afterwards
        // never saw a match and the active account was forgotten without a
        // logout, leaving tokens and session state in place.
        let wasActive = accountRegistry.activeAccountId == accountId
        forgetAccountLocally(accountId: accountId)
        if wasActive {
            logout()
        } else {
            // Re-emit state so UI reflects the removed account
            setState(.disconnected(cachedAccounts: accountRegistry.listLoginableAccounts()))
        }
    }

    /// The removal `forgetAccount` performs, without the session teardown it
    /// decides on afterwards.
    ///
    /// The lifecycle-blocked path uses this. It has already run
    /// `endSessionLocally()`, and it must never reach `logout()`: that would
    /// send `DELETE /auth/session`, which the whole blocked path is built to
    /// avoid (see `endSessionLocally()`). Asking `forgetAccount` not to would
    /// mean trusting `activeAccountId` to still be nil after the awaits in
    /// between - and a login started concurrently can put it back.
    // Not `private`: `SirosWallet+SessionLifecycle.swift` needs it - same
    // cross-file-extension-access reason as `keystore` above.
    func forgetAccountLocally(accountId: String) {
        accountRegistry.removeAccount(accountId: accountId)
    }

    // MARK: - Passkey Management

    /// Passkeys registered for the active account.
    public func listPasskeys() -> [CachedPasskey] {
        guard let active = accountRegistry.activeAccountId else { return [] }
        return accountRegistry.findAccount(accountId: active)?.passkeys ?? []
    }

    /// Rename a passkey (local AccountRegistry only).
    public func renamePasskey(credentialId: String, nickname: String) {
        guard let active = accountRegistry.activeAccountId,
              var account = accountRegistry.findAccount(accountId: active) else { return }
        account.passkeys = account.passkeys.map {
            $0.credentialId == credentialId ? CachedPasskey(credentialId: $0.credentialId, prfSalt: $0.prfSalt, nickname: nickname) : $0
        }
        accountRegistry.upsertAccount(account)
    }

    // MARK: - Wallet instance lifecycle (SID-AUTH-06)

    /// This user's wallet instances in the current tenant, from the backend
    /// (`GET /user/session/instances`). One instance per installation; match
    /// an instance to a passkey via `WalletInstance.credentialId` when present.
    /// Requires a backend with go-wallet-backend#319; older backends answer
    /// 404, surfaced as `SirosError.backendApi`.
    public func listWalletInstances() async throws -> [WalletInstance] {
        guard let client = apiClient else { throw SirosError.auth(message: "Not logged in") }
        // Best-effort: `thisInstanceId` reads the WIA this session already
        // holds, so fetch one when there is none yet rather than returning a
        // list in which no row can be marked "this device". A failure here
        // must not fail the listing - ensureWalletInstanceAttestation()
        // already swallows its own errors and returns nil.
        if thisInstanceId == nil { _ = await ensureWalletInstanceAttestation() }
        let selfId = thisInstanceId
        return try await client.listWalletInstances().map { instance in
            var marked = instance
            marked.isThisDevice = selfId != nil && instance.id == selfId
            return marked
        }
    }

    /// This installation's wallet instance id: the JWK thumbprint of its
    /// instance key, which is what the backend registers an instance under and
    /// what this SDK already sends as `wallet_instance_id`. Nil until this
    /// session has obtained a Wallet Instance Attestation (the value is read
    /// from its `cnf.jkt`); `listWalletInstances()` fetches one if needed, so
    /// reading this right after it is the reliable order.
    public var thisInstanceId: String? { instanceKeyThumbprint() }

    // MARK: - Configuration & dependencies

    // Not `private`: `SirosWallet+Issuance.swift`, `SirosWallet+Lifecycle.swift`
    // and `SirosWallet+Engine.swift` (separate files, same module) need it
    // too - same cross-file-extension-access reason as `keystore` above.
    let config: WalletConfig
    // Not `private`: `SirosWallet+Lifecycle.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    let authProvider: AuthProvider
    // Not `private`: `SirosWallet+Issuance.swift` and
    // `SirosWallet+Lifecycle.swift` need it too - same cross-file-
    // extension-access reason as `keystore` above.
    let sessionStore: SessionStoreProtocol
    // Not `private`: `SirosWallet+Renewal.swift` (a separate file, same
    // module) needs it too - Swift's `private` is file-scoped, not
    // module-scoped, matching this file's existing `activeOffer` etc.
    // convention.
    let keystore: KeystoreManager

    /// WSCD hardware-key lifecycle (enroll/rotate/destroy) and
    /// additional-plugin registration (FIDO2 rawSign, R2PS remote HSM) -
    /// `nil` unless `keystore` is WSCD-backed (see `WscdKeystoreAdapter`).
    /// The default JWE-encrypted keystore has no such concept.
    public var wscdManager: WscdManager? { keystore as? WscdManager }

    /// Static feature availability - lets a consumer gate its own UI
    /// without probing by side effect (e.g. attempting a WSCD plugin
    /// registration and catching the resulting error). Reflects what's
    /// *configured*/available on this platform, not runtime
    /// plugin-registration state the app already controls itself (e.g.
    /// whether FIDO2 specifically has been registered on `wscdManager`).
    public var capabilities: WalletCapabilities {
        #if canImport(DeviceCheck)
        let nativeAttestation = AppAttestProvider().isAvailable
        #else
        let nativeAttestation = false
        #endif
        return WalletCapabilities(nativeAttestation: nativeAttestation, wscd: wscdManager != nil)
    }

    /// Read-only snapshot of the persisted WSCD TOFU mapping
    /// (`"issuer|credentialType" -> pluginId`) - lets a host app render/
    /// manage it in its own UI (e.g. a settings screen). See
    /// `WscdSelectionPolicy.currentTofuMapping`'s doc comment. Always empty
    /// when `config.availableKeystores` was never set, since
    /// `WscdSelectionPolicy.resolve` never runs (and so never persists
    /// anything) in that case.
    public var wscdTofuMapping: [String: String] { wscdSelectionPolicy.currentTofuMapping() }

    /// Clears one persisted WSCD TOFU entry - `key` must be exactly one of
    /// `wscdTofuMapping`'s keys. The corresponding (issuer, credentialType)
    /// pair re-resolves (auto-pick/prompt) on its next matching credential
    /// issuance instead of reusing the old choice.
    public func clearWscdTofuMapping(forKey key: String) {
        wscdSelectionPolicy.clearTofuMapping(forKey: key)
    }

    /// Clears every persisted WSCD TOFU entry.
    public func clearAllWscdTofuMappings() {
        wscdSelectionPolicy.clearAllTofuMappings()
    }

    /// Read-only snapshot of every persisted per-(issuer, credentialType)
    /// user override (`"issuer|credentialType" -> pluginId`) - an explicit,
    /// deliberate user preference, distinct from `wscdTofuMapping` (see
    /// `WscdRememberScope`'s doc comment). Mirrors `wscdTofuMapping`'s
    /// pattern exactly.
    public var wscdUserOverrides: [String: String] { wscdSelectionPolicy.currentUserOverrides() }

    /// Sets (or overwrites) an explicit per-(issuer, credentialType) user
    /// preference - outranks TOFU and the global override for this exact
    /// pair on the next matching resolution (see `WscdSelectionPolicy.resolve`).
    public func setWscdUserOverride(issuer: String, credentialType: String, pluginId: String) {
        wscdSelectionPolicy.setUserOverride(issuer: issuer, credentialType: credentialType, pluginId: pluginId)
    }

    /// Clears one persisted per-issuer user override, if present.
    public func clearWscdUserOverride(issuer: String, credentialType: String) {
        wscdSelectionPolicy.clearUserOverride(issuer: issuer, credentialType: credentialType)
    }

    /// The currently persisted global user override (applies to every
    /// issuer/credential type without a more specific per-issuer override),
    /// if any.
    public var wscdGlobalOverride: String? { wscdSelectionPolicy.currentGlobalUserOverride() }

    /// Sets (or overwrites) the single global user override.
    public func setWscdGlobalOverride(pluginId: String) {
        wscdSelectionPolicy.setGlobalUserOverride(pluginId: pluginId)
    }

    /// Clears the global user override, if set.
    public func clearWscdGlobalOverride() {
        wscdSelectionPolicy.clearGlobalUserOverride()
    }

    /// A hardware-backed WSCD plugin's persisted key metadata, synced via
    /// privatedata (see `WscdKeystoreAdapter.exportWscdCredentialsState`'s
    /// doc comment) - `nil` before any key has ever been exported for this
    /// plugin. The host app should pass this to
    /// `WscdManager.registerFido2PluginWithState` instead of
    /// `WscdManager.registerFido2Plugin` whenever it's non-nil, so a key
    /// enrolled on ANY device sharing this account - not just the one that
    /// originally enrolled it - stays addressable. Deliberately NOT backed by
    /// device-local storage: CTAP2 roaming authenticators (e.g. a YubiKey)
    /// are enrolled once but usable from any device.
    public func wscdCredentials(pluginId: String) async -> String? {
        #if canImport(CryptoKit)
        guard let adapter = keystore as? WscdKeystoreAdapter else { return nil }
        return await adapter.exportWscdCredentialsState()[pluginId]
        #else
        // `WscdKeystoreAdapter` is only defined where CryptoKit is
        // available (see its `#if canImport(CryptoKit)` guard) - on other
        // platforms there's no WSCD-backed keystore to read state from.
        return nil
        #endif
    }

    /// Record a WSCD plugin's freshly-exported key metadata (see
    /// `WscdManager.exportFido2State`) and sync it to the backend, so it
    /// survives to the next `wscdCredentials` call on any device sharing
    /// this account. Call after every enrollment/key-generation that could
    /// have changed the plugin's state.
    public func saveWscdCredentials(pluginId: String, state: String) async {
        #if canImport(CryptoKit)
        if let adapter = keystore as? WscdKeystoreAdapter {
            await adapter.setWscdCredentialsState(pluginId: pluginId, state: state)
        }
        #endif
        await persistAndSyncKeystore()
    }

    /// Exposes `authProvider` as a `WscdAutoEnrollHint` when it implements
    /// one - `nil` otherwise (e.g. a host-supplied `AuthProvider` that
    /// doesn't). Intended use: right after a successful `login()`, the host
    /// app checks `wscdAutoEnrollHint()?.suggestsWscdCapableDevice()` to
    /// decide whether to offer enrolling the just-used login credential as a
    /// WSCD signing device - see that protocol's doc comment for why this is
    /// a hint requiring a real (offered, not automatic) enrollment attempt to
    /// confirm, not a guarantee.
    public func wscdAutoEnrollHint() -> WscdAutoEnrollHint? {
        authProvider as? WscdAutoEnrollHint
    }

    // exportCredentialRefreshTokens/setCredentialRefreshToken/
    // removeCredentialRefreshToken (credential re-issuance/renewal plan,
    // Phase 2) now live in SirosWallet+Renewal.swift, alongside the rest of
    // that plan's logic - see this file's `keystore` doc comment for why
    // `keystore` itself had to stay internal (not private).

    let credentialStore: CredentialStore

    /// Write admission around an account wipe; see `TeardownGate`.
    let teardownGate = TeardownGate()

    /// A BBS credential's holder state vault - `nil` unless `keystore`
    /// conforms to `ExtensionStore`. See `removeBbsHolderStateIfAny`.
    let bbsHolderStateVault: BbsHolderStateVault?

    /// Resolves the DID methods the active `config.diipProfile` requires, for
    /// Issuer and Verifier identities. `did:jwk` resolves offline; `did:web`
    /// goes over HTTPS with no wallet credentials attached, since it targets
    /// arbitrary third-party domains.
    /// Not `private`: `SirosWallet+CredentialStatus.swift` needs it - same
    /// cross-file-extension-access reason as `keystore` above.
    let didResolver: DidResolver

    /// Runs DIIP's Validity and Revocation Algorithm. One per wallet
    /// instance, so the Token Status List it fetches is fetched once and
    /// shared by every credential pointing into it.
    let credentialStatusEvaluator: CredentialStatusEvaluator

    /// Statuses evaluated so far, so a UI can read one without re-running the
    /// algorithm per frame.
    let credentialStatusCache = CredentialStatusCache()
    // Not `private`: `SirosWallet+Issuance.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    // `var`, not `let`: the type-metadata tests replace it with one backed by
    // a stub HTTP function, so the wallet's re-resolution against a credential's
    // `vct#integrity` can be driven without the network. Assigned only in
    // `init` otherwise.
    var vctmFetcher: VctmFetcher
    /// The shared, authenticated type-metadata HTTP GET (see
    /// `makeTypeMetadataHttpGet`). NOT used for anything an SCA attestation's
    /// metadata references: those documents go through `transactionResourceGet`,
    /// which carries no credentials.
    let typeMetadataHttpGet: @Sendable (String) async -> String?
    let mddlSchemaFetcher: MddlSchemaFetcher
    // Not `private`: `SirosWallet+Passkey.swift` reads it for the login PRF
    // candidates - same cross-file-extension-access reason as `keystore`.
    let accountRegistry: AccountRegistry

    /// Client for go-zk-circuits' `/v1` REST API, built from
    /// `config.zkCircuitUrls`. Feeds `zkProofSystemRegistry` below.
    public let zkCircuitClient: ZkCircuitClient

    /// Registered ZK proof systems, resolved against a verifier's
    /// `zk_system_type` request in `handleDCAPIRequest`/`handleSignRequest`'s
    /// ZK branches. Empty on non-iOS platforms - `LongfellowZkProofSystem`
    /// wraps the `zk-cred-longfellow` native XCFramework, which only ships
    /// iOS slices (see that type's own `#if os(iOS)` gating) - so a ZK
    /// request simply finds no matching system there, the same "unsupported"
    /// outcome as any other unregistered proof system.
    public let zkProofSystemRegistry: ZkProofSystemRegistry

    #if os(iOS)
    /// Retained here (not just handed to `zkProofSystemRegistry`'s systems'
    /// initializers and otherwise forgotten) so `releaseZkProvers()` has
    /// something to reach - see `ZkProverResidency`'s own doc comment.
    let zkProverResidency: ZkProverResidency
    #endif

    /// go-wallet-backend's credential-type registry service base URL, for
    /// `vctmFetcher`/`mddlSchemaFetcher`'s registry-service fetch strategy.
    /// Uses `config.registryUrl` when the integrator set one explicitly,
    /// otherwise derives it from `config.backendUrl` - the registry route is
    /// mounted under a `/registry` path prefix on the same host/port as the
    /// rest of go-wallet-backend's public API. Not `private` so
    /// `SirosWallet+Notifications.swift` (a separate file, same module) can
    /// use it too, matching `mddlSchemaFetcher`'s own visibility above.
    var resolvedRegistryUrl: String {
        Self.resolveRegistryUrl(config: config)
    }

    // Internal (not private) so `@testable import` can seed a fake client
    // directly, matching this file's existing precedent for other testable
    // internals (e.g. `cachedWia`, `currentWalletInstanceId()`).
    var apiClient: BackendApiClient? {
        // A new, dropped or logged-out backend connection must not inherit
        // decisions the previous one obtained.
        didSet { trustDecisionCache.clear() }
    }
    var engineSession: WalletEngineSession?
    /// Transport-independent notifier for OID4VCI §10 events.
    var credentialNotifier: CredentialNotifier?
    weak var eventListener: WalletEventListener?
    var activeOffer: CredentialOffer?
    var activeVctm: Vctm?

    /// The bytes ``activeVctm`` was parsed from, kept so `vct#integrity` can be
    /// checked against the document as served rather than a re-serialisation.
    var activeVctmDocument: VctmDocument?
    /// The mdoc analogue of `activeVctm` - the currently-in-flight
    /// issuance's `MddlSchema`, when the credential being issued is
    /// `mso_mdoc` rather than SD-JWT. Populated the same way `activeVctm`
    /// is: fetched (best-effort - `nil` on any failure, including a 404
    /// because the offer is actually SD-JWT and has no MDDL schema) via
    /// `mddlSchemaFetcher` at the same call sites `activeVctm` is.
    var activeMddlSchema: MddlSchema?
    /// Resolves which registered WSCD plugin should back credential-
    /// issuance key generation - a no-op unless `config.availableKeystores`
    /// is set. See `WscdSelectionPolicy`'s doc comment.
    // Not `private`: `SirosWallet+Engine.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    let wscdSelectionPolicy: WscdSelectionPolicy
    /// Per-instance device key IDs from the most recent backend Key
    /// Attestation (`attested_keys`, in submission order) - a batch issuer
    /// binds credential `i` in the eventual response to `attested_keys[i]`
    /// (per `requestBackendKeyAttestation`'s doc comment), so
    /// `StoredCredential.kid` for the credential at `StoredCredential.instanceId`
    /// `i` must be `activeAttestedKeyIds[i]` - without this, every signing
    /// operation had no way to know which of the N generated keys a given
    /// batch credential was actually bound to, and silently used an arbitrary
    /// one (see `WscdKeystoreAdapter.selectSigningKey`'s doc comment).
    var activeAttestedKeyIds: [String]?
    /// Ambient (not flow-ID-keyed) guard against overlapping issuance
    /// attempts - set at the top of `startIssuanceByOffer`/`startIssuance`
    /// and checked there too, throwing if already `true`. Not `private` for
    /// the same cross-file-extension-access reason as `activeOffer` etc.
    /// above; guarded by the same `lock`. See `resetIssuanceGuards()` for
    /// why every terminal path must clear it.
    var issuanceInFlight = false
    /// Changed by every `resetIssuanceGuards()` (cancel, logout, error and
    /// completion paths). A `flow_complete` reads it before its first await and
    /// drops itself if it changed: a cancelled flow's completion must not store
    /// credentials, delete a newer renewal's source batch or clear a newer
    /// flow's guards. Guarded by `lock`.
    var issuanceEpoch = 0
    /// Identifies the current issuance start attempt - see
    /// ``IssuanceStartEpoch`` and `SirosWallet+IssuanceStart.swift`.
    let issuanceStartEpoch = IssuanceStartEpoch()
    /// Test seam only: called with a window name from inside the start
    /// state machine's critical sections (`admit.afterGuard`,
    /// `advance.afterCheck`, `fail.afterCheck`), so a test can make another
    /// thread race exactly that window. Never set in production.
    var issuanceStartHook: ((String) -> Void)?
    /// When set, the next `flow_complete` is a renewal's - see
    /// `renewCredential`/`SirosWallet+Notifications.swift`'s `handleFlowComplete`.
    /// Not `private` for the same cross-file-extension-access reason as
    /// `activeOffer` etc. above; guarded by the same `lock`.
    var pendingRenewalSourceBatchId: Int64?
    // Not `private`: `SirosWallet+Lifecycle.swift` and
    // `SirosWallet+Engine.swift` need it too - same cross-file-extension-
    // access reason as `keystore` above.
    var engineTasks: [Task<Void, Never>] = []
    private var _presentationHistory: [PresentationRecord] = []
    /// Stores trust evaluation results keyed by flow ID for use in credential selection UI.
    // Not `private`: `SirosWallet+Engine.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    var lastTrustResults: [String: TrustResult] = [:]
    /// Cached per-flow-id DCQL match results from whichever credential-
    /// matching step actually ran for that flow (`handleCredentialSelection`'s
    /// `"credential_selection"` flow_progress step - the real, live path for
    /// redirect-flow/haip-vp:// presentations - or the legacy engine's own
    /// `handleMatchRequest`). The later `sign_presentation` sign_request step
    /// (`handleSignRequest`) needs this to know the originating query's
    /// `format`/`zkSystemTypes`/`ppidContext` per credential, since its own
    /// `credentials_to_include` wire shape doesn't carry that back. Mirrors
    /// Kotlin's `pendingMatchResultsByFlow` exactly. Entries are removed once
    /// consumed by `handleSignRequest`, or when the flow terminates (see
    /// `handleFlowComplete`/`handleFlowError`/`reportSignFailure`).
    ///
    /// Not `private` - `handleFlowComplete` (in `SirosWallet+Notifications.swift`)
    /// needs to clear it too, the same cross-file-extension-access reason as
    /// `activeOffer`/`activeAttestedKeyIds` etc. above; guarded by the same `lock`.
    var pendingMatchResultsByFlow: [String: [CredentialMatcher.MatchResult]] = [:]
    /// Authorization context captured from a flow's `authorization_required`
    /// progress message, keyed by flow ID - needed to resume issuance via a
    /// fresh `flow_start` once the OAuth browser redirect returns, since the
    /// original flow_id's WebSocket context isn't guaranteed to survive the
    /// round-trip. See `completeAuthorization`.
    // Not `private`: `SirosWallet+Lifecycle.swift` and
    // `SirosWallet+Engine.swift` need it too - same cross-file-extension-
    // access reason as `keystore` above.
    var pendingAuthorizations: [String: PendingAuthorization] = [:]
    /// The one cache for `/v1/evaluate` decisions (see `TrustDecisionCache`).
    // Not `private`: the trust call sites live in several extension files -
    // same cross-file-extension-access reason as `keystore` above.
    let trustDecisionCache: TrustDecisionCache

    /// Test seam: replaces the mdoc `issuerAuth` verification and issuer trust
    /// evaluation the issuance trust gate runs on each issued mdoc, so a test
    /// can drive the gate without CryptoKit or a backend. Nil in production.
    var mdocIssuanceTrustHook: ((CredentialResult) async -> TrustResult?)?

    /// Test seams for `resumeAuthorization`: replace the token step, the reconnect step and the
    /// final `resumeIssuance` send. Nil in production.
    var authorizationResumeTokenHook: (() async throws -> String)?
    var authorizationResumeConnectHook: ((WalletEngineSession) async throws -> Void)?
    var authorizationResumeSendHook: ((Int) -> Void)?

    // New AS-based auth.
    // Not `private`: the wallet instance lifecycle tests replace it with one
    // backed by a stub HTTP function, so the SDK's own re-login after a
    // lifecycle cut-off can be driven to its `403 WALLET_SUSPENDED` /
    // `WALLET_REVOKED` outcome without reaching the network at all.
    var authServerClient: AuthServerClient?
    // Not `private`: `SirosWallet+Lifecycle.swift` and
    // `SirosWallet+Engine.swift` need it too - same cross-file-extension-
    // access reason as `keystore` above.
    var authTokens: AuthTokens?

    /// In-memory cache for this session's Wallet Instance Attestation (WIA) -
    /// refetched when missing or close to expiry (see
    /// `ensureWalletInstanceAttestation`). Not persisted across app restarts:
    /// cheap to reissue given a challenge round trip, unlike the instance KEY
    /// itself (`SessionStoreProtocol.instanceKeyId`), which must stay stable.
    // Internal (not private), matching this file's `handleFlowComplete`
    // convention - lets tests seed a fake WIA directly via `@testable
    // import` rather than driving a full challenge/generateWIA network round
    // trip through a real keystore.
    var cachedWia: String?
    var cachedWiaExpiresAt: Int = 0
    /// Guard behind `beginSelfDrivenRelogin()`; always read and written under
    /// `lock`.
    var reloginInProgress: Bool = false

    /// Which session this wallet currently holds. Bumped whenever one ends
    /// (`logout()`, `destroy()`) or a new one is established (a successful
    /// `login()`/`register()`).
    ///
    /// It is what makes the self-driven re-login *once per session* rather
    /// than once per call: requests issued before a cut-off complete long
    /// after it, and each of their 401s re-enters
    /// `handleReauthenticationRequired()`. Without a generation, every one of
    /// those arriving after `endSelfDrivenRelogin()` would start another
    /// re-login. It also lets `reloginAfterCutOff()` notice that the caller
    /// logged out or destroyed the wallet while it was awaiting the old
    /// session's teardown, instead of resurrecting a session the user ended.
    /// Always read and written under `lock`.
    var sessionGeneration: Int = 0

    /// Whether a self-driven re-login has already been run for the current
    /// ``sessionGeneration``. Cleared by `bumpSessionGeneration()`.
    var reloginDoneForGeneration: Bool = false

    /// Set by `destroy()`. The state is left untouched there (a destroyed
    /// wallet is not a logged-out one), so without this a reauthentication
    /// signal from a task still unwinding could pass the guard and log back in
    /// after the host tore the wallet down.
    var isDestroyed: Bool = false

    /// The in-flight first-use instance-key generation, shared by every caller
    /// so that concurrent first uses cannot mint two different keys. See
    /// `ensureInstanceKeyId()`.
    var instanceKeyTask: Task<String, Error>?
    /// The account `instanceKeyTask` is generating for; a different account
    /// must not share it. See `ensureInstanceKeyId()`.
    var instanceKeyTaskAccount: String?
    /// Identifies which `instanceKeyTask` is current - `Task` is a struct, so
    /// there is no identity to compare.
    var instanceKeyTaskToken: Int = 0

    // Not `private`: `SirosWallet+Engine.swift`'s `connectViaWmp` needs it
    // too - same cross-file-extension-access reason as `keystore` above.
    var wmpPeer: WmpPeer?

    /// Caller holds `lock`.
    func resetPresentationHistoryLocked() { _presentationHistory = [] }

    /// Presentation history — most recent first.
    public var presentationHistory: [PresentationRecord] {
        lock.lock(); defer { lock.unlock() }
        return _presentationHistory
    }

    /// Filters `instances` down to the ones this wallet's own
    /// `credentialConsumptionPolicy` and `presentationHistory` currently
    /// consider eligible (i.e. not yet consumed), AND whose bound signing
    /// key still actually exists in `keystore` - the same computation this
    /// class performs internally before every presentation, exposed as a
    /// convenience so consent/selection UI doesn't need to thread policy,
    /// history, and live key availability through
    /// `CredentialUtils.eligibleInstances` itself.
    ///
    /// The key-availability half of this check exists because a real,
    /// recurring bug (found via live proximity-presentation testing) let a
    /// credential whose signing key was silently lost (e.g. a sync that
    /// never folded a software key into the persisted container - see
    /// privatedata-spec#1/siros-wscd-manager#68 for the deeper architectural
    /// fix) keep reporting "available" under
    /// `CredentialConsumptionPolicy.neverConsume` forever, right up until a
    /// live presentation attempt failed deep inside key selection with no
    /// user-facing signal at all.
    ///
    /// - Parameter isZkPresentation: Per-candidate: will THIS presentation be
    ///   a ZK proof? Callers that know the matched query's format (the DC API
    ///   and engine paths) pass it so `CredentialConsumptionPolicy.consumeNonZkp`
    ///   can tell ZK from raw; the default falls back to the stored format,
    ///   which is never ZK - see `CredentialUtils.eligibleInstances`.
    public func eligibleInstances(
        from instances: [StoredCredential],
        isZkPresentation: ((StoredCredential) -> Bool)? = nil
    ) -> [StoredCredential] {
        let eligible = policyEligibleInstances(from: instances, isZkPresentation: isZkPresentation)
        // A container this build must not rewrite is read-only: a consumption would
        // be recorded in memory only, and reopening would make the used instance
        // eligible again (a one-time-use credential presented twice). So an
        // instance whose presentation would be consumed is not offered.
        guard keystore.unsupportedSchemaVersion != nil else { return eligible }
        switch credentialConsumptionPolicy {
        case .neverConsume: return eligible
        case .consumeAll: return []
        case .consumeNonZkp: return eligible.filter { isZkPresentation?($0) ?? false }
        }
    }

    private func policyEligibleInstances(
        from instances: [StoredCredential],
        isZkPresentation: ((StoredCredential) -> Bool)?
    ) -> [StoredCredential] {
        let keyIds = availableKeyIds
        if let isZkPresentation {
            return CredentialUtils.eligibleInstances(
                instances: instances,
                policy: credentialConsumptionPolicy,
                presentationHistory: presentationHistory,
                availableKeyIds: keyIds,
                isZkPresentation: isZkPresentation
            )
        }
        return CredentialUtils.eligibleInstances(
            instances: instances,
            policy: credentialConsumptionPolicy,
            presentationHistory: presentationHistory,
            availableKeyIds: keyIds
        )
    }

    /// The `kid`s this wallet's keystore can currently sign with - exposed so
    /// consent/selection UI (e.g. a consent screen's exhausted-query
    /// precheck) can compute eligibility ahead of time without a full
    /// `eligibleInstances(from:)` round trip per candidate list. Read live
    /// from `keystore.listKeys()` on every access, never cached: the whole
    /// point of the check is to notice a key that has gone missing.
    public var availableKeyIds: Set<String> {
        Set(keystore.listKeys().map(\.keyId))
    }

    /// Record a new presentation: adds it to the in-memory history and
    /// persists it into the encrypted container (privatedata-spec's
    /// `S.presentations[]`) so `CredentialUtils.groupForDisplay`'s
    /// remaining-copies count survives an app restart instead of resetting
    /// to the full batch size every time - mirrors `deleteCredential`'s
    /// persist-after-mutation pattern.
    // Not `private`: `SirosWallet+DCAPI.swift` and `SirosWallet+Engine.swift`
    // need it too - same cross-file-extension-access reason as `keystore`
    // above.
    /// - Parameter token: captured by the caller before its first `await`. The
    ///   record is applied only while it is current; the check, the in-memory
    ///   insert and the keystore write are one admitted write, which a wipe
    ///   closes and drains, so a handler that resumed after an account deletion
    ///   records nothing. Returns false when it was refused.
    @discardableResult
    func recordPresentation(_ record: PresentationRecord, token: TeardownToken) async -> Bool {
        lock.lock()
        let current = isCurrentLocked(token)
        lock.unlock()
        guard current else { return false }
        let applied: Bool? = await teardownGate.admit(token.ticket) { [self] in
            lock.lock()
            guard isCurrentLocked(token) else { lock.unlock(); return false }
            _presentationHistory.insert(record, at: 0)
            lock.unlock()
            if keystore.isUnlocked,
               let data = try? JSONEncoder().encode(record), let raw = String(data: data, encoding: .utf8) {
                try? await keystore.savePresentationRecord(id: record.id, json: raw)
            }
            return true
        }
        guard applied == true else { return false }
        if keystore.isUnlocked { await persistAndSyncKeystore() }
        await checkRenewThresholds(consumedCredentialIds: record.credentialIds)
        return true
    }

    /// Per-credential-configuration-id override for
    /// `CredentialUtils.renewThreshold` (plan §4.3: "near-expiry threshold
    /// is a per-credential user preference," not a global constant). Not
    /// durably persisted in this pass - callers wanting persistence across
    /// restarts should re-set this on wallet construction from their own
    /// settings store, matching how `credentialConsumptionPolicy` itself is
    /// currently handled.
    public var renewThresholds: [String: Int] = [:]
    // `renewThresholdFor`/`checkRenewThresholds` that read this live in
    // `SirosWallet+Renewal.swift` (credential re-issuance/renewal plan,
    // Phase 2) - kept together with the rest of that plan's logic; this
    // stored property itself has to stay here since Swift extensions can't
    // add stored properties to a type.

    /// Reload presentation history from the encrypted container after unlock.
    private func reloadPresentationHistory() async {
        guard let allRaw = try? await keystore.getAllPresentationRecords() else { return }
        let decoder = JSONDecoder()
        let records = allRaw.values.compactMap { raw in
            try? decoder.decode(PresentationRecord.self, from: Data(raw.utf8))
        }.sorted(by: { $0.timestamp > $1.timestamp })
        lock.lock()
        _presentationHistory = records
        lock.unlock()
    }

    /// Factory for creating engine sessions (injectable for testing).
    public static var createEngineSession: @Sendable (String, String) -> WalletEngineSession = { baseUrl, tenantId in
        WalletEngineSession(baseUrl: baseUrl, tenantId: tenantId)
    }

    static let hkdfInfo = "eDiplomas PRF"

    // MARK: - Init

    /// Create a new wallet instance.
    ///
    /// - Parameters:
    ///   - config: backend URL, tenant ID, etc.
    ///   - authProvider: platform-specific WebAuthn/passkey implementation.
    ///   - sessionStore: persistent session storage. Defaults to in-memory.
    ///   - keystore: encrypted keystore. Defaults to JweKeystore on Apple platforms.
    ///     On Linux, you **must** provide a custom `KeystoreManager`.
    ///   - accountRegistry: the cross-logout account cache. Defaults to the
    ///     Keychain-backed registry; pass `AccountRegistry.inMemory()` in tests.
    /// - Returns: `nil` if no keystore is available (Linux without custom keystore).
    public init?(
        config: WalletConfig,
        authProvider: AuthProvider,
        sessionStore: SessionStoreProtocol = InMemorySessionStore(),
        keystore: KeystoreManager? = nil,
        accountRegistry: AccountRegistry? = nil
    ) {
        self.config = config
        self.trustDecisionCache = TrustDecisionCache(ttl: config.trustDecisionCacheTtl)
        self.transactionDataEnabledValue = config.transactionDataEnabled
        self.authProvider = authProvider
        self.sessionStore = sessionStore

        #if canImport(CryptoKit)
        // The profile has to reach the default keystore, or a wallet
        // configured for DIIP generates keys with no did:jwk identity and then
        // silently falls back to a HAIP-shaped proof - the configuration would
        // look applied and do nothing. A host-supplied keystore carries its own.
        self.keystore = keystore ?? JweKeystore(profile: config.interopProfile)
        #else
        guard let ks = keystore else {
            return nil
        }
        self.keystore = ks
        #endif

        self.credentialStore = config.credentialStore ?? KeystoreBackedCredentialStore(keystore: self.keystore)
        self.bbsHolderStateVault = (self.keystore as? ExtensionStore).map { BbsHolderStateVault(keystore: $0) }

        // Set up new AS-based auth. Moved ahead of the DID resolver below
        // (it used to follow it) so `tokens` already exists to authenticate
        // the resolver's own `BackendApiClient` - captured directly, the
        // same way `typeMetadataGet`'s `makeTypeMetadataHttpGet` call
        // captures it further down, not via `self.authTokens` (`self` isn't
        // fully initialized yet at this point in `init`).
        let asClient = AuthServerClient(baseUrl: config.backendUrl, tenantId: config.tenantId, httpFn: Self.defaultHttpFn)
        self.authServerClient = asClient
        let tokens = AuthTokens(authServerClient: asClient, tenantId: config.tenantId)
        self.authTokens = tokens

        // `did:jwk` resolves offline inside the resolver; everything else is
        // handed to the backend, which delegates to go-trust. Which document
        // is authoritative for an identifier is a trust decision, and it is
        // not this wallet's to make by fetching whatever a domain serves.
        let backendUrl = config.backendUrl
        let tenantId = config.tenantId
        let diipProfile = config.diipProfile
        let resolver = DidResolver(profile: config.diipProfile) { did in
            let client = BackendApiClient(
                baseUrl: backendUrl,
                tenantId: tenantId,
                httpFn: SirosWallet.defaultHttpFn
            )
            // Without this, every non-did:jwk resolution is unauthenticated
            // and `/v1/resolve` refuses it outright (review finding) - DID
            // resolution needs the same bearer token every other backend
            // REST call does, not a bespoke unauthenticated client.
            client.setAuthTokens(tokens)
            return try? await client.resolveDid(did)
        }
        self.didResolver = resolver
        self.credentialStatusEvaluator = CredentialStatusEvaluator(
            statusListClient: TokenStatusListClient(
                httpGet: { url, headers in
                    await SirosWallet.fetchPublicUrl(url, headers: headers)
                },
                resolveIssuerKey: { issuer, kid in
                    await SirosWallet.resolveIssuerSigningKey(
                        issuer: issuer, kid: kid, resolver: resolver, profile: diipProfile
                    )
                }
            ),
            clockTolerance: config.clockTolerance
        )

        self.accountRegistry = accountRegistry ?? AccountRegistry()

        self.wscdSelectionPolicy = WscdSelectionPolicy(
            sessionStore: sessionStore,
            defaultMapping: config.defaultWscdMapping,
            requestChoice: config.requestWscdChoice
        )

        // Shared HTTP GET for both type-metadata fetchers - see
        // `makeTypeMetadataHttpGet`'s doc comment for why the auth headers
        // are conditional on the target URL. Captures `config`, `tokens`,
        // and the `sessionStore` parameter directly (not `self`) - both
        // `resolvedRegistryUrl` and `authTokens` are invariant for this
        // wallet instance's whole lifetime (derived from/aliasing the `let
        // config` below and the local `tokens` just assigned to
        // `self.authTokens` above, never reassigned afterwards), so there's
        // no need to read them via `self` later. This also has to run
        // BEFORE `tokens.onSessionRejected` below: that closure captures
        // `self`, and Swift requires every stored property - including
        // `vctmFetcher`/`mddlSchemaFetcher`, assigned here - to already be
        // initialized before `self` can be captured anywhere in `init`.
        let typeMetadataGet = Self.makeTypeMetadataHttpGet(
            registryUrl: Self.resolveRegistryUrl(config: config),
            tenantId: config.tenantId,
            authTokens: tokens,
            sessionStore: sessionStore
        )
        self.vctmFetcher = VctmFetcher(httpGet: typeMetadataGet)
        self.typeMetadataHttpGet = typeMetadataGet
        self.mddlSchemaFetcher = MddlSchemaFetcher(httpGet: typeMetadataGet)
        self.zkCircuitClient = ZkCircuitClient(sources: config.zkCircuitUrls)

        #if os(iOS)
        // See `makeIOSZkProofSystemRegistry`'s own doc comment for how the
        // registry and residency are assembled.
        let (zkProofSystemRegistry, zkProverResidency) = Self.makeIOSZkProofSystemRegistry(
            config: config,
            credentialStore: self.credentialStore,
            zkCircuitClient: self.zkCircuitClient,
            bbsHolderStateVault: self.bbsHolderStateVault
        )
        self.zkProverResidency = zkProverResidency
        self.zkProofSystemRegistry = zkProofSystemRegistry
        #else
        // Longfellow/Vega/BBS are all iOS-only (each one's native
        // XCFramework ships no macOS/Linux slice - see Package.swift), so
        // there is nothing to register on this platform.
        self.zkProofSystemRegistry = ZkProofSystemRegistry(systems: [])
        #endif

        tokens.onSessionRejected = { [weak self] in
            self?.handleReauthenticationRequired()
        }
    }

    /// Same derivation as the `resolvedRegistryUrl` instance property below,
    /// factored out as a `static` so it can be computed in `init` before
    /// `self` is fully initialized (see `makeTypeMetadataHttpGet` call site).
    private static func resolveRegistryUrl(config: WalletConfig) -> String {
        if let registryUrl = config.registryUrl { return registryUrl }
        let trimmedBackendUrl = config.backendUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return "\(trimmedBackendUrl)/registry"
    }

    /// Fires whenever ANY code path determines the current session is no
    /// longer valid and can't be silently refreshed - repeated REST 401s
    /// (`AuthTokens.onSessionRejected`) or the engine WebSocket's token
    /// refresh failing before a reconnect (`WalletEngineSession.State
    /// .reauthRequired`, observed via the engine's `stateStream` in
    /// `connectEngine`). Notifies the host app via
    /// `WalletEventListener.onReauthenticationRequired` - distinct from
    /// `onFlowError` - and then attempts one login itself (SID-AUTH-06: a
    /// lifecycle cut-off is indistinguishable from an expired session until
    /// that login is refused with `WALLET_SUSPENDED` / `WALLET_REVOKED`).
    ///
    /// The listener is therefore told, not asked: it should route its UI to a
    /// login/progress screen and wait for the state to change, and must NOT
    /// start a login of its own - two concurrent ceremonies would race on the
    /// session store, the wallet state and the engine session. See
    /// `WalletEventListener.onReauthenticationRequired()`.
    // Not `private`: `SirosWallet+Engine.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    func handleReauthenticationRequired() {
        guard let generation = beginSelfDrivenRelogin() else { return }
        lock.lock()
        let listener = eventListener
        lock.unlock()
        // The host hook stays: apps that drive their own prompt still get
        // told, and it fires before the SDK's attempt so a host that routes to
        // its login screen sees the same ordering as before this change.
        listener?.onReauthenticationRequired()
        Task { [weak self] in
            guard let self else { return }
            // A cut-off (SID-AUTH-06) looks exactly like an expired session
            // from here; the difference only shows in the login that follows,
            // which is refused with WALLET_SUSPENDED / WALLET_REVOKED. Attempt
            // it once - never in a loop - so the state machine converges
            // without host code.
            await self.reloginAfterCutOff(replacing: generation)
            self.endSelfDrivenRelogin()
        }
    }

    // MARK: - Event listener

    /// Set a listener for events that require user interaction.
    public func setEventListener(_ listener: WalletEventListener?) {
        lock.lock(); defer { lock.unlock() }
        eventListener = listener
    }

    /// Governs whether a successful presentation exhausts the credential
    /// instance it used (see `CredentialUtils.eligibleInstances`). Defaults
    /// to `.neverConsume` so existing behavior doesn't change until a host
    /// app opts in. This is core wallet policy, not a UI-only preference -
    /// the host app is responsible for persisting the user's choice across
    /// restarts and setting it here on startup.
    public var credentialConsumptionPolicy: CredentialConsumptionPolicy = .neverConsume

    // MARK: - Registration

    /// Register a new user with a passkey.
    ///
    /// 1. Gets a registration challenge from the backend.
    /// 2. Creates a passkey via the system UI (with PRF extension).
    /// 3. Derives an encryption key from the PRF output.
    /// 4. Initialises an empty encrypted keystore.
    /// 5. Sends the encrypted keystore to the backend as privateData.
    /// 6. Opens the engine WebSocket.
    public func register(displayName: String) async throws {
        precondition(!displayName.isEmpty && displayName.count <= 256, "displayName must be 1-256 characters")
        guard let asClient = authServerClient, let tokens = authTokens else {
            throw SirosError.wallet(message: "AuthServerClient not initialized")
        }
        await reopenForNewSession()
        setState(.connecting)
        // See logout()'s identical reset: this enrollment gets its own
        // instance key, so any WIA still cached from an earlier account must
        // not be what identifies this device afterwards.
        lock.lock(); cachedWia = nil; cachedWiaExpiresAt = 0; lock.unlock()
        do {
            let prfSalt = Self.randomBytes(32)
            let hkdfSalt = Self.randomBytes(32)
            let hkdfInfo = Data(Self.hkdfInfo.utf8)

            // Step 1: Get challenge from AS
            let challengeResponse = try await asClient.registerBegin()
            guard let challengeId = challengeResponse["challengeId"] as? String else {
                throw SirosError.auth(message: "Missing challengeId")
            }
            guard let createOptions = challengeResponse["createOptions"] as? [String: Any],
                  let publicKey = createOptions["publicKey"] as? [String: Any] else {
                throw SirosError.auth(message: "Missing createOptions.publicKey")
            }
            guard let rpObj = publicKey["rp"] as? [String: Any],
                  let rpId = rpObj["id"] as? String else {
                throw SirosError.auth(message: "Missing rp.id")
            }
            let rpName = rpObj["name"] as? String ?? rpId
            guard let challengeB64 = publicKey["challenge"] as? String,
                  let challenge = Self.b64UrlDecode(challengeB64) else {
                throw SirosError.auth(message: "Missing challenge")
            }
            guard let userObj = publicKey["user"] as? [String: Any],
                  let userIdB64 = userObj["id"] as? String,
                  let userId = Self.b64UrlDecode(userIdB64) else {
                throw SirosError.auth(message: "Missing user.id")
            }
            let userName = userObj["name"] as? String ?? displayName

            // Step 2: Create credential via platform AuthProvider
            let result = try await authProvider.register(options: RegisterOptions(
                rpId: rpId,
                rpName: rpName,
                userId: userId,
                userName: userName,
                userDisplayName: displayName,
                challenge: challenge,
                prfSalt: prfSalt
            ))

            // Step 3: Complete registration with AS
            let credential: [String: Any] = [
                "id": Self.b64UrlEncode(result.credentialId),
                "rawId": Self.b64UrlEncode(result.credentialId),
                "type": "public-key",
                "response": [
                    "attestationObject": Self.b64UrlEncode(result.attestationObject),
                    "clientDataJSON": Self.b64UrlEncode(result.clientDataJSON),
                ],
            ]
            // Resolved BEFORE registerFinish: getPrfOutput fails closed for an
            // authenticator without PRF, and failing here leaves only a stray
            // local passkey behind rather than a server-side enrollment with no
            // container behind it.
            let prfOutput = try await resolvePrfOutput(
                ceremonyPrf: result.prfOutput, credentialId: result.credentialId, salt: prfSalt
            )

            let session = try await asClient.registerFinish(
                challengeId: challengeId,
                credential: credential,
                displayName: displayName
            )

            // prfSalt must land in the new PrfKeyInfo, not a random value.
            try await keystore.unlock(
                prfOutput: prfOutput.first,
                encryptedContainer: Data(),
                hkdfSalt: hkdfSalt,
                hkdfInfo: hkdfInfo,
                prfSalt: prfSalt
            )

            let encryptedContainer = try await keystore.exportEncryptedContainer()

            // Register account in the persistent registry (survives logout)
            let accountId = "\(config.tenantId):\(session.uuid)"
            let credIdStr = Self.b64UrlEncode(result.credentialId)
            accountRegistry.upsertAccount(CachedAccount(
                userId: session.uuid,
                tenantId: config.tenantId,
                displayName: displayName,
                backendUrl: config.backendUrl,
                passkeys: [CachedPasskey(
                    credentialId: credIdStr,
                    prfSalt: Self.b64Encode(prfSalt)
                )],
                hkdfSalt: Self.b64Encode(hkdfSalt),
                hkdfInfo: Self.b64Encode(hkdfInfo)
            ))
            accountRegistry.activeAccountId = accountId

            // Scope session store to this account
            sessionStore.activeAccountId = accountId
            sessionStore.userId = session.uuid
            sessionStore.displayName = session.displayName
            sessionStore.tenantId = config.tenantId
            sessionStore.prfSalt = Self.b64Encode(prfSalt)
            sessionStore.hkdfSalt = Self.b64Encode(hkdfSalt)
            sessionStore.hkdfInfo = Self.b64Encode(hkdfInfo)
            // The passkey this installation logs in with. `generateWIA` sends
            // it as `credential_id` so the backend can bind this wallet
            // instance to it and refuse the same passkey at login once the
            // instance is suspended or revoked (SID-AUTH-06). Nothing else
            // writes it, so without this the link is never recorded at all.
            sessionStore.credentialId = credIdStr
            sessionStore.privateDataJwe = String(data: encryptedContainer, encoding: .utf8)

            setupApiClientWithTokens(tokens)
            try await syncPrivateDataToBackend()
            try await connectEngineWithToken(tokens)

            // See login()'s identical bump: a new session.
            bumpSessionGeneration()
            let creds = await credentialStore.getAll()
            setState(.ready(userId: session.uuid, displayName: session.displayName, credentials: creds))
        } catch let e as SirosError {
            #if canImport(os)
            logger.error("Registration failed: \(e.localizedDescription)")
            #endif
            rollbackLocalCredential()
            setState(.error(message: e.localizedDescription))
        } catch {
            #if canImport(os)
            logger.error("Registration failed: \(error.localizedDescription)")
            #endif
            rollbackLocalCredential()
            setState(.error(message: error.localizedDescription))
            throw SirosError.wallet(message: "Registration failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Login

    /// Login with an existing passkey.
    public func login() async throws {
        // A user-driven login answers only for itself: until its passkey
        // resolves to an account, a `.deactivated` refusal has nothing it may
        // forget. The registry's active account is not an answer here - it
        // belongs to whatever session came before, possibly another user.
        try await login(refusalAccountId: nil)
    }

    /// `login()`, told which account a lifecycle refusal is about while the
    /// ceremony has not yet identified one itself.
    ///
    /// Only the SDK's own re-login after a token cut-off has one: it replaces
    /// a session whose account it captured before its teardown began, and a
    /// refusal arriving before the passkey ceremony completes is unambiguously
    /// about that account. See `handleLifecycleRefusal(_:forAccount:)`.
    func login(refusalAccountId: String?) async throws {
        guard let asClient = authServerClient, let tokens = authTokens else {
            throw SirosError.wallet(message: "AuthServerClient not initialized")
        }
        // A new session: admits writes again if an account wipe had closed them (waits for one still running).
        await reopenForNewSession()
        setState(.connecting)
        // See logout()'s identical reset: a WIA still cached from another
        // account (or from before a re-enrollment) must not be what identifies
        // this device once this login resolves.
        lock.lock(); cachedWia = nil; cachedWiaExpiresAt = 0; lock.unlock()
        // Which account this login is for, as soon as the passkey resolves to
        // one. `accountRegistry.activeAccountId` is deliberately not moved
        // until the unlock below has succeeded, so it cannot answer that for a
        // login refused by `loginFinish` - and for a user-driven login the
        // account it still names is the *previous* session's. So until the
        // ceremony identifies one, this is whatever the caller vouched for.
        // See `handleLifecycleRefusal(_:forAccount:)`.
        var loginAccountId = refusalAccountId
        do {
            // Steps 1-2: challenge, passkey assertion, PRF (handled below).
            let assertion = try await performPasskeyAssertion(asClient: asClient)
            loginAccountId = accountId(owningInScope: assertion.credentialId)

            // Step 3: Complete login with AS
            let session = try await asClient.loginFinish(
                challengeId: assertion.challengeId,
                credential: assertion.credential
            )

            // Scope the session store to the account the server confirmed,
            // BEFORE anything is read from or written to it: the store may
            // still be scoped to a previous account (or to none, after
            // logout), and `fetchPrivateData` writes the container it fetches
            // into the active scope. The registry's active account is only
            // moved once the unlock has succeeded.
            let accountId = "\(config.tenantId):\(session.uuid)"
            sessionStore.activeAccountId = accountId
            // Now the server has named the account, so a refusal from anything
            // below this line is unambiguously about it.
            loginAccountId = accountId

            setupApiClientWithTokens(tokens)
            let privateData = try await fetchPrivateData()

            // PRF/HKDF parameters, normal or recovered - see `resolveLoginPrf`.
            let cached = assertion.cachedAccount.flatMap { $0.accountId == accountId ? $0 : nil }
            let resolved = try await resolveLoginPrf(assertion: assertion, privateData: privateData, cachedAccount: cached)

            try await keystore.unlock(
                prfOutput: resolved.prfOutput.first,
                encryptedContainer: privateData,
                hkdfSalt: resolved.hkdfSalt,
                hkdfInfo: resolved.hkdfInfo,
                prfSalt: resolved.prfSalt
            )

            // Records credentialId/salts and heals the account cache on
            // recovery - see `recordSuccessfulLogin`.
            recordSuccessfulLogin(
                accountId: accountId, session: session, assertion: assertion,
                prfSaltBytes: resolved.prfSalt, hkdfSalt: resolved.hkdfSalt, hkdfInfo: resolved.hkdfInfo,
                recoveredSalt: resolved.recoveredSalt
            )

            try await connectEngineWithToken(tokens)

            // A new session: a cut-off met on THIS one deserves its own
            // self-driven re-login, and the 401s of the session it replaced
            // no longer do.
            bumpSessionGeneration()
            let creds = await credentialStore.getAll()
            setState(.ready(userId: session.uuid, displayName: session.displayName, credentials: creds))
            await reloadPresentationHistory()
        } catch let e as SirosError {
            // A SID-AUTH-06 refusal is a state, not an error: this passkey's
            // wallet instance is suspended or the wallet was deactivated, and
            // retrying the same login changes nothing until someone else acts.
            if await handleLifecycleRefusal(e, forAccount: loginAccountId) { return }
            #if canImport(os)
            logger.error("Login failed: \(e.localizedDescription)")
            #endif
            setState(.error(message: e.localizedDescription))
        } catch {
            if await handleLifecycleRefusal(error, forAccount: loginAccountId) { return }
            #if canImport(os)
            logger.error("Login failed: \(error.localizedDescription)")
            #endif
            setState(.error(message: error.localizedDescription))
            throw SirosError.wallet(message: "Login failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Logout

    /// Disconnect, lock keystore, clear session.
    public func logout() {
        endSessionLocally()
        // Ending the server session too is what makes this a logout rather
        // than a local teardown. Fire-and-forget is safe *here* because the
        // wallet then sits on the login screen: any login that follows is a
        // deliberate user action far removed from this DELETE. It is NOT safe
        // on the lifecycle-blocked path, where the app may retry within
        // milliseconds - see `endSessionLocally()`'s doc comment.
        Task {
            try? await authServerClient?.logout()
        }
        setState(.disconnected(cachedAccounts: accountRegistry.listLoginableAccounts()))
    }

    /// Drops every credential-status cache so neither survives a session
    /// boundary (review finding): shared by every teardown path that ends or
    /// replaces a session, not just `endSessionLocally()` - `reloginAfterCutOff`
    /// used to perform its own, separate teardown that skipped this entirely,
    /// so a cut-off-triggered self-driven re-login could reuse a prior
    /// session's no-TTL Status List Token cache and miss a revocation
    /// published since.
    ///
    /// Account-scoped, like the session itself: without this,
    /// `cachedCredentialStatus(of:)` could answer with the PREVIOUS account's
    /// status - or a deleted credential's - until the next account's own
    /// `refreshCredentialStatuses()` happens to overwrite the same id.
    /// `credentialStatusCache` only holds the last-computed UI-facing result,
    /// but `credentialStatusEvaluator`'s own `TokenStatusListClient` caches
    /// the fetched Status List Tokens those results came from - with no ttl
    /// (or a long one), a cached token can survive this boundary and be
    /// reused for the next account's credentials. An in-flight evaluation
    /// from the ending session could otherwise also repopulate
    /// `credentialStatusCache` right after this clears it, so both are
    /// cleared together, in the same place, rather than relying on whatever
    /// engine/task cancellation the caller already did to have stopped
    /// everything that could still be running one.
    func clearCredentialStatusCaches() {
        credentialStatusCache.clear()
        let evaluator = credentialStatusEvaluator
        Task { await evaluator.clearCache() }
    }

    /// ``clearCredentialStatusCaches()``, but AWAITED rather than fired
    /// fire-and-forget (review finding): that version is safe for `logout()`/
    /// `destroy()` - both public, synchronous APIs this SDK cannot change the
    /// signature of - because a human-paced, deliberate action (the user
    /// manually logging back in) always follows, not a race-prone
    /// programmatic retry. `reloginAfterCutOff` is different: it is a SELF-
    /// DRIVEN re-login that calls `login()` itself moments later, with no
    /// human pacing gap, so the fire-and-forget version's race - a new
    /// session's `refreshCredentialStatuses()` reaching the evaluator before
    /// its unawaited clear completes, serving the superseded session's
    /// cached Status List Token - is real there in a way it is not for a
    /// human re-logging in by hand. Any caller that is already `async` and
    /// about to start a new session right after should use this instead.
    func clearCredentialStatusCachesAwaited() async {
        credentialStatusCache.clear()
        await credentialStatusEvaluator.clearCache()
    }

    /// Everything `logout()` does except ending the server session: drop the
    /// engine, the WMP peer, the API client, the cached tokens, the keystore
    /// and the account-scoped session, and end this session's generation.
    ///
    /// The lifecycle-blocked path uses this rather than `logout()`. A
    /// suspended instance is reactivated from another device and the app then
    /// retries `login()`, which reuses the same AS session cookie - an
    /// unawaited `DELETE /auth/session` from the block could land *after* that
    /// `loginFinish` and invalidate the session the retry had just
    /// established. There is also nothing to end: the backend has already
    /// refused this installation.
    func endSessionLocally() {
        lock.lock()
        let engine = engineSession
        let peer = wmpPeer
        engineSession = nil
        wmpPeer = nil
        credentialNotifier = nil
        apiClient = nil
        lock.unlock()
        engine?.disconnect()
        if let peer { Task { try? await peer.close() } }
        cancelEngineTasks()
        releaseZkProvers()
        keystore.lock()
        resetDefaultTransactionLogStore()
        sessionStore.clear()  // clears active account's session only
        accountRegistry.activeAccountId = nil
        authTokens?.clear()
        clearCredentialStatusCaches()
        // The WIA cache is wallet-wide but the instance key it attests is
        // account-scoped, so a WIA kept across a logout would answer
        // `thisInstanceId` (and `wallet_instance_id`) with the PREVIOUS
        // account's thumbprint for the next one. It is cheap to reissue.
        lock.lock(); cachedWia = nil; cachedWiaExpiresAt = 0; lock.unlock()
        // This session is over: a 401 still in flight from it must not be
        // taken for a cut-off worth re-logging in from, and a self-driven
        // re-login awaiting the old session's teardown must abandon rather
        // than resurrect what the user just ended.
        bumpSessionGeneration()
    }

    // MARK: - Session resume

    /// Resume a previous session without requiring a new WebAuthn assertion.
    public func resumeSession() async {
        await reopenForNewSession()
        // Restore the active account ID so the session store reads the right data
        let resumingAccountId = accountRegistry.activeAccountId
        if let resumingAccountId {
            sessionStore.activeAccountId = resumingAccountId
        }
        guard let userId = sessionStore.userId, let tokens = authTokens else { return }
        setState(.connecting)
        do {
            let displayName = sessionStore.displayName

            setupApiClientWithTokens(tokens)

            // Verify the session is still valid by requesting a backend token
            do {
                _ = try await tokens.ensureBackendToken()
            } catch {
                if await handleLifecycleRefusal(error, forAccount: resumingAccountId) { return }
                sessionStore.clear()
                lock.lock(); apiClient = nil; lock.unlock()
                setState(.disconnected(cachedAccounts: accountRegistry.listLoginableAccounts()))
                return
            }

            try await connectEngineWithToken(tokens)

            let storedJwe = sessionStore.privateDataJwe
            let hkdfSalt = sessionStore.hkdfSalt.flatMap { Self.b64Decode($0) }
            let hkdfInfo = sessionStore.hkdfInfo.flatMap { Self.b64Decode($0) }

            if storedJwe != nil, hkdfSalt != nil, hkdfInfo != nil {
                setState(.keystoreLocked(userId: userId, displayName: displayName))
            } else {
                setState(.ready(userId: userId, displayName: displayName, credentials: []))
            }
        } catch {
            if await handleLifecycleRefusal(error, forAccount: resumingAccountId) { return }
            setState(.disconnected(cachedAccounts: accountRegistry.listLoginableAccounts()))
        }
    }

    // MARK: - Keystore unlock

    /// Unlock the keystore after a session resume.
    public func unlockKeystore() async throws {
        guard case .keystoreLocked(let userId, let displayName) = state,
              let asClient = authServerClient else { return }
        // The account being unlocked, captured before the ceremony: a refusal
        // arrives after it, and the registry is mutable in between. See
        // `handleLifecycleRefusal(_:forAccount:)`.
        let unlockingAccountId = accountRegistry.activeAccountId
        do {
            // Use AS login to get PRF output via biometric assertion, then
            // complete it (refreshes the session cookie). Candidates are scoped
            // to the resumed account: its container is what gets unwrapped, so
            // another account's passkey must not be offered here.
            let assertion = try await performPasskeyAssertion(
                asClient: asClient, accountId: sessionStore.activeAccountId
            )
            _ = try await asClient.loginFinish(
                challengeId: assertion.challengeId,
                credential: assertion.credential
            )
            // Same reason as login()/register(): this is also a completed
            // passkey ceremony, and a session resumed from an older SDK (or
            // one whose stored id went stale) would otherwise reach WIA
            // generation with no `credential_id` to bind the instance to.
            // The store is already scoped to the resumed account here.
            if let credentialId = assertion.credential["id"] as? String {
                sessionStore.credentialId = credentialId
            }

            guard let storedJwe = sessionStore.privateDataJwe else {
                throw SirosError.keystore(message: "Missing private data")
            }
            let storedContainer = Data(storedJwe.utf8)
            let resolved = try await resolveUnlockKeystorePrf(assertion: assertion, storedContainer: storedContainer)

            try await keystore.unlock(
                prfOutput: resolved.prfOutput.first,
                encryptedContainer: storedContainer,
                hkdfSalt: resolved.hkdfSalt,
                hkdfInfo: resolved.hkdfInfo
            )

            if let recoveredSalt = resolved.recoveredSalt, let accountId = sessionStore.activeAccountId {
                healAccountCache(
                    accountId: accountId, userId: userId, displayName: displayName,
                    credentialId: assertion.credentialId, prfSalt: recoveredSalt,
                    hkdfSalt: resolved.hkdfSalt, hkdfInfo: resolved.hkdfInfo
                )
            }

            let creds = await credentialStore.getAll()
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
            await reloadPresentationHistory()
        } catch {
            if await handleLifecycleRefusal(error, forAccount: unlockingAccountId) { return }
            setState(.error(message: error.localizedDescription))
        }
    }

    // MARK: - Credentials
    //
    // getCredentials/deleteCredential moved to
    // SirosWallet+CredentialLifecycle.swift (file_length gate - review
    // finding on PR #194, which also added deleteCredential's BBS-vault
    // cleanup call; see that file).
}
