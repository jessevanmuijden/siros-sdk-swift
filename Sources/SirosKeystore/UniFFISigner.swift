// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// siros_wscd_managerFFI's XCFramework only ships iOS slices - no macOS
// slice exists, and this package's CI builds/tests on bare macOS too, so
// this entire file (which exists solely to bridge to that module) is
// iOS-only. See Package.swift's SirosKeystore target for the matching
// platform-scoped dependency.
#if os(iOS)
import siros_wscd_managerFFI

/// Provides user authentication credentials when requested by the WSCD.
///
/// Implement this protocol in the wallet application to handle
/// PIN entry prompts and WebAuthn assertion ceremonies during
/// signing operations that require 2FA (e.g. R2PS remote signing).
///
/// Note: These methods are called synchronously from the FFI queue.
/// Implementations that show UI should use platform mechanisms to
/// block until the user completes the interaction.
public protocol WscdAuthProvider: AnyObject, Sendable {
    /// Request the user's PIN (e.g. for OPAQUE authentication, or a CTAP2
    /// authenticator's ClientPin).
    /// - Parameter pluginId: Which registered WSCD plugin (e.g. "fido2",
    ///   "r2ps") is asking - a single `WscdAuthProvider` can back multiple
    ///   plugins with very different PIN semantics (a real hardware secret
    ///   vs. a fixed debug-only test value), so implementations MUST
    ///   dispatch on this rather than guessing from ambient app/UI state.
    ///   Confirmed via live hardware testing on the Kotlin SDK: guessing
    ///   from a "currently selected dev-screen tab" signal silently sent
    ///   the wrong plugin's PIN to a real YubiKey for an entire session,
    ///   which the authenticator correctly rejected every time with no
    ///   indication of the real cause.
    /// - Returns: The PIN as raw bytes (UTF-8 encoded).
    /// - Throws: If the user cancels.
    func requestPin(pluginId: String) throws -> Data

    /// Request a WebAuthn assertion.
    /// - Parameters:
    ///   - pluginId: Which registered WSCD plugin is asking - see
    ///     `requestPin`'s doc comment for why implementations must
    ///     dispatch on this rather than guessing.
    ///   - challenge: The authentication challenge bytes.
    ///   - rpId: The Relying Party ID.
    ///   - allowedCredentials: List of allowed credential IDs.
    /// - Returns: The CBOR-encoded authenticator assertion response.
    /// - Throws: If the user cancels or no credential is available.
    func requestWebauthnAssertion(
        pluginId: String,
        challenge: Data,
        rpId: String,
        allowedCredentials: [Data]
    ) throws -> Data
}

/// `UniFFISigner` wraps the Rust `siros-wscd-manager` UniFFI bindings
/// into the SDK's `Signer` protocol.
///
/// This enables the native SDK to use any WSCD plugin (softkey, R2PS,
/// FIDO2) through the same interface used by the software `JweKeystore`.
///
/// Usage:
/// ```swift
/// let config = FfiWscdConfig(defaultPlugin: "softkey")
/// let signer = try UniFFISigner(config: config)
/// let keystore = WscdKeystoreAdapter(signer: signer)
/// ```
public final class UniFFISigner: Signer, @unchecked Sendable {

    let ffi: FfiWscdManager
    private weak var authProvider: WscdAuthProvider?
    /// Serial queue for ordered access to FFI bindings.
    private let ffiQueue = DispatchQueue(label: "org.siros.UniFFISigner.ffi")
    /// Cache of key ID → JWK JSON Data, populated at generateKey time.
    private var publicKeyCache: [String: Data] = [:]
    private let cacheLock = NSLock()

    /// Create a UniFFI-backed signer.
    ///
    /// - Parameters:
    ///   - config: WSCD manager configuration.
    ///   - authProvider: Optional callback for user authentication (PIN/WebAuthn).
    public init(config: FfiWscdConfig, authProvider: WscdAuthProvider? = nil) throws {
        self.ffi = FfiWscdManager(config: config)
        self.authProvider = authProvider
        try self.ffi.registerSoftkeyPlugin()
    }

    /// Register the R2PS remote HSM plugin.
    ///
    /// Real OPAQUE (RFC 9807) PAKE authentication (used when
    /// `config.authMode == .opaque`) is handled entirely in Rust
    /// (`r2ps-client`) - `transport` only needs to move raw R2PS protocol
    /// message bytes.
    public func registerR2psPlugin(config: R2psConfig, transport: R2psTransportProvider) throws {
        let authMode: R2psAuthMode = config.authMode
        var rpId = ""
        var allowedCredentialIds: [String] = []
        if case let .webAuthn(configRpId, configAllowedCredentialIds) = authMode {
            rpId = configRpId
            allowedCredentialIds = configAllowedCredentialIds
        }
        let ffiConfig = FfiR2psConfig(
            serverUrl: config.serverUrl,
            clientId: config.clientId,
            context: config.context,
            authMode: isWebAuthn(authMode) ? "webauthn" : "opaque",
            rpId: rpId,
            allowedCredentialIds: allowedCredentialIds,
            clientKeyPem: config.clientKeyPem,
            serverPublicKeyPem: config.serverPublicKeyPem
        )
        try ffi.registerR2psPlugin(config: ffiConfig, transport: R2psTransportBridge(transport))
    }

    private func isWebAuthn(_ mode: R2psAuthMode) -> Bool {
        if case .webAuthn = mode { return true }
        return false
    }

    /// Register the FIDO2 previewSign (rawSign) plugin.
    ///
    /// - Parameter transport: Provides the physical CTAP2 channel (BLE,
    ///   NFC/CoreNFC, ...) to the authenticator. All previewSign CBOR
    ///   request-building/response-parsing happens in Rust; `transport`
    ///   only needs to move raw command/response bytes.
    public func registerFido2Plugin(transport: Ctap2TransportProvider) throws {
        try ffi.registerFido2Plugin(transport: Ctap2TransportBridge(transport))
    }

    /// Register the FIDO2 previewSign plugin, restoring a previously-
    /// enrolled key's metadata (`state`, from a prior `exportFido2State()`
    /// call - possibly on a different device sharing this account, since
    /// CTAP2 roaming authenticators aren't tied to one device) instead of
    /// starting with no known keys.
    public func registerFido2PluginWithState(transport: Ctap2TransportProvider, state: Data) throws {
        try ffi.registerFido2PluginWithState(transport: Ctap2TransportBridge(transport), state: state)
    }

    /// Export the FIDO2 plugin's current key metadata (key handles + public
    /// keys only, never private key material - the private key never
    /// leaves the physical authenticator) for persisting via
    /// `SirosWallet.saveWscdCredentials`, so it survives to the next
    /// `registerFido2PluginWithState` call on any device sharing this
    /// account. Call after every enrollment/key-generation that could have
    /// changed the plugin's state.
    public func exportFido2State() throws -> Data {
        try ffi.exportFido2State()
    }

    // MARK: - Signer conformance

    public func generateKey(algorithm: String) async throws -> String {
        try await onFFIQueue {
            let ffiAlgorithm = try Self.mapAlgorithm(algorithm)
            let result = try self.ffi.generateKey(
                algorithm: ffiAlgorithm,
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            )
            self.cacheLock.lock()
            self.publicKeyCache[result.kid] = Data(result.publicKeyJwk.utf8)
            self.cacheLock.unlock()
            return result.kid
        }
    }

    public func sign(keyId: String, data: Data) async throws -> Data {
        try await onFFIQueue {
            let result = try self.ffi.sign(
                kid: keyId,
                data: data,
                algorithm: .es256, // algorithm is inferred from key by the manager
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            )
            return result.data
        }
    }

    public func listKeys() async throws -> [SignerKeyInfo] {
        try await onFFIQueue {
            try self.ffi.listKeys().map {
                SignerKeyInfo(keyId: $0.kid, algorithm: Self.algorithmToString($0.algorithm), pluginId: $0.pluginId)
            }
        }
    }

    public func deleteKey(keyId: String) async throws {
        try await onFFIQueue {
            try self.ffi.deleteKey(kid: keyId)
            self.cacheLock.lock()
            self.publicKeyCache.removeValue(forKey: keyId)
            self.cacheLock.unlock()
        }
    }

    public func attestationChain(keyId: String) async throws -> AttestationChain? {
        try await onFFIQueue {
            try self.ffi.attestationChain(kid: keyId).map {
                AttestationChain(certificates: $0.certificates, clientDataHash: $0.clientDataHash)
            }
        }
    }

    public func exportPublicKey(keyId: String) async throws -> Data {
        try await onFFIQueue {
            self.cacheLock.lock()
            let cached = self.publicKeyCache[keyId]
            self.cacheLock.unlock()
            if let jwkData = cached {
                return jwkData
            }
            // A cache miss doesn't mean the key doesn't exist - only
            // generateKey populates publicKeyCache, so a key created via
            // registerLifecycle/activateLifecycle, or one generated in a
            // prior process (this cache is process-memory-only), has no
            // entry here even though the Rust core still has it. `ffi`'s own
            // exportPublicKey(kid:) is documented as the recovery path for
            // exactly this case - fall back to it, and cache the result so
            // subsequent calls in this process don't need to.
            let jwk = try self.ffi.exportPublicKey(kid: keyId)
            let jwkData = Data(jwk.utf8)
            self.cacheLock.lock()
            self.publicKeyCache[keyId] = jwkData
            self.cacheLock.unlock()
            return jwkData
        }
    }

    public func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult {
        try await onFFIQueue {
            let result = try self.ffi.migrateKey(
                kid: keyId,
                targetPluginId: targetPlugin,
                auth: self.authCallbackBridge()
            )
            switch result {
            case .migrated(let newKid):
                return .migrated(newKeyId: newKid)
            case .reEnrollmentRequired(let oldKid):
                return .reEnrollmentRequired(oldKeyId: oldKid)
            }
        }
    }

    public func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        try await onFFIQueue {
            let props = try self.ffi.securityProperties(kid: keyId)
            return SignerSecurityProperties(
                keyStorage: [Self.keyStorageToString(props.keyStorage)],
                userAuthentication: props.userAuthentication,
                certification: Self.certificationToSdk(props.certification),
                amr: props.amr
            )
        }
    }

    /// Export the softkey plugin container as JSON bytes for encrypted backup.
    public func exportSoftkeyContainer() throws -> Data {
        try ffi.exportSoftkeyContainer()
    }

    /// Import a softkey container (JSON bytes) to restore keys from backup.
    public func importSoftkeyContainer(_ container: Data) throws {
        try ffi.importSoftkeyContainer(container: container)
    }

    // MARK: - Private helpers

    /// Execute a blocking FFI call on the serial FFI queue.
    func onFFIQueue<T>(_ block: @escaping () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            ffiQueue.async {
                do {
                    let result = try block()
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    func authCallbackBridge() -> AuthCallbackBridge {
        AuthCallbackBridge(provider: authProvider)
    }

    // MARK: - Type mapping

    /// The manager's name for a BLS12-381 Schnorr key-binding key
    /// (`Algorithm::as_str` in siros-wscd-manager), used as the SDK-side
    /// algorithm string since JOSE has none for it. Same string as the
    /// Kotlin SDK's `BLS12381_G1_SCHNORR_NAME`.
    private static let bls12381G1SchnorrName = "EcsdsaBls12381Bp1Sha256Sec1"
    private static let bls12381G1SchnorrNameUppercased = bls12381G1SchnorrName.uppercased()

    private static func mapAlgorithm(_ s: String) throws -> FfiAlgorithm {
        switch s.uppercased() {
        case "ES256": return .es256
        case "EDDSA", "ED25519": return .edDsa
        // The manager's own name for it (`Algorithm::as_str`), since JOSE has
        // no `alg` for a BLS12-381 Schnorr key. Blind BBS key binding, COSE
        // -65609; only the fido2 plugin serves it, on YubiKey 5.8 alpha.
        case Self.bls12381G1SchnorrNameUppercased: return .bls12381G1Schnorr
        default: throw UniFFISignerError.unsupportedAlgorithm(s)
        }
    }

    private static func algorithmToString(_ alg: FfiAlgorithm) -> String {
        switch alg {
        case .es256: return "ES256"
        case .edDsa: return "EdDSA"
        case .bls12381G1Schnorr: return Self.bls12381G1SchnorrName
        }
    }

    private static func keyStorageToString(_ ks: FfiKeyStorageType) -> String {
        switch ks {
        case .software: return "software"
        case .hardware: return "hardware"
        case .remoteHsm: return "remote_hsm"
        case .trustedExecution: return "trusted_execution"
        }
    }

    private static func certificationToSdk(_ cert: FfiCertificationLevel) -> CertificationInfo {
        switch cert {
        case .none: return .none
        case .baseline: return .certified(scheme: "EUCC", assuranceLevel: "baseline")
        case .substantial: return .certified(scheme: "EUCC", assuranceLevel: "substantial")
        case .high: return .certified(scheme: "EUCC", assuranceLevel: "high")
        }
    }
}

// MARK: - Errors

public enum UniFFISignerError: Error, LocalizedError {
    case unsupportedAlgorithm(String)
    case publicKeyNotCached(keyId: String)

    public var errorDescription: String? {
        switch self {
        case .unsupportedAlgorithm(let alg):
            return "Unsupported algorithm: \(alg)"
        case .publicKeyNotCached(let kid):
            return "Public key not cached for \(kid). Key was generated before this session or on another device."
        }
    }
}

// MARK: - Auth callback bridge

final class AuthCallbackBridge: FfiAuthCallback, @unchecked Sendable {
    private weak var provider: WscdAuthProvider?

    init(provider: WscdAuthProvider?) {
        self.provider = provider
    }

    func requestPin(pluginId: String) throws -> Data {
        guard let provider = provider else {
            throw FfiWscdError.AuthCancelled(msg: "No AuthProvider configured")
        }
        return try provider.requestPin(pluginId: pluginId)
    }

    func requestWebauthnAssertion(
        pluginId: String,
        challenge: Data,
        rpId: String,
        allowedCredentials: [Data]
    ) throws -> Data {
        guard let provider = provider else {
            throw FfiWscdError.AuthCancelled(msg: "No AuthProvider configured")
        }
        return try provider.requestWebauthnAssertion(
            pluginId: pluginId,
            challenge: challenge,
            rpId: rpId,
            allowedCredentials: allowedCredentials
        )
    }
}

// MARK: - No-op progress callback

final class NoOpProgressCallback: FfiProgressCallback, @unchecked Sendable {
    func onProgress(progress: FfiOperationProgress) { /* no-op */ }
}

// MARK: - CTAP2 bridge

/// Bridges the SDK's `Ctap2TransportProvider` to the UniFFI `FfiCtap2Transport`
/// callback.
///
/// As of siros-wscd-manager v0.6.0, `FfiCtap2Transport` is a single raw
/// `ctap2SendCommand(command:) -> Data` method - all previewSign CBOR
/// request-building and response-parsing lives in Rust
/// (`preview_sign_protocol`), confirmed against real YubiKey 5.8 hardware.
/// This bridge does no CBOR/CTAP2 work of its own; it only adapts between
/// the FFI's synchronous callback (called from Rust's FFI queue thread)
/// and `Ctap2TransportProvider.send(command:)`'s `async` signature, and
/// lazily calls `connect()` on first use since the FFI has no separate
/// connect step of its own.
private final class Ctap2TransportBridge: FfiCtap2Transport, @unchecked Sendable {
    private let provider: Ctap2TransportProvider
    private let connectLock = NSLock()
    private var connected = false

    init(_ provider: Ctap2TransportProvider) {
        self.provider = provider
    }

    func ctap2SendCommand(command: Data) throws -> Data {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Data, Error> = .failure(Ctap2TransportError.deviceDisconnected)

        Task {
            do {
                try await self.ensureConnected()
                do {
                    result = .success(try await self.provider.send(command: command))
                } catch {
                    // A transient physical disconnect (unplug/replug, PIN-
                    // lockout recovery) used to wedge every subsequent
                    // CTAP2 call with deviceDisconnected until app restart -
                    // `connected` was set true on the first successful
                    // connect() and never reset, so ensureConnected() kept
                    // short-circuiting forever. Mirrors the Kotlin SDK's
                    // fix for the same real hardware-confirmed bug: reset,
                    // reconnect, and retry once before giving up.
                    self.connectLock.lock()
                    self.connected = false
                    self.connectLock.unlock()
                    try? await self.provider.disconnect()
                    try await self.ensureConnected()
                    result = .success(try await self.provider.send(command: command))
                }
            } catch {
                result = .failure(error)
            }
            semaphore.signal()
        }
        semaphore.wait()

        switch result {
        case .success(let data): return data
        case .failure(let error): throw error
        }
    }

    private func ensureConnected() async throws {
        connectLock.lock()
        let alreadyConnected = connected
        connectLock.unlock()
        guard !alreadyConnected else { return }

        try await provider.connect()

        connectLock.lock()
        connected = true
        connectLock.unlock()
    }
}

/// Bridges the `async`-based `R2psTransportProvider` to `FfiHttpTransport`'s
/// synchronous callback, same `DispatchSemaphore` pattern as
/// `Ctap2TransportBridge`.
private final class R2psTransportBridge: FfiHttpTransport, @unchecked Sendable {
    private let provider: R2psTransportProvider

    init(_ provider: R2psTransportProvider) {
        self.provider = provider
    }

    func send(body: Data) throws -> Data {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Data, Error> = .failure(Ctap2TransportError.deviceDisconnected)

        Task {
            do {
                result = .success(try await self.provider.send(body: body))
            } catch {
                result = .failure(error)
            }
            semaphore.signal()
        }
        semaphore.wait()

        switch result {
        case .success(let data): return data
        case .failure(let error): throw error
        }
    }
}

// MARK: - WSCD manager conformance

extension UniFFISigner: WscdManager {}

// MARK: - Lifecycle conformance

extension UniFFISigner: SignerLifecycleManager {
    public func lifecycleStatus(pluginId: String, contextId: String) async throws -> LifecycleStatus {
        try await onFFIQueue {
            try self.ffi.lifecycleStatus(pluginId: pluginId, contextId: contextId).toSdkLifecycleStatus()
        }
    }

    public func registerLifecycle(request: RegisterLifecycleRequest) async throws -> RegistrationOutcome {
        try await onFFIQueue {
            try self.ffi.registerLifecycle(
                request: request.toFfiRequest(),
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            ).toSdkRegistrationOutcome()
        }
    }

    public func activateLifecycle(request: ActivateLifecycleRequest) async throws -> ActivationOutcome {
        try await onFFIQueue {
            try self.ffi.activateLifecycle(
                request: request.toFfiRequest(),
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            ).toSdkActivationOutcome()
        }
    }

    public func rotateLifecycle(request: RotateLifecycleRequest) async throws -> RotationOutcome {
        try await onFFIQueue {
            try self.ffi.rotateLifecycle(
                request: request.toFfiRequest(),
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            ).toSdkRotationOutcome()
        }
    }

    public func destroyLifecycle(request: DestroyLifecycleRequest) async throws -> DestructionOutcome {
        try await onFFIQueue {
            try self.ffi.destroyLifecycle(
                request: request.toFfiRequest(),
                auth: self.authCallbackBridge(),
                progress: NoOpProgressCallback()
            ).toSdkDestructionOutcome()
        }
    }
}

private extension RegisterLifecycleRequest {
    func toFfiRequest() -> FfiRegisterLifecycleRequest {
        FfiRegisterLifecycleRequest(
            pluginId: pluginId,
            contextId: contextId,
            factorKind: factorKind.toFfiFactorKind()
        )
    }
}

private extension ActivateLifecycleRequest {
    func toFfiRequest() -> FfiActivateLifecycleRequest {
        FfiActivateLifecycleRequest(pluginId: pluginId, contextId: contextId)
    }
}

private extension RotateLifecycleRequest {
    func toFfiRequest() -> FfiRotateLifecycleRequest {
        FfiRotateLifecycleRequest(pluginId: pluginId, contextId: contextId)
    }
}

private extension DestroyLifecycleRequest {
    func toFfiRequest() -> FfiDestroyLifecycleRequest {
        FfiDestroyLifecycleRequest(
            pluginId: pluginId,
            contextId: contextId,
            mode: mode.toFfiDestroyMode(),
            reason: reason
        )
    }
}

private extension FactorKind {
    func toFfiFactorKind() -> FfiFactorKind {
        switch self {
        case .opaque: return .opaque
        case .webAuthn: return .webAuthn
        case .rawSign: return .rawSign
        }
    }
}

private extension DestroyMode {
    func toFfiDestroyMode() -> FfiDestroyMode {
        switch self {
        case .localOnly: return .localOnly
        case .remoteRevokeIfSupported: return .remoteRevokeIfSupported
        case .strict: return .strict
        }
    }
}

private extension FfiFactorKind {
    func toSdkFactorKind() -> FactorKind {
        switch self {
        case .opaque: return .opaque
        case .webAuthn: return .webAuthn
        case .rawSign: return .rawSign
        }
    }
}

private extension FfiLifecycleState {
    func toSdkLifecycleState() -> LifecycleState {
        switch self {
        case .uninitialized: return .uninitialized
        case .registered: return .registered
        case .active: return .active
        case .suspended: return .suspended
        case .destroyed: return .destroyed
        }
    }
}

private extension FfiLifecycleStatus {
    func toSdkLifecycleStatus() -> LifecycleStatus {
        LifecycleStatus(
            contextId: contextId,
            pluginId: pluginId,
            factorKind: factorKind.toSdkFactorKind(),
            state: state.toSdkLifecycleState(),
            updatedAt: updatedAt
        )
    }
}

private extension FfiRegistrationOutcome {
    func toSdkRegistrationOutcome() -> RegistrationOutcome {
        RegistrationOutcome(contextId: contextId, state: state.toSdkLifecycleState())
    }
}

private extension FfiActivationOutcome {
    func toSdkActivationOutcome() -> ActivationOutcome {
        ActivationOutcome(contextId: contextId, state: state.toSdkLifecycleState())
    }
}

private extension FfiRotationOutcome {
    func toSdkRotationOutcome() -> RotationOutcome {
        RotationOutcome(contextId: contextId, state: state.toSdkLifecycleState())
    }
}

private extension FfiDestructionOutcome {
    func toSdkDestructionOutcome() -> DestructionOutcome {
        DestructionOutcome(
            contextId: contextId,
            state: state.toSdkLifecycleState(),
            remotePerformed: remotePerformed
        )
    }
}
#endif // os(iOS)
