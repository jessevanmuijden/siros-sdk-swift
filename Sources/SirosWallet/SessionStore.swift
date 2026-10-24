// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Protocol for persisting session tokens and key material across app launches.
///
/// All reads/writes are scoped to the ``activeAccountId``. When set,
/// keys are prefixed with `{accountId}/` so multiple accounts coexist.
/// When nil, reads return nil and writes are no-ops.
public protocol SessionStoreProtocol: AnyObject, Sendable {
    /// The currently active account ID (`tenantId:userId`).
    var activeAccountId: String? { get set }

    var appToken: String? { get set }
    var refreshToken: String? { get set }
    var userId: String? { get set }
    var displayName: String? { get set }
    var tenantId: String? { get set }
    var mainKey: String? { get set }
    var hkdfSalt: String? { get set }
    var hkdfInfo: String? { get set }
    var prfSalt: String? { get set }
    var credentialId: String? { get set }
    var privateDataJwe: String? { get set }
    var privateDataEtag: String? { get set }

    /// TOFU (trust-on-first-use) `(issuer, credentialType) -> pluginId`
    /// mapping for `WscdSelectionPolicy`, serialized as a single JSON
    /// string blob (`[String: String]`, matching `privateDataJwe`'s
    /// as-string-blob precedent rather than one Keychain/store item per
    /// mapping entry). Account-scoped like every other property here (not
    /// install-scoped like `appAttestKeyId`) - a WSCD plugin choice for a
    /// given issuer/credential type is a per-account decision.
    var wscdTofuMappingJson: String? { get set }

    /// Per-(issuer, credentialType) EXPLICIT user preference for
    /// `WscdSelectionPolicy`, serialized the same way as
    /// `wscdTofuMappingJson` (`[String: String]`, same key shape, own JSON
    /// blob). Deliberately a separate property from TOFU rather than folded
    /// into it: TOFU is the SDK's own auto-remembered outcome of an
    /// otherwise-ambiguous resolution, whereas this is a user's own
    /// deliberate "always use X for this issuer" choice, which outranks TOFU
    /// and must survive independently of it (e.g. clearing TOFU must not
    /// clear this, and vice versa).
    var wscdUserOverrideMappingJson: String? { get set }

    /// The single global user preference for `WscdSelectionPolicy` - one
    /// plugin ID applying across every (issuer, credentialType) pair that
    /// doesn't already have its own more-specific
    /// `wscdUserOverrideMappingJson` entry. A simple scalar, unlike the two
    /// JSON-blob mapping properties above, since there is only ever one.
    var wscdGlobalOverridePluginId: String? { get set }

    /// The keystore key ID used as this wallet installation's persistent
    /// OAuth Client Attestation instance key (draft-ietf-oauth-attestation-based-client-auth-04
    /// §3.1) - generated once, reused for the account's lifetime. The
    /// backend's Wallet Instance Attestation tracks/revokes instances by this
    /// key's JWK thumbprint, so a different key each time would silently
    /// register a new "instance" on every flow.
    ///
    /// Account-scoped, but deliberately **survives ``clearAccount()``**: a
    /// logout must not change which wallet instance this installation is.
    /// Clearing it would mint a new key, and therefore a new backend instance,
    /// at the next login - which would silently hand a suspended or revoked
    /// installation a fresh, unblocked identity just by logging out and back
    /// in (SID-AUTH-06). Only ``clearAll()`` (a factory reset) removes it.
    var instanceKeyId: String? { get set }

    /// This install's persisted Apple App Attest key ID (see
    /// `AppAttestProvider`), if one has been generated - App Attest keys
    /// are generated exactly once PER INSTALL (not per-account, unlike every
    /// other property here) and reused forever after. Implementations must
    /// store this OUTSIDE the `activeAccountId`-scoped namespace and must
    /// NOT clear it in `clearAccount()` (only `clearAll()`/factory reset) -
    /// otherwise switching accounts or logging out would force a fresh App
    /// Attest key + attestation on next login, which defeats the entire
    /// point of a stable per-install identity (and wastes real App Attest
    /// key-generation calls against Apple's servers).
    var appAttestKeyId: String? { get set }

    var hasSession: Bool { get }

    /// Clear the active account's session data only.
    func clearAccount()
    /// Clear all accounts' session data (factory reset).
    func clearAll()
    /// Legacy alias for ``clearAccount()``.
    func clear()
    /// ``clearAll()`` that reports a failure instead of swallowing it, so an
    /// account wipe can tell the host that secrets may remain. The default
    /// calls ``clearAll()``.
    func eraseAll() throws
}

public extension SessionStoreProtocol {
    func eraseAll() throws { clearAll() }
}

/// Account-keyed in-memory session store for testing and Linux.
public final class InMemorySessionStore: SessionStoreProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private var store: [String: String] = [:]

    public var activeAccountId: String?

    public init() {}

    private func scopedKey(_ key: String) -> String? {
        guard let id = activeAccountId else { return nil }
        return "\(id)/\(key)"
    }
    private func get(_ key: String) -> String? {
        guard let k = scopedKey(key) else { return nil }
        lock.lock(); defer { lock.unlock() }
        return store[k]
    }
    private func set(_ key: String, _ value: String?) {
        guard let k = scopedKey(key) else { return }
        lock.lock(); defer { lock.unlock() }
        if let value { store[k] = value } else { store.removeValue(forKey: k) }
    }

    public var appToken: String? { get { get("appToken") } set { set("appToken", newValue) } }
    public var refreshToken: String? { get { get("refreshToken") } set { set("refreshToken", newValue) } }
    public var userId: String? { get { get("userId") } set { set("userId", newValue) } }
    public var displayName: String? { get { get("displayName") } set { set("displayName", newValue) } }
    public var tenantId: String? { get { get("tenantId") } set { set("tenantId", newValue) } }
    public var mainKey: String? { get { get("mainKey") } set { set("mainKey", newValue) } }
    public var hkdfSalt: String? { get { get("hkdfSalt") } set { set("hkdfSalt", newValue) } }
    public var hkdfInfo: String? { get { get("hkdfInfo") } set { set("hkdfInfo", newValue) } }
    public var prfSalt: String? { get { get("prfSalt") } set { set("prfSalt", newValue) } }
    public var credentialId: String? { get { get("credentialId") } set { set("credentialId", newValue) } }
    public var privateDataJwe: String? { get { get("privateDataJwe") } set { set("privateDataJwe", newValue) } }
    public var privateDataEtag: String? { get { get("privateDataEtag") } set { set("privateDataEtag", newValue) } }
    public var wscdTofuMappingJson: String? { get { get("wscdTofuMappingJson") } set { set("wscdTofuMappingJson", newValue) } }
    public var wscdUserOverrideMappingJson: String? { get { get("wscdUserOverrideMappingJson") } set { set("wscdUserOverrideMappingJson", newValue) } }
    public var wscdGlobalOverridePluginId: String? { get { get("wscdGlobalOverridePluginId") } set { set("wscdGlobalOverridePluginId", newValue) } }
    public var instanceKeyId: String? { get { get("instanceKeyId") } set { set("instanceKeyId", newValue) } }

    // Deliberately NOT account-scoped (see the protocol doc comment) - a
    // fixed key with no account prefix, so it survives `clearAccount()` and
    // account switches. `clearAccount()`'s prefix-based filter below can
    // never match this key, since it's never written with an `{id}/` prefix.
    private var unscopedAppAttestKeyId: String?
    public var appAttestKeyId: String? {
        get { lock.lock(); defer { lock.unlock() }; return unscopedAppAttestKeyId }
        set { lock.lock(); defer { lock.unlock() }; unscopedAppAttestKeyId = newValue }
    }

    public var hasSession: Bool { userId != nil }

    public func clearAccount() {
        guard let id = activeAccountId else { return }
        let prefix = "\(id)/"
        // The instance key is the exception: see `instanceKeyId`'s doc comment
        // - it identifies this installation to the backend's wallet instance
        // lifecycle, and a logout must not change that identity.
        let keep = "\(id)/instanceKeyId"
        lock.lock(); defer { lock.unlock() }
        store = store.filter { !$0.key.hasPrefix(prefix) || $0.key == keep }
    }

    public func clearAll() {
        lock.lock(); defer { lock.unlock() }
        store.removeAll()
        unscopedAppAttestKeyId = nil
        activeAccountId = nil
    }

    public func clear() { clearAccount() }

    /// Test seam: make ``eraseAll()`` fail the way a Keychain store can.
    var eraseFailure: Error?

    public func eraseAll() throws {
        if let eraseFailure { throw eraseFailure }
        clearAll()
    }
}
