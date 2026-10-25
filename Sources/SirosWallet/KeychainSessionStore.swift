// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(Security)
import Foundation
import Security
import SirosCredentials

/// Keychain-backed session store for iOS/macOS.
///
/// Stores session tokens and key material securely in the system Keychain
/// using `kSecClassGenericPassword` items scoped by a configurable service name.
///
/// Usage:
/// ```swift
/// let store = KeychainSessionStore(service: "org.siros.wallet")
/// let wallet = SirosWallet(config: config, authProvider: auth, sessionStore: store)
/// ```
public final class KeychainSessionStore: SessionStoreProtocol, @unchecked Sendable {
    private let lock = NSLock()
    private let service: String
    private let accessGroup: String?

    public var activeAccountId: String?

    /// Create a Keychain session store.
    ///
    /// - Parameters:
    ///   - service: Keychain service identifier (e.g. your bundle ID).
    ///   - accessGroup: Optional Keychain access group for sharing across apps.
    public init(service: String = "org.siros.wallet", accessGroup: String? = nil) {
        self.service = service
        self.accessGroup = accessGroup
    }

    // MARK: - SessionStoreProtocol

    public var appToken: String? {
        get { read("appToken") }
        set { write("appToken", newValue) }
    }
    public var refreshToken: String? {
        get { read("refreshToken") }
        set { write("refreshToken", newValue) }
    }
    public var userId: String? {
        get { read("userId") }
        set { write("userId", newValue) }
    }
    public var displayName: String? {
        get { read("displayName") }
        set { write("displayName", newValue) }
    }
    public var tenantId: String? {
        get { read("tenantId") }
        set { write("tenantId", newValue) }
    }
    public var mainKey: String? {
        get { read("mainKey") }
        set { write("mainKey", newValue) }
    }
    public var hkdfSalt: String? {
        get { read("hkdfSalt") }
        set { write("hkdfSalt", newValue) }
    }
    public var hkdfInfo: String? {
        get { read("hkdfInfo") }
        set { write("hkdfInfo", newValue) }
    }
    public var prfSalt: String? {
        get { read("prfSalt") }
        set { write("prfSalt", newValue) }
    }
    public var credentialId: String? {
        get { read("credentialId") }
        set { write("credentialId", newValue) }
    }
    public var privateDataJwe: String? {
        get { read("privateDataJwe") }
        set { write("privateDataJwe", newValue) }
    }
    public var privateDataEtag: String? {
        get { read("privateDataEtag") }
        set { write("privateDataEtag", newValue) }
    }
    public var wscdTofuMappingJson: String? {
        get { read("wscdTofuMappingJson") }
        set { write("wscdTofuMappingJson", newValue) }
    }
    public var wscdUserOverrideMappingJson: String? {
        get { read("wscdUserOverrideMappingJson") }
        set { write("wscdUserOverrideMappingJson", newValue) }
    }
    public var wscdGlobalOverridePluginId: String? {
        get { read("wscdGlobalOverridePluginId") }
        set { write("wscdGlobalOverridePluginId", newValue) }
    }
    public var instanceKeyId: String? {
        get { read("instanceKeyId") }
        set { write("instanceKeyId", newValue) }
    }
    // Deliberately NOT run through read/write (which scope by
    // activeAccountId) - see the protocol doc comment. `clearAll()`'s
    // existing blanket SecItemDelete (no kSecAttrAccount filter, matches
    // every item under `service`) already covers this on factory reset;
    // `clearAccount()` below must NOT touch it.
    public var appAttestKeyId: String? {
        get { readRaw(account: "appAttestKeyId") }
        set { writeRaw(account: "appAttestKeyId", newValue) }
    }

    public var hasSession: Bool { userId != nil }

    public func clearAccount() {
        guard let id = activeAccountId else { return }
        // Delete all keys with the account prefix
        // Since Keychain doesn't support prefix queries easily,
        // we delete each known key individually
        let keys = ["appToken", "refreshToken", "userId", "displayName",
                    "tenantId", "mainKey", "hkdfSalt", "hkdfInfo",
                    "prfSalt", "credentialId", "privateDataJwe", "privateDataEtag",
                    // NOT "instanceKeyId": see its doc comment in
                    // `SessionStore.swift`. It identifies this installation to
                    // the backend's wallet instance lifecycle, so deleting it
                    // here would mint a new instance at the next login and let
                    // a suspended or revoked installation walk away from its
                    // block by logging out (SID-AUTH-06). `clearAll()` still
                    // removes it.
                    "wscdTofuMappingJson",
                    "wscdUserOverrideMappingJson", "wscdGlobalOverridePluginId",
                    // Legacy key, no longer written (the per-instance-key
                    // FIDO2 registration dedupe it backed was removed in
                    // favor of per-credential-key registration - see
                    // SirosWallet.registerFido2AttestationsForBatch).
                    // Kept in this deletion list only so upgraded installs
                    // that still have this Keychain item from an older
                    // version get it cleaned up on logout/account switch
                    // instead of leaking it forever.
                    "fido2AttestationRegisteredKeyId"]
        lock.lock(); defer { lock.unlock() }
        for key in keys {
            let scopedKey = "\(id)/\(key)"
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: scopedKey,
            ]
            if let group = accessGroup { query[kSecAttrAccessGroup as String] = group }
            SecItemDelete(query as CFDictionary)
        }
    }

    public func clearAll() {
        try? eraseAll()
    }

    /// Removes every item under `service`; an absent item is success, any
    /// other Keychain status is thrown. The active account is forgotten
    /// either way.
    public func eraseAll() throws {
        lock.lock(); defer { lock.unlock() }
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        if let group = accessGroup { query[kSecAttrAccessGroup as String] = group }
        let status = SecItemDelete(query as CFDictionary)
        activeAccountId = nil
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SirosError.keystore(message: "Keychain session store could not be erased (status \(status))")
        }
    }

    public func clear() { clearAccount() }

    // MARK: - Keychain helpers

    private func scopedKey(_ key: String) -> String? {
        guard let id = activeAccountId else { return nil }
        return "\(id)/\(key)"
    }

    private func read(_ key: String) -> String? {
        guard let k = scopedKey(key) else { return nil }
        return readRaw(account: k)
    }

    private func write(_ key: String, _ value: String?) {
        guard let k = scopedKey(key) else { return }
        writeRaw(account: k, value)
    }

    /// Reads a Keychain item under `account` directly - NOT run through
    /// `scopedKey()`/`activeAccountId`. Only for genuinely install-scoped
    /// (not account-scoped) values like `appAttestKeyId`.
    private func readRaw(account: String) -> String? {
        lock.lock()
        defer { lock.unlock() }

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if let group = accessGroup {
            query[kSecAttrAccessGroup as String] = group
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Writes a Keychain item under `account` directly - see `readRaw`'s doc comment.
    private func writeRaw(account: String, _ value: String?) {
        lock.lock()
        defer { lock.unlock() }

        var deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let group = accessGroup {
            deleteQuery[kSecAttrAccessGroup as String] = group
        }
        SecItemDelete(deleteQuery as CFDictionary)

        guard let value, let data = value.data(using: .utf8) else { return }

        var addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        if let group = accessGroup {
            addQuery[kSecAttrAccessGroup as String] = group
        }
        SecItemAdd(addQuery as CFDictionary, nil)
    }
}
#endif
