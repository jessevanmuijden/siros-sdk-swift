// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
#if canImport(Security)
import Security
#endif

/// Persistent registry of known accounts that survives logout.
///
/// Mirrors the frontend's `localStorage.cachedUsers` — stores an array
/// of ``CachedAccount`` entries so the login screen can show "Welcome back"
/// with a list of known accounts and their passkeys.
///
/// On Apple platforms, backed by the Keychain for encrypted storage.
/// On Linux, falls back to UserDefaults.
public final class AccountRegistry: @unchecked Sendable {

    private let lock = NSLock()
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()
    private let storage: AccountRegistryStorage

    /// Registry persisted in the Keychain under `service` (UserDefaults on
    /// Linux). Survives logout and app reinstall-with-keychain-restore.
    public init(service: String = "org.siros.wallet.accounts") {
        #if canImport(Security)
        self.storage = KeychainAccountRegistryStorage(service: service)
        #else
        self.storage = UserDefaultsAccountRegistryStorage()
        #endif
    }

    init(storage: AccountRegistryStorage) {
        self.storage = storage
    }

    /// A registry that persists nothing - for tests and previews, and for
    /// hosts that manage account persistence themselves.
    public static func inMemory() -> AccountRegistry {
        AccountRegistry(storage: InMemoryAccountRegistryStorage())
    }

    // MARK: - Account CRUD

    /// All known accounts across all tenants and backends.
    public func listAccounts() -> [CachedAccount] {
        lock.lock(); defer { lock.unlock() }
        return loadAccountsLocked()
    }

    /// Accounts for a specific tenant.
    public func listAccounts(tenantId: String) -> [CachedAccount] {
        listAccounts().filter { $0.tenantId == tenantId }
    }

    /// Accounts that have at least one passkey with PRF support.
    public func listLoginableAccounts() -> [CachedAccount] {
        listAccounts().filter { $0.hasPrfKeys }
    }

    /// Accounts for a specific tenant that can log in.
    public func listLoginableAccounts(tenantId: String) -> [CachedAccount] {
        listAccounts(tenantId: tenantId).filter { $0.hasPrfKeys }
    }

    /// Find an account by its unique ID (`tenantId:userId`).
    public func findAccount(accountId: String) -> CachedAccount? {
        listAccounts().first { $0.accountId == accountId }
    }

    /// Add or update an account in the registry.
    public func upsertAccount(_ account: CachedAccount) {
        lock.lock(); defer { lock.unlock() }
        var accounts = loadAccountsLocked()
        if let index = accounts.firstIndex(where: { $0.accountId == account.accountId }) {
            accounts[index] = account
        } else {
            accounts.append(account)
        }
        saveAccountsLocked(accounts)
    }

    /// Remove an account from the registry.
    public func removeAccount(accountId: String) {
        lock.lock(); defer { lock.unlock() }
        var accounts = loadAccountsLocked()
        accounts.removeAll { $0.accountId == accountId }
        saveAccountsLocked(accounts)
        if readString(Keys.active) == accountId {
            deleteKey(Keys.active)
        }
    }

    /// Remove all cached accounts (factory reset).
    public func clear() {
        lock.lock(); defer { lock.unlock() }
        try? storage.eraseAll()
    }

    /// ``clear()`` that reports a storage failure, so an account wipe can tell
    /// the host that cached accounts may remain.
    public func eraseAll() throws {
        lock.lock(); defer { lock.unlock() }
        try storage.eraseAll()
    }

    // MARK: - Active Account

    /// The ID of the currently active account, or nil.
    public var activeAccountId: String? {
        get { readString(Keys.active) }
        set {
            if let id = newValue {
                writeString(Keys.active, id)
            } else {
                deleteKey(Keys.active)
            }
        }
    }

    // MARK: - Tenants

    /// Distinct tenants across all registered accounts.
    public func knownTenants() -> [TenantInfo] {
        let accounts = listAccounts()
        let grouped = Dictionary(grouping: accounts, by: { $0.tenantId })
        return grouped.map { (tenantId, accts) in
            TenantInfo(
                id: tenantId,
                accountCount: accts.count,
                backendUrl: accts.first?.backendUrl ?? ""
            )
        }
    }

    // MARK: - Storage Backend

    private func loadAccountsLocked() -> [CachedAccount] {
        guard let data = storage.readData(Keys.accounts) else { return [] }
        return (try? decoder.decode([CachedAccount].self, from: data)) ?? []
    }

    private func saveAccountsLocked(_ accounts: [CachedAccount]) {
        guard let data = try? encoder.encode(accounts) else { return }
        storage.writeData(Keys.accounts, data)
    }

    private func readString(_ key: String) -> String? {
        guard let data = storage.readData(key) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func writeString(_ key: String, _ value: String) {
        guard let data = value.data(using: .utf8) else { return }
        storage.writeData(key, data)
    }

    private func deleteKey(_ key: String) { storage.deleteKey(key) }

    private enum Keys {
        static let accounts = "siros_cached_accounts"
        static let active = "siros_active_account_id"
    }
}

// MARK: - Storage backends

protocol AccountRegistryStorage: Sendable {
    func readData(_ key: String) -> Data?
    func writeData(_ key: String, _ data: Data)
    func deleteKey(_ key: String)
    func deleteAll()
    /// ``deleteAll()`` that surfaces a failure; defaults to it.
    func eraseAll() throws
}

extension AccountRegistryStorage {
    func eraseAll() throws { deleteAll() }
}

final class InMemoryAccountRegistryStorage: AccountRegistryStorage, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]

    func readData(_ key: String) -> Data? { lock.withLock { items[key] } }
    func writeData(_ key: String, _ data: Data) { lock.withLock { items[key] = data } }
    func deleteKey(_ key: String) { lock.withLock { _ = items.removeValue(forKey: key) } }
    func deleteAll() { lock.withLock { items.removeAll() } }

    /// Test seam: make ``eraseAll()`` fail the way a Keychain store can.
    var eraseFailure: Error?
    func eraseAll() throws {
        if let eraseFailure { throw eraseFailure }
        deleteAll()
    }
}

#if canImport(Security)
/// Keychain-backed storage (Apple platforms).
final class KeychainAccountRegistryStorage: AccountRegistryStorage {
    private let service: String

    init(service: String) { self.service = service }

    func readData(_ key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    func writeData(_ key: String, _ data: Data) {
        deleteKey(key)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    func deleteKey(_ key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(query as CFDictionary)
    }

    func deleteAll() { try? eraseAll() }

    func eraseAll() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw SirosError.keystore(message: "Keychain account registry could not be erased (status \(status))")
        }
    }
}
#else
/// UserDefaults fallback (Linux).
final class UserDefaultsAccountRegistryStorage: AccountRegistryStorage, @unchecked Sendable {
    private let defaults = UserDefaults.standard

    /// Older builds stored the active-account id as a String; read it back as
    /// UTF-8 so an upgraded install still resumes its session.
    func readData(_ key: String) -> Data? {
        defaults.data(forKey: key) ?? defaults.string(forKey: key).map { Data($0.utf8) }
    }
    func writeData(_ key: String, _ data: Data) { defaults.set(data, forKey: key) }
    func deleteKey(_ key: String) { defaults.removeObject(forKey: key) }
    func deleteAll() {
        deleteKey("siros_cached_accounts")
        deleteKey("siros_active_account_id")
    }
}
#endif
