// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Local credential store protocol.
///
/// SDK consumers can implement custom storage backends (e.g. Core Data,
/// Keychain, encrypted file). All methods are async to allow I/O-backed
/// implementations.
///
/// Implementations must be safe for concurrent access.
public protocol CredentialStore: Sendable {
    /// Return all stored credentials.
    func getAll() async -> [StoredCredential]

    /// Find a credential by its unique ID. Returns nil if not found.
    func getById(_ id: Int64) async -> StoredCredential?

    /// Store a new credential. Overwrites any existing credential with the same ID.
    func save(_ credential: StoredCredential) async

    /// Update an existing credential's metadata. Equivalent to `save`.
    func update(_ credential: StoredCredential) async

    /// Delete a credential by ID. No-op if not found.
    func delete(_ id: Int64) async

    /// Remove all stored credentials.
    func clear() async

    /// Remove all stored credentials and report a failure. `clear()` cannot
    /// say that it failed; an account wipe needs to know, so a store whose
    /// removal can fail overrides this. The default calls `clear()`.
    func eraseAll() async throws
}

public extension CredentialStore {
    func eraseAll() async throws { await clear() }
}

/// In-memory credential store for development/testing.
public actor InMemoryCredentialStore: CredentialStore {
    private var store: [Int64: StoredCredential] = [:]

    public init() {}

    public func getAll() -> [StoredCredential] {
        Array(store.values)
    }

    public func getById(_ id: Int64) -> StoredCredential? {
        store[id]
    }

    public func save(_ credential: StoredCredential) {
        store[credential.id] = credential
    }

    public func update(_ credential: StoredCredential) {
        store[credential.id] = credential
    }

    public func delete(_ id: Int64) {
        store.removeValue(forKey: id)
    }

    public func clear() {
        store.removeAll()
    }
}
