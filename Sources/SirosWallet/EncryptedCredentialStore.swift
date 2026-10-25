// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosKeystore

/// ``CredentialStore`` backed by the PRF-encrypted keystore container.
///
/// Credentials are serialised to JSON and stored inside the same JWE
/// envelope as the wallet's private keys. This matches the wallet-frontend
/// pattern where all sensitive data is encrypted with the PRF-derived key
/// and synchronised to the backend as `privateData`.
public final class KeystoreBackedCredentialStore: CredentialStore, @unchecked Sendable {
    private let keystore: KeystoreManager
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    public init(keystore: KeystoreManager) {
        self.keystore = keystore
    }

    public func getAll() async -> [StoredCredential] {
        guard keystore.isUnlocked else { return [] }
        guard let allRaw = try? await keystore.getAllCredentials() else { return [] }
        return allRaw.values.compactMap { raw in
            try? decoder.decode(StoredCredential.self, from: Data(raw.utf8))
        }
    }

    public func getById(_ id: Int64) async -> StoredCredential? {
        guard keystore.isUnlocked else { return nil }
        guard let raw = try? await keystore.getCredential(id: id) else { return nil }
        return try? decoder.decode(StoredCredential.self, from: Data(raw.utf8))
    }

    public func save(_ credential: StoredCredential) async {
        guard keystore.isUnlocked else { return }
        guard let data = try? encoder.encode(credential),
              let raw = String(data: data, encoding: .utf8) else { return }
        try? await keystore.saveCredential(id: credential.id, json: raw)
    }

    public func update(_ credential: StoredCredential) async {
        await save(credential)
    }

    public func delete(_ id: Int64) async {
        guard keystore.isUnlocked else { return }
        try? await keystore.deleteCredential(id: id)
    }

    public func clear() async {
        try? await eraseAll()
    }

    /// A locked keystore holds nothing in memory; its persisted container is
    /// the session store's to remove.
    public func eraseAll() async throws {
        guard keystore.isUnlocked else { return }
        try await keystore.clearCredentials()
    }
}
