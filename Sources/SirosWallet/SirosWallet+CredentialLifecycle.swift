// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosKeystore

extension SirosWallet {
    /// Get credentials, optionally including expired.
    public func getCredentials(includeExpired: Bool = false) async -> [StoredCredential] {
        let all = await credentialStore.getAll()
        if includeExpired { return all }
        let now = Int64(Date().timeIntervalSince1970)
        return all.filter { $0.expiresAt == nil || $0.expiresAt! > now }
    }

    /// Delete a credential by ID and sync to backend.
    public func deleteCredential(_ credentialId: Int64) async {
        let deletedBatchId = await credentialStore.getAll().first { $0.id == credentialId }?.batchId
        await credentialStore.delete(credentialId)
        await removeBbsHolderStateIfAny(credentialId: credentialId)
        // A deleted id can be reused (review finding) - an unrelated
        // credential later assigned this same id must not read back the
        // deleted one's cached status.
        credentialStatusCache.remove(credentialId)
        // If that was the last instance of its batch, its refresh_token
        // entry (if any) is now orphaned - privatedata-spec §6.2 requires
        // it not linger pointing at a batch that no longer exists.
        if let batchId = deletedBatchId {
            let remaining = await credentialStore.getAll()
            if !remaining.contains(where: { $0.batchId == batchId }) {
                await removeCredentialRefreshToken(batchId: batchId)
            }
        }
        if case .ready(let userId, let displayName, _, _) = state {
            let creds = await credentialStore.getAll()
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
        }
        await persistAndSyncKeystore()
    }

    /// Removes `credentialId`'s BBS holder state, if any - privatedata-spec
    /// §6.1.2 requires deleting the entity an entry names to delete the
    /// entry too, and `BbsHolderStateVault.remove`'s own doc comment says
    /// the same. Shared by every credential-deletion path
    /// (`deleteCredential`, `deleteRenewalSourceBatch`) rather than each
    /// repeating the same call - a no-op for a non-BBS credential (no entry
    /// ever existed under this id) and for a keystore that cannot hold
    /// extension entries at all (`bbsHolderStateVault` is `nil`).
    /// Best-effort, like `removeCredentialRefreshToken`: a locked keystore
    /// must not block the credential deletion itself (Copilot review, PR #194).
    func removeBbsHolderStateIfAny(credentialId: Int64) async {
        try? await bbsHolderStateVault?.remove(credentialId: String(credentialId))
    }
}
