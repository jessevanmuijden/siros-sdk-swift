// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosKeystore

// Presentation history writes, moved out of `SirosWallet.swift` unchanged (apart from
// `reloadPresentationHistory` and `_presentationHistory` losing `private`, which an extension
// in another file needs) to keep that file under the lint file-length limit.
extension SirosWallet {
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

    /// Reload presentation history from the encrypted container after unlock.
    func reloadPresentationHistory() async {
        guard let allRaw = try? await keystore.getAllPresentationRecords() else { return }
        let decoder = JSONDecoder()
        let records = allRaw.values.compactMap { raw in
            try? decoder.decode(PresentationRecord.self, from: Data(raw.utf8))
        }.sorted(by: { $0.timestamp > $1.timestamp })
        lock.lock()
        _presentationHistory = records
        lock.unlock()
    }
}
