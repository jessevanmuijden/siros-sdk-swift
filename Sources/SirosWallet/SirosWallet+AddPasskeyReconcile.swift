// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore

/// What the backend's private data says about an enrolment whose `register-finish` response was lost.
enum UnknownFinishResolution {
    /// The container the backend holds already has the new passkey's PRF entry: it stored the enrolment.
    case adopted
    /// The backend holds a container without it: it did not store the enrolment.
    case notStored
    /// The backend could not be asked (or answered something unreadable).
    case unresolved
}

/// An enrolment whose outcome is still unknown: the backend may hold the new passkey and its PRF entry while this
/// wallet's keystore and caches do not. Until it is reconciled, ordinary exports and syncs are blocked, because an
/// ordinary private-data write carries no `If-Match` precondition and would overwrite the entry the backend may hold.
struct PendingEnrolmentReconcile {
    let accountId: String?
    let credentialId: Data
    let prfSalt: Data
    let nickname: String
}

extension SirosWallet {
    /// Whether an unknown enrolment is waiting to be reconciled (ordinary syncs are blocked meanwhile).
    var enrolmentSyncBlocked: Bool {
        lock.lock(); defer { lock.unlock() }
        return pendingEnrolmentReconcile != nil
    }

    /// The container bytes of a `GET /user/session/private-data` answer, or nil when it carries none.
    static func privateDataContainer(from response: [String: Any]) -> Data? {
        guard let value = response["privateData"] else { return nil }
        if let object = value as? [String: Any], let b64 = object["$b64u"] as? String { return Self.b64UrlDecode(b64) }
        if let text = value as? String { return Data(text.utf8) }
        return nil
    }

    private static func containerHasEntry(_ container: Data, credentialId: Data) -> Bool? {
        guard let parsed = try? EncryptedContainer.parse(container) else { return nil }
        return parsed.prfKeys.contains { $0.credentialId == credentialId }
    }

    /// Asked inside the enrolment's locked transaction when `register-finish` threw: fetches the backend's private
    /// data and decides whether it stored the enrolment. When it cannot be decided the enrolment is recorded as
    /// pending, syncs are blocked, and the keystore is locked.
    func reconcileUnknownFinish(prepared: PreparedPrfKey, context: EnrolmentContext) async -> UnknownFinishResolution {
        if let response = try? await context.client.getPrivateData(),
           let container = Self.privateDataContainer(from: response),
           let stored = Self.containerHasEntry(container, credentialId: context.created.credentialId) {
            return stored ? .adopted : .notStored
        }
        lock.lock()
        pendingEnrolmentReconcile = PendingEnrolmentReconcile(
            accountId: sessionStore.activeAccountId, credentialId: context.created.credentialId,
            prfSalt: context.prfSalt, nickname: context.nickname
        )
        lock.unlock()
        // The live keystore lacks the entry the backend may hold: lock it so the cached container (not this
        // keystore's export) is what the next unlock reads, and no export can drop the entry.
        keystore.lock()
        return .unresolved
    }

    /// Settles an enrolment left unknown: asks the backend for its private data and either adopts the enrolment (the
    /// container has the new passkey's PRF entry: the caches take the backend's container and the passkey is
    /// recorded; the keystore is locked so the next unlock reads it), or rolls the credential back (it does not).
    /// Returns nil when nothing is pending for the active account, and `.finishOutcomeUnknown` when the backend
    /// still cannot be asked (syncs stay blocked).
    ///
    /// Runs automatically at the start of `unlockKeystore()` and after `login()` fetched the private data; call it
    /// to retry earlier.
    public func reconcilePendingEnrolment() async -> AddPasskeyResult? {
        guard let pending = currentPendingEnrolment() else { return nil }
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client,
              let response = try? await client.getPrivateData(),
              let container = Self.privateDataContainer(from: response) else {
            return .finishOutcomeUnknown(message: "the backend could not be reached to settle the enrolment")
        }
        return applyReconcile(pending, container: container, relock: true)
    }

    /// `login()` already fetched the container: settle against it.
    func reconcilePendingEnrolment(fetched container: Data) {
        guard let pending = currentPendingEnrolment() else { return }
        _ = applyReconcile(pending, container: container, relock: false)
    }

    private func currentPendingEnrolment() -> PendingEnrolmentReconcile? {
        lock.lock(); defer { lock.unlock() }
        guard let pending = pendingEnrolmentReconcile, pending.accountId == sessionStore.activeAccountId else { return nil }
        return pending
    }

    private func applyReconcile(_ pending: PendingEnrolmentReconcile, container: Data, relock: Bool) -> AddPasskeyResult {
        guard let stored = Self.containerHasEntry(container, credentialId: pending.credentialId) else {
            return .finishOutcomeUnknown(message: "the backend's private data could not be read")
        }
        guard stored else {
            rollbackLocalCredential(credentialId: pending.credentialId)
            lock.lock(); pendingEnrolmentReconcile = nil; lock.unlock()
            return .notSubmitted(message: "the backend did not store the passkey")
        }
        lock.lock()
        if relock { sessionStore.privateDataJwe = String(data: container, encoding: .utf8) }
        pendingEnrolmentReconcile = nil
        recordAddedPasskey(pending.credentialId, prfSalt: pending.prfSalt, nickname: pending.nickname)
        lock.unlock()
        if relock {
            // The unlocked keystore (if the user already unlocked) lacks the entry: lock it so the next unlock reads
            // the adopted container.
            keystore.lock()
        }
        return .added(credentialId: nil)
    }
}
