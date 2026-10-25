// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosAuth

/// The word the user must type to confirm deleting the account.
public let accountDeletionConfirmation = "DELETE"

/// Supplies the step-up passkey assertion for `SirosWallet.deleteAccount`.
/// The options carry the backend's challenge and the caller's own passkeys,
/// with user verification required.
public typealias StepUpAssertionProvider = @Sendable (AuthenticateOptions) async throws -> AuthenticateResult

/// One piece of local state that could not be removed after the account was
/// deleted.
public struct LocalWipeFailure: Sendable, Equatable {
    public let component: String
    public let message: String

    public init(component: String, message: String) {
        self.component = component
        self.message = message
    }
}

/// What the local wipe after an accepted deletion could not remove. The wipe
/// continues past a failing step, so this lists every one.
public struct LocalWipeReport: Sendable, Equatable {
    public let failures: [LocalWipeFailure]
    public var isComplete: Bool { failures.isEmpty }

    public init(failures: [LocalWipeFailure] = []) {
        self.failures = failures
    }
}

/// Why a deletion was not carried out but may be retried with a new
/// assertion. Local state is kept.
public enum DeleteAccountRetryReason: Sendable, Equatable {
    /// `409 DELETION_INCOMPLETE`: the account still exists.
    case incomplete(message: String?)
    /// `401 STEP_UP_FAILED`: the assertion did not verify.
    case stepUpFailed
    /// `410 STEP_UP_EXPIRED`: the assertion was older than 2 minutes.
    case stepUpExpired
    /// `401 STEP_UP_REQUIRED`: the backend saw no assertion.
    case stepUpRequired
}

/// Why a deletion could not be attempted or was refused outright. Local state
/// is kept.
public enum DeleteAccountFailure: Sendable, Equatable {
    /// The typed confirmation was not `DELETE` (checked before any request,
    /// and again by the backend's `400 CONFIRMATION_REQUIRED`).
    case confirmationRequired
    case notLoggedIn
    /// `400 NO_PASSKEY`: the account has no passkey, so no step-up is possible.
    case noPasskey
    /// `403`: the session token may not delete the account (it lacks the `w`
    /// scope).
    case notPermitted
    /// The passkey assertion could not be obtained (cancelled, unavailable).
    case stepUpAborted(message: String)
    /// `401`: the session token is revoked or expired.
    case sessionRejected
    /// `404`: the backend does not know the account.
    case accountNotFound
    /// Transport failure or a response outside the contract.
    case requestFailed(message: String)
}

/// Outcome of `SirosWallet.deleteAccount`. Expected outcomes are values, not
/// thrown errors.
///
/// Only `deleted`, `cleanupPending` and `operatorRequired` wipe local state;
/// every other case leaves it untouched.
public enum DeleteAccountResult: Sendable, Equatable {
    /// `200`: the account is erased.
    case deleted(localWipe: LocalWipeReport)
    /// `202 DELETION_CLEANUP_PENDING`: the account is gone and an operator
    /// clears the last remainder. Do not repeat the request.
    case cleanupPending(localWipe: LocalWipeReport)
    /// `202 DELETION_OPERATOR_REQUIRED`: tokens are revoked and an operator
    /// finishes the deletion. Do not repeat the request.
    case operatorRequired(localWipe: LocalWipeReport)
    case retryNeeded(DeleteAccountRetryReason)
    case failed(DeleteAccountFailure)

    /// Whether local state was wiped.
    public var wipedLocalState: Bool {
        switch self {
        case .deleted, .cleanupPending, .operatorRequired: return true
        case .retryNeeded, .failed: return false
        }
    }
}
