// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// What `SirosWallet.addPasskey` did. Every outcome the backend defines is a
/// value here; a transport failure before `register-finish` or an unexpected
/// response throws, and a transport failure OF `register-finish` is
/// ``finishOutcomeUnknown(message:)``.
///
/// Only `added` means the passkey is enrolled AND applied to this wallet.
/// ``sessionChanged(message:)`` (accepted, not applied here),
/// ``localCommitFailed(credentialId:message:)`` (accepted, keystore locked) and
/// ``finishOutcomeUnknown(message:)`` (unknown) leave a credential that may be
/// on the account; every other result leaves the account and this wallet's
/// keystore exactly as they were, with the new credential rolled back where the
/// `AuthProvider` can. A refused attempt has consumed its challenge, so calling
/// `addPasskey` again starts afresh.
public enum AddPasskeyResult: Sendable, Equatable {
    /// The passkey is on the account and its PRF entry is in the synced private
    /// data. `credentialId` is the backend's id for it.
    case added(credentialId: String?)
    /// The backend wanted an assertion from an existing passkey and none was sent.
    case authorizationRequired(message: String?)
    /// The backend rejected the authorising assertion. Try again with a passkey
    /// of this account.
    case authorizationFailed(message: String?)
    /// The authorising assertion could not be obtained (declined, cancelled, no
    /// authenticator).
    case authorizerUnavailable(message: String?)
    /// The new passkey could not be created (declined, cancelled, no authenticator).
    case passkeyCreationUnavailable(message: String?)
    /// The new passkey's authenticator returned no PRF output, so it cannot
    /// unlock the wallet's keystore and was not added. The passkey it created
    /// on the device is unused and may be removed.
    case prfUnsupported(message: String?)
    /// The challenge expired or was already used. Call `addPasskey` again.
    case retryNeeded(reason: String?)
    /// The private data changed on the backend (another device) since this one
    /// read it. Sync, then try again.
    case privateDataConflict(message: String?)
    /// The backend refused the new passkey (it did not verify, or its
    /// authenticator is not allowed).
    case registrationRejected(message: String?)
    /// The wallet is locked: a passkey can only be added while the keystore is
    /// unlocked.
    case walletLocked(message: String?)
    /// The session token lacks the scope to enrol a passkey.
    case insufficientScope(message: String?)
    /// The session token is revoked or expired; log in again.
    case sessionRevoked(message: String?)
    /// The backend ACCEPTED the passkey for the account/session this call
    /// started for, but the session has since moved on (a logout, or a
    /// login/re-login - possibly to a different account - completed while
    /// the backend round trip was in flight). The new passkey is real and
    /// usable on the account it was added to, but this call deliberately did
    /// NOT apply it to whatever account/keystore happens to be active now,
    /// to avoid recording it under the wrong identity. Call `addPasskey`
    /// again on that account's session if it still needs doing. Contrast
    /// ``notSubmitted(message:)``, where nothing was enrolled.
    case sessionChanged(message: String?)
    /// The session changed BEFORE the enrolment was sent: `register-finish` never went out, the credential just
    /// created was rolled back (where the `AuthProvider` can), and nothing is enrolled anywhere. Call `addPasskey`
    /// again on the active session if it still needs doing.
    case notSubmitted(message: String?)
    /// The request to `register-finish` failed in transport (timeout, lost response, 5xx) and the backend could not
    /// be asked either, so whether it stored the passkey and its PRF entry is UNKNOWN. (When it CAN be asked, the
    /// wallet settles it at once: `.added` if the backend stored it, `.notSubmitted` if not.) The credential just
    /// created was NOT rolled back, the keystore was locked, and ordinary private-data syncs and exports are blocked
    /// until the enrolment is settled - an ordinary write carries no `If-Match` and would erase an entry the backend
    /// may hold. It is settled by ``SirosWallet/reconcilePendingEnrolment()``, and automatically at the next
    /// `unlockKeystore()` and `login()`.
    case finishOutcomeUnknown(message: String?)
    /// The backend accepted the passkey and the cached container carries its
    /// PRF entry, but this wallet's live keystore could not take the entry.
    /// The new passkey was NOT rolled back (it is on the account), and the
    /// keystore was locked so nothing can push a container without the entry;
    /// unlock the wallet again to continue with the entry in place.
    case localCommitFailed(credentialId: String?, message: String?)
}
