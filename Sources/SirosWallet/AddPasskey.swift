// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// What `SirosWallet.addPasskey` did. Every outcome the backend defines is a
/// value here; only a transport failure or an unexpected response throws.
///
/// Only `added` changes anything: every other result leaves the account and
/// this wallet's keystore exactly as they were. A refused attempt has consumed
/// its challenge, so calling `addPasskey` again starts afresh.
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
    /// The backend accepted the passkey for the account/session this call
    /// started for, but the session has since moved on (a logout, or a
    /// login/re-login - possibly to a different account - completed while
    /// the backend round trip was in flight). The new passkey is real and
    /// usable on the account it was added to, but this call deliberately did
    /// NOT apply it to whatever account/keystore happens to be active now,
    /// to avoid recording it under the wrong identity. Call `addPasskey`
    /// again on that account's session if it still needs doing.
    case sessionChanged(message: String?)
}
