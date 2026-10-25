// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Observable wallet state. Apps observe `SirosWallet.state` to drive their UI.
public enum WalletState: Sendable, Equatable {
    /// Not authenticated. `cachedAccounts` are loginable accounts for the picker.
    case disconnected(cachedAccounts: [CachedAccount] = [])

    /// Authentication / keystore unlock in progress.
    case connecting

    /// Authenticated, keystore unlocked, ready.
    case ready(userId: String, displayName: String?, credentials: [StoredCredential], cachedAccounts: [CachedAccount] = [])

    /// Session resumed but keystore still locked (requires PRF).
    case keystoreLocked(userId: String, displayName: String?)

    /// An issuance or presentation flow is in progress.
    case flowActive(userId: String, displayName: String?, flowId: String, flowType: String, status: String, credentials: [StoredCredential])

    /// The backend refuses this installation because of its wallet instance's
    /// lifecycle (SID-AUTH-06): the instance is suspended, the instance was
    /// revoked, or the whole wallet has been deactivated and its data erased.
    /// Terminal for this session - it is not an error to retry or dismiss, but
    /// a condition that only someone else (another device, the provider) can
    /// lift.
    ///
    /// Entered from `login()`, `unlockKeystore()`, `resumeSession()` and from
    /// the SDK's own re-login after a token cut-off, whenever the
    /// authorization server answers `403` with `WALLET_SUSPENDED` /
    /// `WALLET_REVOKED`.
    ///
    /// `.suspended` and `.revoked` are scoped to *this* wallet instance and
    /// **forget nothing local**: `cachedAccounts` still lists this account,
    /// and the cached credentials stay, because the user's other devices and
    /// passkeys keep working. `.deactivated` is the whole wallet - every
    /// instance revoked, the data erased server-side - so the SDK forgets the
    /// affected account there, the same way `SirosWallet.forgetAccount(accountId:)`
    /// does, and `cachedAccounts` no longer lists it.
    ///
    /// The one qualification: the SDK only forgets an account it has
    /// identified. A login refused before its passkey resolved to a cached
    /// account - the ceremony never completed, or it completed with a
    /// credential this deployment does not know - leaves every cached account
    /// alone, because the alternative is deleting one the refusal was not
    /// about. So treat `.deactivated` as "this account is gone if it is
    /// listed", not as "`cachedAccounts` is now empty"; render whatever it
    /// actually contains.
    ///
    /// The three are told apart by the refusal's machine-readable `scope`
    /// (go-wallet-backend#340), never by `message` - which is prose for the
    /// user. A backend older than #340 sends no `scope`, and `WALLET_REVOKED`
    /// then resolves to the per-instance `.revoked`, so nothing local is lost
    /// on a backend that cannot say which it meant.
    ///
    /// What an app should offer: for `.suspended`, a retry - a later `login()`
    /// succeeds once the instance is reactivated from another device. For
    /// `.revoked` and `.deactivated`, a fresh enrollment; for `.deactivated`
    /// there is also nothing left of the old wallet to come back to.
    case lifecycleBlocked(
        reason: SirosError.WalletLifecycleRefusal,
        message: String?,
        cachedAccounts: [CachedAccount] = []
    )

    /// An error occurred.
    case error(message: String)
}
