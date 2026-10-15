// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Context provided when a verifier requests credential presentation.
public struct PresentationRequest: Sendable {
    public var verifierName: String?
    /// Trust evaluation result with full metadata. Nil if trust was not evaluated.
    public var trustResult: TrustResult?
    public var candidates: [StoredCredential]
    public var requestedClaims: [[String]]

    public init(verifierName: String? = nil, trustResult: TrustResult? = nil, candidates: [StoredCredential], requestedClaims: [[String]] = []) {
        self.verifierName = verifierName
        self.trustResult = trustResult
        self.candidates = candidates
        self.requestedClaims = requestedClaims
    }
}

/// Callback protocol for wallet events that require user interaction.
///
/// Implement this and pass it to `SirosWallet.setEventListener()`.
public protocol WalletEventListener: AnyObject, Sendable {
    /// A verifier has requested credentials. Return the IDs the user consented to share.
    /// Return an empty list to cancel the presentation.
    func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64]

    /// A new credential has been received from an issuer.
    func onCredentialReceived(credential: StoredCredential)

    /// Called when a flow completes.
    ///
    /// - Parameter redirectUri: For an OID4VP `direct_post.jwt` presentation,
    ///   some verifiers (e.g. verifier.multipaz.org) return a `redirect_uri`
    ///   in their response so the user's browser/session can be returned to
    ///   the verifier's own page to see the result. When present, open it
    ///   (e.g. via `UIApplication.shared.open`), matching
    ///   `onAuthorizationRequired`'s pattern. Nil when the verifier didn't
    ///   return one (also true for every OID4VCI issuance completion).
    func onFlowComplete(flowId: String, redirectUri: String?)

    /// Called when a flow fails.
    ///
    /// - Parameter redirectUri: Some verifiers return a `redirect_uri` even
    ///   from their error-response endpoint (e.g. when the user declines an
    ///   OID4VP presentation) - see `onFlowComplete`'s equivalent parameter.
    ///   Nil unless the verifier provided one.
    func onFlowError(flowId: String, errorMessage: String, redirectUri: String?)

    /// The verifier asked for a credential this wallet cannot present, and the
    /// flow ended there (engine error code `NO_MATCHING_CREDENTIAL`). Fires
    /// immediately before `onFlowError` for the same failure - implement this
    /// one to say *which* credential is missing ("you need a PID first")
    /// instead of showing the generic message, and leave the generic path to
    /// apps that don't.
    ///
    /// - Parameters:
    ///   - requestedTypes: the credential types the verifier's DCQL query
    ///     asked for (SD-JWT VC `vct` values, mdoc doctypes), as the engine
    ///     derived them. Empty for a query naming none.
    ///   - reason: this wallet's own explanation of why nothing matched, as
    ///     sent with the empty match set - e.g. which types it looked for, or
    ///     that the matching credentials have no unused copies left.
    func onNoMatchingCredential(flowId: String, requestedTypes: [String], reason: String?, redirectUri: String?)

    /// An issuer requires user authorization (OAuth consent).
    func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String)

    /// An issuer requires a transaction code (PIN).
    /// Return the PIN value, or nil to cancel.
    func onTxCodeRequired(flowId: String, description: String?) -> String?

    /// The current session could not be silently refreshed and is no longer
    /// valid - e.g. the engine WebSocket's token refresh failed before a
    /// reconnect, or repeated REST calls were rejected as unauthenticated.
    /// Unlike `onFlowError` (a specific flow's failure, session otherwise
    /// fine), this means the whole session is gone - route the user to the
    /// login screen rather than surfacing a generic error message.
    ///
    /// Since SID-AUTH-06 the SDK attempts exactly one login itself right after
    /// this fires: a lifecycle cut-off is indistinguishable from an expired
    /// session until that login is refused with `WALLET_SUSPENDED` /
    /// `WALLET_REVOKED`, which is what turns it into
    /// `WalletState.lifecycleBlocked` rather than an endless reauth loop. So
    /// an implementation should show its login/progress screen and wait for
    /// the state to change - it must NOT call `login()` itself, or two
    /// WebAuthn ceremonies race on the session store, the wallet state and the
    /// engine session.
    func onReauthenticationRequired()

    /// The backend refuses this installation because of its wallet instance's
    /// lifecycle (SID-AUTH-06): the instance was suspended, the instance was
    /// revoked, or the whole wallet was deactivated and its data erased. Fired
    /// when `SirosWallet` enters `WalletState.lifecycleBlocked` - from a login,
    /// a keystore unlock, a session resume, or the SDK's own single re-login
    /// after a token cut-off.
    ///
    /// Unlike `onReauthenticationRequired()` this is not "prompt again":
    /// another login attempt with the same passkey is refused the same way
    /// until someone else acts. `.suspended` is lifted by reactivating the
    /// instance from another device; `.revoked` is terminal *for this
    /// installation's instance* and needs a fresh enrollment; `.deactivated`
    /// is terminal for the whole wallet in this tenant.
    ///
    /// `.revoked` does **not** imply the wallet was deactivated and erased -
    /// the account's other passkeys and devices keep working - so nothing
    /// local is discarded for it or for `.suspended`, and this callback is not
    /// licence to drop account state. Only `.deactivated` says the wallet is
    /// gone, and by then the SDK has forgotten the cached account itself - if
    /// it could tell which one. A login refused before its passkey resolved to
    /// a known account leaves every cached account in place rather than delete
    /// one the refusal was not about, so read
    /// `WalletState.lifecycleBlocked`'s `cachedAccounts` for what is left
    /// instead of assuming the login picker is now empty.
    ///
    /// The three are told apart by the refusal's `scope`
    /// (go-wallet-backend#340), not by `message`, which is prose for the user.
    /// Apps that already render `WalletState.lifecycleBlocked` need not
    /// implement this.
    func onWalletLifecycleBlocked(reason: SirosError.WalletLifecycleRefusal, message: String?)

    /// A credential batch was renewed (credential re-issuance/renewal plan,
    /// Phase 2, `AttributeDiffService`-equivalent, ISSU_59) and at least one
    /// claim differs from the batch it replaced. The renewal's own network
    /// round-trip was silent (no user interaction), but ISSU_59 mandates
    /// notifying the user of any claim change - the app should surface this
    /// (e.g. wallet-frontend #73's consent/notification popup) even though
    /// `onCredentialReceived` already fired for the new credential.
    ///
    /// Not called when a renewal completes with identical claims (the fully
    /// silent case per plan §4.4) - only when `CredentialAttributeDiff.hasChanges`
    /// is true.
    func onCredentialRenewedWithAttributeDiff(credential: StoredCredential, diff: CredentialAttributeDiff)

    /// A credential batch's eligible (unused) instance count has dropped to
    /// or below its renew threshold (credential re-issuance/renewal plan
    /// §4.3/wallet-frontend #72 parity - EUDI ARF ISSU_50/54's proactive
    /// renewal trigger). The app should surface this as a near-expiry
    /// banner/nudge (Phase 3 UX, not yet built here) rather than waiting for
    /// the reactive fully-exhausted case. Fires at most once per drop below
    /// threshold per `SirosWallet.recordPresentation` call - not repeated on
    /// every recomposition.
    func onCredentialNearExpiry(credential: StoredCredential, eligibleRemaining: Int, threshold: Int)

    /// A transaction-log record (EC TS12 section 5.3) could not be made
    /// durable. The record is still held for the running session.
    func onTransactionLogFailure()
}

/// Default implementations for optional callbacks.
public extension WalletEventListener {
    func onCredentialReceived(credential: StoredCredential) {}
    func onFlowComplete(flowId: String, redirectUri: String?) {}
    func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) {}
    func onNoMatchingCredential(flowId: String, requestedTypes: [String], reason: String?, redirectUri: String?) {}
    func onAuthorizationRequired(flowId: String, authorizationUrl: String, redirectUri: String, state: String) {}
    func onTxCodeRequired(flowId: String, description: String?) -> String? { nil }
    func onReauthenticationRequired() {
        // No-op by default: implementers only need to override this if they
        // want to route the user to a login screen on forced logout.
    }
    func onWalletLifecycleBlocked(reason: SirosError.WalletLifecycleRefusal, message: String?) {
        // No-op by default: the state change is the primary signal.
    }
    func onCredentialRenewedWithAttributeDiff(credential: StoredCredential, diff: CredentialAttributeDiff) {}
    func onCredentialNearExpiry(credential: StoredCredential, eligibleRemaining: Int, threshold: Int) {}
    func onTransactionLogFailure() {
        // No-op by default: implementers override to tell the user a record was not stored.
    }
}
