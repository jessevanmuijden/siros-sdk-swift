// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Backend error code: the delete request carried no step-up assertion.
public let errorStepUpRequired = "STEP_UP_REQUIRED"
/// Backend error code: the step-up assertion did not verify (wrong user, bad
/// signature, user verification missing, challenge already used).
public let errorStepUpFailed = "STEP_UP_FAILED"
/// Backend error code: the step-up challenge is older than 2 minutes.
public let errorStepUpExpired = "STEP_UP_EXPIRED"
/// Backend error code: the typed confirmation was missing or not `DELETE`.
public let errorConfirmationRequired = "CONFIRMATION_REQUIRED"
/// Backend error code: `202`, the account is deleted but an operator must
/// clear the remainder. Repeating the request is pointless.
public let errorDeletionCleanupPending = "DELETION_CLEANUP_PENDING"
/// Backend error code: `202`, tokens are revoked and the deletion has begun but
/// only an operator can finish it. Repeating the request is pointless.
public let errorDeletionOperatorRequired = "DELETION_OPERATOR_REQUIRED"
/// Backend error code: `400` from `delete-begin`, the account has no passkey to
/// authorise the deletion with.
public let errorNoPasskey = "NO_PASSKEY"
/// Backend error code: `409`, the account still exists; repeat with a fresh
/// step-up assertion.
public let errorDeletionIncomplete = "DELETION_INCOMPLETE"

/// The step-up challenge returned by `POST /user/session/delete-begin`: what a
/// passkey needs to produce the assertion that authorises deleting the account.
public struct AccountDeletionChallenge: Sendable {
    public let challengeId: String
    public let rpId: String
    public let challenge: Data
    /// The caller's own passkeys; empty when the backend named none.
    public let allowCredentials: [AllowCredential]
    public let userVerification: String

    public init(
        challengeId: String,
        rpId: String,
        challenge: Data,
        allowCredentials: [AllowCredential],
        userVerification: String = "required"
    ) {
        self.challengeId = challengeId
        self.rpId = rpId
        self.challenge = challenge
        self.allowCredentials = allowCredentials
        self.userVerification = userVerification
    }

    init(json: [String: Any]) throws {
        func malformed(_ what: String) -> SirosError {
            .backendApi(code: 0, message: "Missing \(what) in delete-begin response", body: "")
        }
        guard let challengeId = json["challengeId"] as? String, !challengeId.isEmpty else {
            throw malformed("challengeId")
        }
        guard let publicKey = json["publicKey"] as? [String: Any] else { throw malformed("publicKey") }
        guard let rpId = publicKey["rpId"] as? String, !rpId.isEmpty else { throw malformed("rpId") }
        guard let challengeB64 = publicKey["challenge"] as? String else { throw malformed("challenge") }
        let challenge = WebAuthnAuthClient.base64UrlDecode(challengeB64)
        guard !challenge.isEmpty else { throw malformed("challenge") }
        // The backend answers either a non-empty passkey list or NO_PASSKEY.
        // A missing, empty or partly malformed list must not degrade into a
        // discoverable-credential prompt, so refuse it outright.
        guard let rawAllowed = publicKey["allowCredentials"] as? [[String: Any]], !rawAllowed.isEmpty else {
            throw malformed("allowCredentials")
        }
        var allowed: [AllowCredential] = []
        for entry in rawAllowed {
            guard let id = entry["id"] as? String else { throw malformed("allowCredentials") }
            let decoded = WebAuthnAuthClient.base64UrlDecode(id)
            guard !decoded.isEmpty else { throw malformed("allowCredentials") }
            allowed.append(AllowCredential(id: decoded, type: entry["type"] as? String ?? "public-key"))
        }
        self.init(
            challengeId: challengeId,
            rpId: rpId,
            challenge: challenge,
            allowCredentials: allowed,
            userVerification: publicKey["userVerification"] as? String ?? "required"
        )
    }
}

/// What the backend answered to `DELETE /user/session`, one case per outcome
/// in its contract.
public enum AccountDeletionResponse: Sendable, Equatable {
    /// `200 DELETED`.
    case deleted
    /// `202 DELETION_CLEANUP_PENDING`: the account is gone; an operator clears
    /// the remainder. Do not repeat the request.
    case cleanupPending
    /// `202 DELETION_OPERATOR_REQUIRED`: tokens are revoked for good, only an
    /// operator can finish. Do not repeat the request.
    case operatorRequired
    /// `409 DELETION_INCOMPLETE`: the account is kept; repeat with a fresh
    /// assertion.
    case incomplete(message: String?)
    /// `401 STEP_UP_REQUIRED`.
    case stepUpRequired
    /// `401 STEP_UP_FAILED`.
    case stepUpFailed
    /// `410 STEP_UP_EXPIRED`.
    case stepUpExpired
    /// `400 CONFIRMATION_REQUIRED`.
    case confirmationRequired
    /// Any other `401`: the session token is revoked or expired.
    case sessionRejected
    /// `404`: the backend does not know the account.
    case accountNotFound

    /// A `2xx` body; nil when it is neither the `200` nor a known `202` shape.
    init?(success json: [String: Any]) {
        switch json["error"] as? String {
        case errorDeletionCleanupPending: self = .cleanupPending
        case errorDeletionOperatorRequired: self = .operatorRequired
        case nil where json["result"] as? String == "DELETED": self = .deleted
        default: return nil
        }
    }

    /// An HTTP failure; nil when it is outside the delete contract.
    init?(failure error: SirosError) {
        guard case let .backendApi(code, _, _) = error else { return nil }
        let apiCode = error.apiErrorCode
        switch (code, apiCode) {
        case (401, errorStepUpRequired): self = .stepUpRequired
        case (401, errorStepUpFailed): self = .stepUpFailed
        case (401, _): self = .sessionRejected
        case (410, errorStepUpExpired): self = .stepUpExpired
        case (400, errorConfirmationRequired): self = .confirmationRequired
        case (409, errorDeletionIncomplete): self = .incomplete(message: error.serverMessage)
        case (404, _): self = .accountNotFound
        default: return nil
        }
    }
}
