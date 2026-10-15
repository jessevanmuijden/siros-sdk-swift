// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Backend error code: `401` from `register-finish`, the account has a passkey
/// and the request carried no authorising assertion.
public let errorEnrollmentAuthorizationRequired = "ENROLLMENT_AUTHORIZATION_REQUIRED"
/// Backend error code: `401` from `register-finish`, the authorising assertion
/// is not from one of the caller's passkeys, is over another challenge, or does
/// not verify.
public let errorEnrollmentAuthorizationFailed = "ENROLLMENT_AUTHORIZATION_FAILED"

/// What `POST /user/session/webauthn/register-begin` returned: the passkey to
/// create (`createOptions`) and, when the account already has a passkey, the
/// assertion one of them must make to authorise the addition (`authorization`).
///
/// Both ceremonies are answered in the one `register-finish`. The challenge is
/// single use and expires after five minutes; a refused finish consumes it.
public struct PasskeyEnrollmentChallenge: Sendable {
    public let challengeId: String
    public let username: String?
    /// The credential to create, as the backend asked for it (without a PRF
    /// salt; the caller adds its own).
    public let createOptions: RegisterOptions
    /// The assertion an existing passkey must make; nil for an account with no
    /// passkey yet.
    public let authorization: AuthenticateOptions?

    public init(challengeId: String, username: String?, createOptions: RegisterOptions, authorization: AuthenticateOptions?) {
        self.challengeId = challengeId
        self.username = username
        self.createOptions = createOptions
        self.authorization = authorization
    }

    /// `json` has had its `{"$b64u": ...}` values unwrapped (`TaggedBinary.decode`).
    init(json: [String: Any]) throws {
        func malformed(_ what: String) -> SirosError {
            .backendApi(code: 0, message: "Missing \(what) in register-begin response", body: "")
        }
        guard let challengeId = json["challengeId"] as? String, !challengeId.isEmpty else {
            throw malformed("challengeId")
        }
        guard let create = (json["createOptions"] as? [String: Any])?["publicKey"] as? [String: Any] else {
            throw malformed("createOptions.publicKey")
        }
        guard let rp = create["rp"] as? [String: Any], let rpId = rp["id"] as? String, !rpId.isEmpty else {
            throw malformed("rp.id")
        }
        guard let challengeB64 = create["challenge"] as? String else { throw malformed("challenge") }
        let challenge = WebAuthnAuthClient.base64UrlDecode(challengeB64)
        guard !challenge.isEmpty else { throw malformed("challenge") }
        guard let user = create["user"] as? [String: Any], let userIdB64 = user["id"] as? String else {
            throw malformed("user.id")
        }
        let userId = WebAuthnAuthClient.base64UrlDecode(userIdB64)
        guard !userId.isEmpty else { throw malformed("user.id") }
        let username = json["username"] as? String
        let userName = user["name"] as? String ?? username ?? ""
        let selection = (create["authenticatorSelection"] as? [String: Any]).map {
            AuthenticatorSelection(
                authenticatorAttachment: $0["authenticatorAttachment"] as? String,
                residentKey: $0["residentKey"] as? String ?? "required",
                userVerification: $0["userVerification"] as? String ?? "preferred"
            )
        }
        // The credentials this registration must not recreate - see
        // `RegisterOptions.excludeCredentials`'s doc comment. Malformed
        // entries are skipped rather than failing the whole challenge: an
        // exclusion list that can't be fully honoured is still better applied
        // partially than discarded outright (the backend remains the source
        // of truth and will itself reject a replayed/invalid registration).
        let excludeCredentials: [AllowCredential] = (create["excludeCredentials"] as? [[String: Any]] ?? []).compactMap { entry in
            guard let id = entry["id"] as? String else { return nil }
            return AllowCredential(id: WebAuthnAuthClient.base64UrlDecode(id), type: entry["type"] as? String ?? "public-key")
        }

        var authorization: AuthenticateOptions?
        if let raw = json["authorization"] {
            // Present but unusable must not read as "no passkey to authorise
            // with": that would send a finish the backend then refuses, after
            // spending the ceremony.
            guard let publicKey = (raw as? [String: Any])?["publicKey"] as? [String: Any],
                  let authRpId = publicKey["rpId"] as? String, !authRpId.isEmpty,
                  let authChallengeB64 = publicKey["challenge"] as? String else {
                throw malformed("authorization.publicKey")
            }
            let authChallenge = WebAuthnAuthClient.base64UrlDecode(authChallengeB64)
            guard !authChallenge.isEmpty else { throw malformed("authorization.publicKey.challenge") }
            let allowed = (publicKey["allowCredentials"] as? [[String: Any]] ?? []).compactMap { entry -> AllowCredential? in
                guard let id = entry["id"] as? String else { return nil }
                return AllowCredential(id: WebAuthnAuthClient.base64UrlDecode(id), type: entry["type"] as? String ?? "public-key")
            }
            authorization = AuthenticateOptions(
                rpId: authRpId,
                challenge: authChallenge,
                allowCredentials: allowed.isEmpty ? nil : allowed,
                userVerification: publicKey["userVerification"] as? String ?? "required"
            )
        }

        self.init(
            challengeId: challengeId,
            username: username,
            createOptions: RegisterOptions(
                rpId: rpId,
                rpName: rp["name"] as? String ?? rpId,
                userId: userId,
                userName: userName,
                userDisplayName: user["displayName"] as? String ?? userName,
                challenge: challenge,
                attestation: create["attestation"] as? String ?? "none",
                authenticatorSelection: selection,
                excludeCredentials: excludeCredentials.isEmpty ? nil : excludeCredentials
            ),
            authorization: authorization
        )
    }
}

/// The backend's answer to `POST /user/session/webauthn/register-begin`.
public enum AddPasskeyBegin: Sendable {
    /// `200`: the ceremonies to run.
    case ready(PasskeyEnrollmentChallenge)
    /// `403`: the token lacks the scope to enrol a passkey.
    case forbidden(message: String?)
    /// `401`: the bearer token is revoked or expired.
    case sessionRevoked(message: String?)
}

/// The backend's answer to `POST /user/session/webauthn/register-finish`, for
/// every outcome it defines. Except for `added`, every outcome leaves the
/// account unchanged, and a refused finish has consumed its challenge: start
/// again from `BackendApiClient.passkeyRegisterBegin()`.
public enum AddPasskeyOutcome: Sendable, Equatable {
    /// `200`: the passkey was added; `credentialId` is the backend's id for it.
    case added(credentialId: String?)
    /// `401 ENROLLMENT_AUTHORIZATION_REQUIRED`: the account has a passkey and no
    /// `authorization` was sent.
    case authorizationRequired(message: String?)
    /// `401 ENROLLMENT_AUTHORIZATION_FAILED`: the assertion is not from one of
    /// the caller's passkeys, is over another challenge, or does not verify.
    case authorizationFailed(message: String?)
    /// `404`: the challenge is unknown, expired or already consumed.
    case retryNeeded(message: String?)
    /// `412`: the private data changed on the backend since it was read;
    /// `currentEtag` is the backend's current ETag.
    case privateDataConflict(currentEtag: String?)
    /// `400` / `403`: the new passkey was refused (it did not verify, or its
    /// authenticator is not allowed).
    case registrationRejected(status: Int, message: String?)
    /// `401` without an enrolment code: the bearer token is revoked or expired.
    case sessionRevoked(message: String?)
}
