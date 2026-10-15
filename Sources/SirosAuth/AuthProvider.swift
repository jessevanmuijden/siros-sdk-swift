// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Authenticator abstraction for FIDO2/WebAuthn operations.
/// SDK consumers provide their own platform-specific implementation
/// (e.g. ASAuthorizationController on iOS, CredentialManager on Android).
public protocol AuthProvider: AnyObject, Sendable {
    /// Create a new passkey credential (registration).
    func register(options: RegisterOptions) async throws -> RegisterResult

    /// Authenticate with an existing passkey (assertion).
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult

    /// Obtain PRF output for keystore key derivation.
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput

    /// Best-effort: undo the most recent `register(options:)` this provider
    /// performed, when the backend then refused the enrolment it was for
    /// (declined assertion aside - that path never creates anything). A
    /// provider backed by a real platform authenticator (e.g.
    /// `ASAuthorizationAuthProvider`) generally has no API to delete a
    /// platform passkey and leaves this a no-op - the created credential
    /// simply goes unused on the device, an accepted limitation. A fully
    /// local/dev provider (`LocalAuthProvider`) can and does remove it.
    func rollbackLastRegistration()
}

public extension AuthProvider {
    /// Default: nothing to roll back. See the protocol requirement's doc
    /// comment.
    func rollbackLastRegistration() {}
}

// MARK: - Registration types

public struct RegisterOptions: Sendable {
    public var rpId: String
    public var rpName: String
    public var userId: Data
    public var userName: String
    public var userDisplayName: String
    public var challenge: Data
    public var attestation: String
    public var authenticatorSelection: AuthenticatorSelection?
    public var prfSalt: Data?
    /// Credentials the backend already has for this RP/user that this
    /// registration must NOT recreate - WebAuthn's
    /// `excludeCredentials` (go-wallet-backend#352's "add a passkey" asks for
    /// this so an authenticator that replaces an existing discoverable
    /// credential for the same RP/user, when asked to create a new one with
    /// no exclusions, cannot silently invalidate it before the new
    /// registration is even accepted). A conforming `AuthProvider` applies
    /// these to the platform-authenticator AND security-key registration
    /// requests it offers; empty/nil excludes nothing.
    public var excludeCredentials: [AllowCredential]?

    public init(
        rpId: String,
        rpName: String,
        userId: Data,
        userName: String,
        userDisplayName: String,
        challenge: Data,
        attestation: String = "none",
        authenticatorSelection: AuthenticatorSelection? = nil,
        prfSalt: Data? = nil,
        excludeCredentials: [AllowCredential]? = nil
    ) {
        self.rpId = rpId
        self.rpName = rpName
        self.userId = userId
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.challenge = challenge
        self.attestation = attestation
        self.authenticatorSelection = authenticatorSelection
        self.prfSalt = prfSalt
        self.excludeCredentials = excludeCredentials
    }
}

public struct AuthenticatorSelection: Sendable {
    public var authenticatorAttachment: String?
    public var residentKey: String
    public var userVerification: String

    public init(
        authenticatorAttachment: String? = nil,
        residentKey: String = "required",
        userVerification: String = "preferred"
    ) {
        self.authenticatorAttachment = authenticatorAttachment
        self.residentKey = residentKey
        self.userVerification = userVerification
    }
}

public struct RegisterResult: Sendable {
    public var credentialId: Data
    public var attestationObject: Data
    public var clientDataJSON: Data
    public var prfOutput: PrfOutput?

    public init(credentialId: Data, attestationObject: Data, clientDataJSON: Data, prfOutput: PrfOutput? = nil) {
        self.credentialId = credentialId
        self.attestationObject = attestationObject
        self.clientDataJSON = clientDataJSON
        self.prfOutput = prfOutput
    }
}

// MARK: - Authentication types

public struct AuthenticateOptions: Sendable {
    public var rpId: String
    public var challenge: Data
    public var allowCredentials: [AllowCredential]?
    public var userVerification: String
    /// One PRF salt for whichever credential the user picks. Ignored when
    /// `prfSaltsByCredential` is non-empty.
    public var prfSalt: Data?
    /// PRF salt per credential ID - WebAuthn's `prf.evalByCredential`. Each
    /// account's passkey was sealed with its own salt, so login offers every
    /// loginable credential with its own salt and the authenticator evaluates
    /// PRF with the right one in a single ceremony; no fixed/shared salt, no
    /// guessing the account in advance, no second prompt. Takes precedence
    /// over `prfSalt` when non-empty.
    public var prfSaltsByCredential: [Data: Data]?

    public init(
        rpId: String,
        challenge: Data,
        allowCredentials: [AllowCredential]? = nil,
        userVerification: String = "preferred",
        prfSalt: Data? = nil,
        prfSaltsByCredential: [Data: Data]? = nil
    ) {
        self.rpId = rpId
        self.challenge = challenge
        self.allowCredentials = allowCredentials
        self.userVerification = userVerification
        self.prfSalt = prfSalt
        self.prfSaltsByCredential = prfSaltsByCredential
    }

    /// The salt that applies to `credentialId`.
    ///
    /// With a non-empty `prfSaltsByCredential`, only that map counts: the
    /// credential's own entry, or `nil` when it has none - never the shared
    /// `prfSalt`, which was meant for a different credential and would derive
    /// a key the container was not sealed with. The shared `prfSalt` applies
    /// only when the map is nil or empty.
    public func prfSalt(for credentialId: Data) -> Data? {
        if let byCredential = prfSaltsByCredential, !byCredential.isEmpty {
            return byCredential[credentialId]
        }
        return prfSalt
    }
}

public struct AllowCredential: Sendable {
    public var id: Data
    public var type: String

    public init(id: Data, type: String = "public-key") {
        self.id = id
        self.type = type
    }
}

public struct AuthenticateResult: Sendable {
    public var credentialId: Data
    public var authenticatorData: Data
    public var clientDataJSON: Data
    public var signature: Data
    public var userHandle: Data?
    public var prfOutput: PrfOutput?

    public init(
        credentialId: Data,
        authenticatorData: Data,
        clientDataJSON: Data,
        signature: Data,
        userHandle: Data? = nil,
        prfOutput: PrfOutput? = nil
    ) {
        self.credentialId = credentialId
        self.authenticatorData = authenticatorData
        self.clientDataJSON = clientDataJSON
        self.signature = signature
        self.userHandle = userHandle
        self.prfOutput = prfOutput
    }
}

public struct PrfOutput: Sendable {
    public var first: Data
    public var second: Data?

    public init(first: Data, second: Data? = nil) {
        self.first = first
        self.second = second
    }
}

// MARK: - Session

/// Session tokens returned after successful authentication.
public struct AuthSession: Codable, Sendable, Equatable {
    public var appToken: String
    public var uuid: String
    public var displayName: String?
    public var username: String?
    public var refreshToken: String?
    public var did: String?
    public var privateData: String?
    public var tenantId: String?

    public init(
        appToken: String,
        uuid: String,
        displayName: String? = nil,
        username: String? = nil,
        refreshToken: String? = nil,
        did: String? = nil,
        privateData: String? = nil,
        tenantId: String? = nil
    ) {
        self.appToken = appToken
        self.uuid = uuid
        self.displayName = displayName
        self.username = username
        self.refreshToken = refreshToken
        self.did = did
        self.privateData = privateData
        self.tenantId = tenantId
    }
}
