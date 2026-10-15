// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// Manages encrypted credential key storage.
///
/// The keystore is unlocked using a PRF-derived key (from WebAuthn)
/// and contains private keys for credential signing operations.
/// The encrypted container is synchronized with the backend for
/// cross-device portability.
public protocol KeystoreManager: AnyObject, Sendable {
    /// Whether the keystore is currently unlocked and usable.
    var isUnlocked: Bool { get }

    /// Unlock the keystore using PRF-derived key material.
    ///
    /// - Parameters:
    ///   - prfOutput: raw PRF output from the WebAuthn authenticator (32 bytes).
    ///   - encryptedContainer: the encrypted container (may be empty for first-time setup).
    ///   - hkdfSalt: HKDF extraction salt (32 bytes).
    ///   - hkdfInfo: HKDF expansion info (e.g. "eDiplomas PRF").
    func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) async throws

    /// `unlock(prfOutput:encryptedContainer:hkdfSalt:hkdfInfo:)` with the real
    /// WebAuthn PRF extension salt (`prf.eval.first`/evalByCredential input)
    /// that produced `prfOutput`.
    ///
    /// - Parameter prfSalt: consumed only on first-time setup (an empty
    ///   `encryptedContainer`), where it is persisted into the new
    ///   container's own `PrfKeyInfo.prfSalt` - matching the wallet-frontend
    ///   wire format - instead of a disconnected random value, so a later
    ///   login, even from a device whose local account cache never saw this
    ///   registration, can recover the exact salt this credential needs from
    ///   the account's server-synced privateData rather than guessing. See
    ///   `SirosWallet`'s login recovery path. Ignored once a container
    ///   already exists: an existing entry's own stored salt is always
    ///   authoritative over whatever salt a caller happened to use for
    ///   *this* unlock call.
    ///
    /// A genuine protocol REQUIREMENT (default-implemented below to forward
    /// to the four-parameter overload, for conformers written before this
    /// existed) rather than merely a defaulted extension method - see
    /// `generateProof(audience:nonce:freshKey:holderBinding:)`'s doc comment
    /// for why that distinction matters when called through a
    /// `KeystoreManager` existential, which is exactly how `SirosWallet`
    /// holds its `keystore`.
    func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data,
        prfSalt: Data
    ) async throws

    /// Lock the keystore, clearing key material from memory.
    func lock()

    /// Wrap this unlocked keystore's main key for an additional passkey (the
    /// web wallet's `keystore.addPrf`) without changing anything yet.
    ///
    /// Returns the container that includes the new passkey's PRF entry, to be
    /// sent to the backend. Only once the backend accepted it is
    /// `commitPrfKey(_:)` called, so a refused enrolment leaves the keystore as
    /// it was. The main key and the wallet state are unchanged: the other
    /// passkeys keep working. `hkdfSalt` is the new entry's own; a login with
    /// that passkey must derive with it (it is the entry the keystore picks by
    /// HKDF salt).
    ///
    /// A genuine requirement, not a defaulted convenience: a keystore that
    /// cannot do this must say so rather than let an enrolment succeed with a
    /// container the new passkey cannot open (the default throws).
    ///
    /// - Throws: `KeystoreError.locked`, or `.invalidParameter` when the
    ///   container already has an entry for `credentialId` or this keystore
    ///   cannot add one.
    func preparePrfKey(
        credentialId: Data,
        prfOutput: Data,
        prfSalt: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) async throws -> PreparedPrfKey

    /// Make the `prepared` PRF entry part of this keystore's container, once
    /// the backend stored it.
    func commitPrfKey(_ prepared: PreparedPrfKey) async throws

    /// Give the ORIGINAL (first-time-setup) PRF entry its real credential ID,
    /// once one exists to give it - see `JweKeystore.setCredentialId`'s doc
    /// comment for why that entry is created with an empty ID in the first
    /// place and what goes wrong (a second passkey's HKDF salt masquerading
    /// as the original's on resume) if this is never called.
    ///
    /// A genuine protocol REQUIREMENT, not merely a defaulted extension
    /// method - same reason as `unlock(prfOutput:encryptedContainer:hkdfSalt:
    /// hkdfInfo:prfSalt:)` above: `SirosWallet` calls this through a
    /// `KeystoreManager` existential, where a conformer's own non-protocol
    /// method is invisible. Default-implemented as a no-op below for a
    /// keystore with no such concept (e.g. `WscdKeystoreAdapter`, which
    /// doesn't support `preparePrfKey` either).
    func setCredentialId(_ credentialId: Data)

    /// Generate a new keypair and return the key ID.
    func generateKey(algorithm: String) async throws -> String

    /// Sign a payload with the specified key.
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data

    /// Generate a proof JWT for credential issuance (c_nonce binding).
    /// When `freshKey` is true, a new key is generated for this proof (batch issuance).
    ///
    /// This names the Holder's key however the keystore itself sees fit - for
    /// the keystores here, the way their ``InteropProfile`` says. To choose
    /// per issuance instead, implement
    /// ``generateProof(audience:nonce:freshKey:holderBinding:)``, which is
    /// what an Issuer's advertised binding methods are negotiated into.
    func generateProof(
        audience: String,
        nonce: String,
        freshKey: Bool
    ) async throws -> String

    /// ``generateProof(audience:nonce:freshKey:)`` with the Holder binding
    /// decided per issuance.
    ///
    /// `holderBinding` is the one place HAIP and DIIP genuinely disagree, and
    /// OID4VCI allows only one of `jwk` and `kid` in a proof header, so it has
    /// to be decided per issuance: an Issuer that does not resolve DIDs cannot
    /// verify a DIIP-shaped proof, and a DIIP conformance suite will not accept
    /// a HAIP-shaped one. Nil uses whatever profile the keystore was built for,
    /// which is right whenever the caller has nothing more specific to go on.
    ///
    /// A protocol REQUIREMENT, not merely a defaulted extension method (review
    /// finding): a protocol extension's default implementation is statically
    /// dispatched, so calling this through a value statically typed as the
    /// `KeystoreManager` existential - which is exactly how `SirosWallet`
    /// holds its `keystore` - would always have run the ignore-and-forward
    /// default below, even when the underlying concrete instance is a
    /// `JweKeystore`/`WscdKeystoreAdapter` that overrides it; per-issuer HAIP/
    /// DIIP negotiation would have been silently inert in the one call site
    /// that actually matters. A conformer written before this requirement
    /// existed still compiles unchanged: the default implementation below
    /// satisfies it automatically.
    func generateProof(
        audience: String,
        nonce: String,
        freshKey: Bool,
        holderBinding: HolderBinding?
    ) async throws -> String

    /// Sign a verifiable presentation for OID4VP.
    ///
    /// - Parameter kid: the key ID bound to the credential(s) being
    ///   presented (see `StoredCredential.kid`) - when non-nil, signing MUST
    ///   use exactly this key (throwing if it isn't available) rather than
    ///   an arbitrary one, since a wallet holding more than one key (e.g.
    ///   after a batch issuance where each credential instance is bound to
    ///   its own device key) would otherwise silently sign with the wrong
    ///   key for every credential except whichever one happens to be first.
    ///   nil (the legacy no-credential-context call shape) preserves the old
    ///   first-available-key behavior.
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String

    /// Build a complete SD-JWT VP token with Key Binding JWT.
    ///
    /// - Parameter kid: the key ID bound to this credential (see
    ///   `signPresentation`'s doc comment for why this must be the exact
    ///   key, not an arbitrary available one).
    func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        kid: String?
    ) async throws -> String

    /// Build an mDoc DeviceResponse (ISO 18013-5) for OID4VP presentation.
    ///
    /// - Parameter kid: the key ID bound to this credential (see
    ///   `signPresentation`'s doc comment) - the DeviceResponse's
    ///   `deviceSignature` MUST be produced with the exact device key this
    ///   credential's MSO `deviceKeyInfo.deviceKey` embeds.
    func signMdocPresentation(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data

    /// Build an mDoc DeviceResponse (ISO 18013-5) for OID4VP presentation via
    /// the W3C Digital Credentials API, using the `OpenID4VPDCAPIHandover`
    /// session transcript (OpenID4VP 1.0 Appendix B.2.6) instead of
    /// ``signMdocPresentation(credentialBytes:disclosedClaims:nonce:audience:responseUri:verifierJwkThumbprint:)``'s
    /// redirect-flow `OpenID4VPHandover`.
    ///
    /// - Parameters:
    ///   - credentialBytes: Raw CBOR bytes of the IssuerSigned structure.
    ///   - disclosedClaims: Claim names to disclose (nil = all).
    ///   - nonce: Verifier-provided nonce.
    ///   - origin: The verified browser/page origin that called `navigator.credentials.get()`.
    ///   - encryptionPublicJwkThumbprint: JWK thumbprint of the verifier's
    ///     response-encryption key (present when `response_mode=dc_api.jwt`), nil otherwise.
    ///   - kid: the key ID bound to this credential (see `signMdocPresentation`'s doc comment).
    /// - Returns: Base64url-encoded DeviceResponse CBOR bytes.
    func signMdocPresentationForDCAPI(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data

    /// Build an mDoc DeviceResponse (ISO 18013-5) for a proximity (BLE)
    /// presentation, using the caller-supplied proximity `SessionTranscript`
    /// bytes (§9.1.5.1) instead of ``signMdocPresentation``'s redirect-flow
    /// `OpenID4VPHandover` or ``signMdocPresentationForDCAPI``'s
    /// `OpenID4VPDCAPIHandover` - see `ProximitySessionTranscript`'s doc
    /// comment for how that transcript is built from the device engagement,
    /// reader key, and handover context.
    ///
    /// - Parameters:
    ///   - credentialBytes: Raw CBOR bytes of the IssuerSigned structure.
    ///   - disclosedClaims: Claim names to disclose (nil = all).
    ///   - sessionTranscriptBytes: CBOR-encoded proximity `SessionTranscript`.
    ///   - kid: the key ID bound to this credential (see `signMdocPresentation`'s doc comment).
    /// - Returns: CBOR-encoded DeviceResponse bytes.
    func signMdocPresentationForProximity(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        sessionTranscriptBytes: Data,
        kid: String?
    ) async throws -> Data

    /// Export the encrypted container for backend sync.
    func exportEncryptedContainer() async throws -> Data

    /// List all key IDs in the keystore.
    func listKeys() -> [KeyInfo]

    // MARK: - Credential storage

    /// Store a credential's raw JSON inside the encrypted container.
    func saveCredential(id: Int64, json: String) async throws

    /// Get a stored credential's raw JSON by ID.
    func getCredential(id: Int64) async throws -> String?

    /// Get all stored credential JSON blobs.
    func getAllCredentials() async throws -> [Int64: String]

    /// Remove a credential by ID.
    func deleteCredential(id: Int64) async throws

    /// Remove all stored credentials.
    func clearCredentials() async throws

    // MARK: - Presentation history storage

    /// Store a presentation record's raw JSON inside the encrypted container.
    func savePresentationRecord(id: Int64, json: String) async throws

    /// Get all stored presentation record JSON blobs.
    func getAllPresentationRecords() async throws -> [Int64: String]

    /// Remove all stored presentation records.
    func clearPresentationRecords() async throws

    /// Generate `count` keypairs and return their public JWKs.
    /// Used for key attestation requests.
    func generateKeypairs(count: Int) async throws -> [KeypairInfo]

    /// Get the security properties for this keystore's signing keys.
    /// Used to populate KA JWT claims (CS-04 §7.1.3, Annex C §C.3.1).
    /// Returns nil if security properties are not available.
    func securityProperties() async -> SignerSecurityProperties?

    /// Get the security properties for a specific key, as reported by the
    /// underlying WSCD/signer. Used to populate a real backend-issued Key
    /// Attestation request's `security_properties` (CS-04 §7.1.3, Annex C
    /// §C.3.1) with the properties of the actual freshly-generated
    /// attestation keys, rather than the batch-agnostic [securityProperties]
    /// above. Returns nil if not available.
    func securityProperties(keyId: String) async -> SignerSecurityProperties?

    /// Return the attestation certificate chain for a key, if available -
    /// see `Signer.attestationChain`. Returns nil if attestation is not
    /// available; only a WSCD-backed keystore with a hardware-attesting
    /// plugin (e.g. FIDO2/CTAP2) actually has one to return.
    func attestationChain(keyId: String) async throws -> AttestationChain?

    /// Generate `count` fresh keypairs and build a single OID4VCI `attestation`
    /// proof-type Key Attestation JWT (spec: "Key Attestation in JWT format",
    /// proof type Appendix "attestation Proof Type") covering all of them via
    /// the `attested_keys` claim.
    ///
    /// Unlike the `jwt` proof type (one proof of possession per credential in
    /// the batch), the spec requires exactly one Key Attestation JWT per
    /// request regardless of `count` - the issuer is expected to mint one
    /// credential per entry in `attested_keys`.
    ///
    /// Default implementation throws so existing implementations continue to
    /// compile without attestation support.
    func generateKeyAttestation(nonce: String, count: Int) async throws -> String

    /// Build a self-signed JWT proof for an existing key: header `{typ, jwk =
    /// that key's own public JWK}`, claims `{iss, aud, iat, exp, jti, ...extraClaims}`.
    ///
    /// Used for OAuth Client Attestation PoP JWTs
    /// (draft-ietf-oauth-attestation-based-client-auth-10 §3.1) - both the
    /// one-time proof sent to this wallet's own backend to obtain a Wallet
    /// Instance Attestation (WIA) (`audience` = the wallet provider/backend,
    /// `extraClaims = ["nonce": <challenge>]`), and the per-issuance-flow
    /// proof sent (via the backend, forwarded as an HTTP header) to a
    /// credential issuer's authorization server alongside that WIA
    /// (`audience` = the issuer's AS, `extraClaims = ["challenge": ...]` when
    /// the AS publishes a `challenge_endpoint`).
    ///
    /// `issuer` is the caller's choice, not derived from the key - per the
    /// spec, `iss` should be the same OAuth `client_id` this wallet uses in
    /// the flow (matching the WIA's own `sub` claim, see
    /// `BackendApiClient.generateWIA`'s `clientId` param), not an instance
    /// identifier (that's what `cnf.jkt`, computed server-side from this
    /// proof's `jwk` header, is for).
    ///
    /// Deliberately takes an existing `keyId` rather than managing "the
    /// instance key" internally - callers are responsible for generating one
    /// persistent key (via `generateKey`) and remembering its ID across app
    /// restarts (the backend's WIA tracks/revokes wallet instances by this
    /// key's JWK thumbprint, so reusing a different key each time would
    /// silently register a new "instance" every call).
    ///
    /// Default implementation throws so existing implementations continue to
    /// compile without attestation support.
    func generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: [String: String]
    ) async throws -> String

    /// Sign an RFC 9449 DPoP proof JWT (`typ: dpop+jwt`, public key in the
    /// `jwk` header) with `keyId` over the HTTP method `htm` and URL `htu`.
    /// `nonce` is the server-provided DPoP nonce (§8) and `accessTokenHash`
    /// the `ath` claim for resource requests, both omitted when nil. Fresh
    /// `jti` and `iat` per call. Answers the engine's `sign_client_auth` sign
    /// request (go-wallet-backend#317), where the same key is the WIA `cnf`
    /// key so the sender-constrained token is bound to the attested key.
    ///
    /// Default implementation throws so existing implementations continue to
    /// compile.
    func generateDPoPProof(
        keyId: String,
        htm: String,
        htu: String,
        nonce: String?,
        accessTokenHash: String?
    ) async throws -> String
}

/// Default implementation for optional methods.
public extension KeystoreManager {
    /// Default: freshKey=false for backward compatibility.
    func generateProof(audience: String, nonce: String) async throws -> String {
        try await generateProof(audience: audience, nonce: nonce, freshKey: false)
    }

    /// Default: this keystore cannot add a passkey to its container.
    func preparePrfKey(
        credentialId: Data,
        prfOutput: Data,
        prfSalt: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) async throws -> PreparedPrfKey {
        throw KeystoreError.invalidParameter("This keystore cannot add a passkey to its container")
    }

    func commitPrfKey(_ prepared: PreparedPrfKey) async throws {
        throw KeystoreError.invalidParameter("This keystore cannot add a passkey to its container")
    }

    /// Default: nothing to do. See the protocol requirement's doc comment.
    func setCredentialId(_ credentialId: Data) {}

    /// Default for a conformer written before the `prfSalt` parameter
    /// existed: forwards unchanged, so a first-time-setup container it
    /// creates still gets *some* `PrfKeyInfo.prfSalt` (whatever its own
    /// four-parameter implementation generates internally) rather than
    /// failing to compile. Only the keystores in this SDK (`JweKeystore`/
    /// `WscdKeystoreAdapter`) override this to thread the real salt through.
    func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data,
        prfSalt: Data
    ) async throws {
        try await unlock(prfOutput: prfOutput, encryptedContainer: encryptedContainer, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
    }

    /// Default for a conformer - including a host's own `KeystoreManager`,
    /// written before this requirement existed - that does not override it.
    /// `nil` and `.embeddedJwk` forward to ``generateProof(audience:nonce:freshKey:)``
    /// unchanged, since a conformer written before DIIP existed can only ever
    /// have produced the HAIP/`embeddedJwk` shape - forwarding is exactly
    /// honoring the request. `.didJwk` is different: this conformer has no
    /// way to produce a did:jwk-shaped proof, and silently emitting the
    /// HAIP shape instead is not a safe fallback - it is a proof a
    /// DIIP-only Issuer will reject, sent as if it had been negotiated
    /// correctly. The keystores in this SDK override this method and
    /// handle `.didJwk` for real (see `JweKeystore`/`WscdKeystoreAdapter`,
    /// including over a hardware-backed WSCD key: a did:jwk is a pure
    /// function of the public key, so no WSCD plugin needs special-casing);
    /// only a third-party conformer that hasn't gets this default.
    func generateProof(
        audience: String,
        nonce: String,
        freshKey: Bool,
        holderBinding: HolderBinding?
    ) async throws -> String {
        if holderBinding == .didJwk {
            throw KeystoreError.invalidParameter(
                "This KeystoreManager does not implement generateProof(...holderBinding:) " +
                "and so cannot produce a did:jwk-shaped (DIIP) proof - refusing rather than " +
                "silently emitting a HAIP-shaped proof a DIIP-only Issuer would reject."
            )
        }
        return try await generateProof(audience: audience, nonce: nonce, freshKey: freshKey)
    }

    func securityProperties() async -> SignerSecurityProperties? { nil }
    func securityProperties(keyId: String) async -> SignerSecurityProperties? { nil }
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func signMdocPresentation(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        throw KeystoreError.invalidParameter("mDoc presentation not supported by this keystore")
    }

    func signMdocPresentationForDCAPI(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        throw KeystoreError.invalidParameter("mDoc DC API presentation not supported by this keystore")
    }

    func signMdocPresentationForProximity(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        sessionTranscriptBytes: Data,
        kid: String?
    ) async throws -> Data {
        throw KeystoreError.invalidParameter("mDoc proximity presentation not supported by this keystore")
    }

    func generateKeyAttestation(nonce: String, count: Int) async throws -> String {
        throw KeystoreError.invalidParameter("generateKeyAttestation not supported by this keystore")
    }

    func generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: [String: String]
    ) async throws -> String {
        throw KeystoreError.invalidParameter("generateKeyProof not supported by this keystore")
    }

    func generateDPoPProof(
        keyId: String,
        htm: String,
        htu: String,
        nonce: String?,
        accessTokenHash: String?
    ) async throws -> String {
        throw KeystoreError.invalidParameter("generateDPoPProof not supported by this keystore")
    }
}

/// The claims of an RFC 9449 §4.2 DPoP proof: `jti`, `htm`, `htu`, `iat`,
/// plus `nonce` (§8) and `ath` (§4.2, resource requests) when given.
/// Deliberately no `iss`/`aud`/`exp` - those are PoP claims, not DPoP ones.
/// Shared by every `KeystoreManager` implementation in this module.
func dpopClaims(htm: String, htu: String, nonce: String?, accessTokenHash: String?) -> [String: Any] {
    var claims: [String: Any] = [
        "jti": UUID().uuidString.lowercased(),
        "htm": htm,
        "htu": htu,
        "iat": Int(Date().timeIntervalSince1970),
    ]
    if let nonce, !nonce.isEmpty { claims["nonce"] = nonce }
    if let accessTokenHash, !accessTokenHash.isEmpty { claims["ath"] = accessTokenHash }
    return claims
}

/// Result of a generateKeypairs call.
public struct KeypairInfo: @unchecked Sendable {
    public let keyId: String
    public let publicKeyJWK: [String: Any]

    public init(keyId: String, publicKeyJWK: [String: Any]) {
        self.keyId = keyId
        self.publicKeyJWK = publicKeyJWK
    }
}

/// Information about a key in the keystore.
public struct KeyInfo: Sendable, Equatable {
    public let keyId: String
    public let algorithm: String
    public let createdAt: Int64

    public init(keyId: String, algorithm: String, createdAt: Int64 = 0) {
        self.keyId = keyId
        self.algorithm = algorithm
        self.createdAt = createdAt
    }
}

/// A container carrying a new passkey's PRF entry that has not been committed
/// to the keystore yet; see `KeystoreManager.preparePrfKey`.
public struct PreparedPrfKey: Sendable {
    /// The serialized container to store on the backend.
    public let container: Data
    /// The credential the entry is for.
    public let credentialId: Data
    /// The entry itself; nil for a keystore that has its own way to commit.
    let entry: PrfKeyInfo?

    public init(container: Data, credentialId: Data) {
        self.container = container
        self.credentialId = credentialId
        self.entry = nil
    }

    init(container: Data, credentialId: Data, entry: PrfKeyInfo) {
        self.container = container
        self.credentialId = credentialId
        self.entry = entry
    }
}

/// Keystore-related errors.
public enum KeystoreError: Error, Sendable {
    case locked
    case keyNotFound(String)
    case containerMissing(String)
    case cryptoError(String)
    case invalidContainer(String)
    case invalidParameter(String)
}

extension KeystoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .locked: return "Keystore is locked"
        case .keyNotFound(let id): return "Key not found: \(id)"
        case .containerMissing(let id): return "Container missing: \(id)"
        case .cryptoError(let msg): return "Crypto error: \(msg)"
        case .invalidContainer(let msg): return "Invalid container: \(msg)"
        case .invalidParameter(let msg): return "Invalid parameter: \(msg)"
        }
    }
}
