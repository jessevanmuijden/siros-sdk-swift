// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#endif
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// A durable OID4VCI renewal candidate for one credential batch - see
/// privatedata-spec SPEC.md §6.2 "S.credentialRefreshTokens". `dpopJwk` MUST
/// be presented back unchanged on every renewal of the same batch (RFC
/// 9449/ARF ISSU_65 key-binding), never regenerated client-side.
public struct CredentialRefreshTokenEntry: Sendable, Equatable {
    public let refreshToken: String
    public let dpopJwk: String?
    public let credentialIssuerIdentifier: String
    public let credentialConfigurationId: String
    /// Identifier of the client-held DPoP key the token is bound to when this
    /// wallet signed the DPoP proofs itself (`sign_client_auth`,
    /// go-wallet-backend#317) - `dpopJwk` is nil in that case. Presented back
    /// as `dpop_key_id` on renewal so the engine asks this wallet to sign with
    /// the same key.
    public let dpopKeyId: String?

    public init(
        refreshToken: String,
        dpopJwk: String?,
        credentialIssuerIdentifier: String,
        credentialConfigurationId: String,
        dpopKeyId: String? = nil
    ) {
        self.refreshToken = refreshToken
        self.dpopJwk = dpopJwk
        self.credentialIssuerIdentifier = credentialIssuerIdentifier
        self.credentialConfigurationId = credentialConfigurationId
        self.dpopKeyId = dpopKeyId
    }

    fileprivate func toJsonObject() -> [String: Any] {
        var dict: [String: Any] = [
            "refreshToken": refreshToken,
            "credentialIssuerIdentifier": credentialIssuerIdentifier,
            "credentialConfigurationId": credentialConfigurationId,
        ]
        if let dpopJwk { dict["dpopJwk"] = dpopJwk }
        if let dpopKeyId { dict["dpopKeyId"] = dpopKeyId }
        return dict
    }

    fileprivate static func fromJsonObject(_ obj: [String: Any]) -> CredentialRefreshTokenEntry? {
        guard let refreshToken = obj["refreshToken"] as? String,
              let credentialIssuerIdentifier = obj["credentialIssuerIdentifier"] as? String,
              let credentialConfigurationId = obj["credentialConfigurationId"] as? String else {
            return nil
        }
        return CredentialRefreshTokenEntry(
            refreshToken: refreshToken,
            dpopJwk: obj["dpopJwk"] as? String,
            credentialIssuerIdentifier: credentialIssuerIdentifier,
            credentialConfigurationId: credentialConfigurationId,
            dpopKeyId: obj["dpopKeyId"] as? String
        )
    }
}

/// JWE-based keystore implementation fully compatible with the wallet-frontend
/// encrypted container format.
///
/// Uses the same key hierarchy as the TypeScript web wallet:
///   PRF output → HKDF(SHA-256, salt, info="eDiplomas PRF") → prfKey (AES-GCM-256)
///   prfKey → unwrap ECDH private key → ECDH key agreement → AES-KW → unwrap mainKey
///   mainKey → decrypt JWE (alg=A256GCMKW, enc=A256GCM) → WalletStateContainer
///
/// This enables cross-device portability: the same encrypted private data
/// can be used by both the iOS native wallet and the web wallet,
/// provided the same passkey PRF is used on the same authenticator.
public final class JweKeystore: @unchecked Sendable, KeystoreManager, ExtensionStore {

    #if canImport(CryptoKit)

    private let mutex = NSLock()
    private var keys: [String: P256.Signing.PrivateKey] = [:]
    private var credentials: [Int64: String] = [:]
    private var presentationRecords: [Int64: String] = [:]
    private var _mainKey: SymmetricKey?
    private var containerMetadata: ContainerData?
    // Preserve full WalletStateContainer for round-trip fidelity
    private var preservedWalletState: [String: Any]?
    // Hardware-backed WSCD plugins' exported key metadata (kid ->
    // credential_handle/pubkey mappings, never private key material), keyed
    // by plugin ID - see privatedata-spec SPEC.md §6.1 "S.wscdCredentials".
    // This is what makes a FIDO2 (or future R2PS) hardware key addressable
    // again from ANY device sharing this account, not just the one that
    // enrolled it - a roaming CTAP2 authenticator can be tapped/plugged into
    // a different device entirely, and every device needs the same mapping.
    private var wscdCredentials: [String: String] = [:]
    // Namespaced client-defined state - privatedata-spec SPEC.md §6.1
    // "S.extensions", the normative replacement for one-off top-level fields
    // like `wscdCredentials` above.
    //
    // namespace -> entry key -> opaque value. Both levels are opaque to this
    // class: it stores and round-trips them and never interprets a value,
    // which is what lets a client carry a namespace it does not implement.
    //
    // Entry keys name an ENTITY - a kid, a credential id, a batch id - never
    // a subsystem (§6.1.1). That is a correctness rule, not a style one:
    // resolution is last-write-wins per (namespace, key), so one aggregate
    // entry per subsystem loses data whenever two devices write concurrently.
    private var extensions: [String: [String: String]] = [:]
    // OID4VCI renewal (credential re-issuance/renewal plan, Phase 2) -
    // refresh_token + the DPoP key it's bound to, keyed by the credential
    // batch's batchId - see privatedata-spec SPEC.md §6.2
    // "S.credentialRefreshTokens". The issuer binds refresh_token to the
    // exact DPoP key used at initial issuance (RFC 9449/ARF ISSU_65), so
    // dpopJwk must be presented back unchanged on every renewal of the same
    // batch, never regenerated - long-term storage of this key belongs only
    // on the client (this field); the backend never persists it, since it
    // only ever needs it ephemerally to forward a single renewal request.
    private var credentialRefreshTokens: [Int64: CredentialRefreshTokenEntry] = [:]

    // kid -> the DID that key pair is published under. Kept alongside `keys`
    // rather than recomputed on export, because a key read back from the
    // container must round-trip the DID it was stored with: recomputing it
    // under a different `didKeyVersion` would silently re-identify a key that
    // credentials are already bound to.
    private var keyDids: [String: String] = [:]

    /// The interoperability profile this keystore signs for - see
    /// ``InteropProfile``. It decides how a new key pair is named and, unless
    /// a caller overrides it per issuance, how the Holder's key is named in an
    /// OID4VCI proof. Defaults to HAIP, which is what this SDK has always
    /// sent.
    private let profile: InteropProfile

    /// How a newly generated key pair is named - see ``DidKeyVersion``.
    /// Follows `profile` unless a wallet needs something else. Keys already in
    /// the container keep whatever id they were stored with regardless of this
    /// setting, so changing it never orphans a credential.
    private let didKeyVersion: DidKeyVersion

    public init(profile: InteropProfile = .default, didKeyVersion: DidKeyVersion? = nil) {
        self.profile = profile
        self.didKeyVersion = didKeyVersion ?? DidKeyVersion.forProfile(profile)
    }

    /// Generate a key pair, name it per ``didKeyVersion``, and add it to the
    /// in-memory state. The caller is already holding `mutex`.
    private func registerNewKey() -> (keyId: String, key: P256.Signing.PrivateKey) {
        let privateKey = P256.Signing.PrivateKey()
        let identity = HolderIdentity.derive(
            publicJwk: JwtHelpers.publicKeyJwk(privateKey),
            version: didKeyVersion
        )
        keys[identity.kid] = privateKey
        keyDids[identity.kid] = identity.did
        return (identity.kid, privateKey)
    }

    /// Find a stored key pair by the `kid` a credential refers to it by.
    ///
    /// Matches on the stored id first, then falls back to comparing JWK
    /// thumbprints - see ``HolderIdentity/matches(storedKid:publicJwk:kid:)``
    /// for why a wallet naming its keys by `did:jwk` URL still has to answer
    /// to a thumbprint.
    private func findKeypair(kid: String) -> (keyId: String, key: P256.Signing.PrivateKey)? {
        if let key = keys[kid] { return (kid, key) }
        for (storedKid, key) in keys
        where HolderIdentity.matches(
            storedKid: storedKid,
            publicJwk: JwtHelpers.publicKeyJwk(key),
            kid: kid
        ) {
            return (storedKid, key)
        }
        return nil
    }

    /// The public JWK of a stored key pair, found by whichever identifier a
    /// credential names it with - see ``findKeypair(kid:)``.
    func publicKeyJwk(forKid kid: String) -> [String: String]? {
        mutex.lock()
        defer { mutex.unlock() }
        return findKeypair(kid: kid).map { JwtHelpers.publicKeyJwk($0.key) }
    }

    /// The DID a stored key pair is published under, if it has one.
    public func did(forKid kid: String) -> String? {
        mutex.lock()
        defer { mutex.unlock() }
        return keyDids[kid]
    }

    public var isUnlocked: Bool {
        mutex.lock()
        defer { mutex.unlock() }
        return _mainKey != nil
    }

    // MARK: - Unlock / Lock
    // (the four-parameter overload is in JweKeystore+DefaultPrfSaltUnlock.swift)

    public func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data,
        prfSalt: Data
    ) async throws {
        mutex.lock()
        defer { mutex.unlock() }

        if !encryptedContainer.isEmpty {
            let container = try EncryptedContainer.parse(encryptedContainer)
            guard let mainKeyInfo = container.mainKey else {
                throw KeystoreError.containerMissing("Container missing mainKey")
            }

            let prfKeyInfo = container.prfKeys.first(where: { !$0.credentialId.isEmpty && $0.hkdfSalt == hkdfSalt })
                ?? container.prfKeys.first(where: { $0.hkdfSalt == hkdfSalt })
                ?? container.prfKeys.first
            guard let prfKeyInfo else {
                throw KeystoreError.containerMissing("No PRF key entries in container")
            }

            let prfKey = EncryptedContainer.derivePrfKey(
                prfOutput: prfOutput,
                hkdfSalt: prfKeyInfo.hkdfSalt,
                hkdfInfo: prfKeyInfo.hkdfInfo
            )

            let unwrappedMainKey = try EncryptedContainer.unwrapMainKey(
                prfKey: prfKey,
                prfKeyInfo: prfKeyInfo,
                mainKeyInfo: mainKeyInfo
            )
            _mainKey = unwrappedMainKey

            let jwePayload = try decryptJwe(container.jwe, mainKey: unwrappedMainKey)
            if let jweDict = jwePayload as? [String: Any] {
                preservedWalletState = jweDict
            }
            loadWalletState(jwePayload)
            containerMetadata = container
        } else {
            // First-time setup
            let (newMainKey, newMainKeyInfo) = EncryptedContainer.generateMainKey()
            _mainKey = newMainKey

            let prfKey = EncryptedContainer.derivePrfKey(
                prfOutput: prfOutput,
                hkdfSalt: hkdfSalt,
                hkdfInfo: hkdfInfo
            )
            let encapsulation = try EncryptedContainer.wrapMainKey(
                prfKey: prfKey,
                mainKey: newMainKey,
                mainKeyInfo: newMainKeyInfo
            )

            containerMetadata = ContainerData(
                jwe: "",
                mainKey: newMainKeyInfo,
                prfKeys: [
                    PrfKeyInfo(
                        credentialId: Data(),
                        transports: nil,
                        prfSalt: prfSalt,
                        hkdfSalt: hkdfSalt,
                        hkdfInfo: hkdfInfo,
                        algorithm: AesGcmKeyAlgorithm(name: "AES-GCM", length: 256),
                        keypair: encapsulation.keypair,
                        unwrapKey: encapsulation.unwrapKey
                    )
                ]
            )
        }
    }

    public func setCredentialId(_ credentialId: Data) {
        mutex.lock()
        defer { mutex.unlock() }
        guard var meta = containerMetadata,
              !meta.prfKeys.isEmpty,
              meta.prfKeys[0].credentialId.isEmpty else { return }
        meta.prfKeys[0].credentialId = credentialId
        containerMetadata = meta
    }

    public func lock() {
        mutex.lock()
        defer { mutex.unlock() }
        keys.removeAll()
        credentials.removeAll()
        presentationRecords.removeAll()
        keyDids.removeAll()
        wscdCredentials.removeAll()
        extensions.removeAll()
        credentialRefreshTokens.removeAll()
        _mainKey = nil
        containerMetadata = nil
        preservedWalletState = nil
    }

    // MARK: - Key operations

    public func generateKey(algorithm: String = "ES256") async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        return registerNewKey().keyId
    }

    public func sign(keyId: String, payload: Data, algorithm: String = "ES256") async throws -> Data {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        guard let key = keys[keyId] else {
            throw KeystoreError.keyNotFound(keyId)
        }
        let header = JwtHelpers.jsonBase64Url(["alg": "ES256", "kid": keyId])
        let payloadB64 = EncryptedContainer.base64UrlEncode(payload)
        let signingInput = "\(header).\(payloadB64)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        let jws = "\(signingInput).\(sigB64)"
        return Data(jws.utf8)
    }

    /// The pre-DIIP call shape: this keystore's own profile decides.
    public func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String {
        try await generateProof(audience: audience, nonce: nonce, freshKey: freshKey, holderBinding: nil)
    }

    public func generateProof(
        audience: String,
        nonce: String,
        freshKey: Bool,
        holderBinding: HolderBinding?
    ) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        // `freshKey` means batch issuance: each credential in the batch must
        // be bound to its own key, or every copy shares one holder key and
        // presenting them is linkable. Honouring it also keeps the recorded
        // per-credential `kid` meaningful.
        let keyId: String
        let key: P256.Signing.PrivateKey
        if freshKey {
            (keyId, key) = registerNewKey()
        } else if let first = keys.first {
            (keyId, key) = (first.key, first.value)
        } else {
            (keyId, key) = registerNewKey()
        }

        // DIIP requires the `jwt` proof type to carry the Holder's did:jwk as
        // `iss` and to name the key with a `kid` from that DID document; HAIP
        // carries the key in the header instead. The caller may know which
        // this issuer speaks; when it does not, this keystore's own profile
        // decides.
        //
        // The DID is derived from the key rather than read from `keyDids`,
        // exactly as `WscdKeystoreAdapter` does it. A did:jwk *is* its public
        // key, so any key pair has one whether or not it was created under
        // `DidKeyVersion.jwk`. Requiring a stored did:jwk here made the whole
        // negotiation inert for the default wallet: `didKeyVersion` follows
        // `interopProfile`, which defaults to HAIP, so a negotiated `.didJwk`
        // could never be satisfied and every proof fell back to the HAIP shape
        // that a DIIP-only Issuer rejects. What a key was *created* as is a
        // storage question; how this issuance names its holder is not.
        //
        // For a keystore already on `DidKeyVersion.jwk` this is the same value
        // it stored - `createDidJwk` is deterministic over the canonical
        // public JWK - so nothing changes there.
        let binding = holderBinding ?? profile.holderBinding
        let publicJwk = JwtHelpers.publicKeyJwk(key)
        let did = binding == .didJwk ? Did.createDidJwk(publicJwk) : nil
        var headerFields: [String: Any] = ["alg": "ES256", "typ": "openid4vci-proof+jwt"]
        if let did {
            headerFields["kid"] = Did.didJwkKeyId(did)
        } else {
            headerFields["jwk"] = publicJwk
        }
        let header = JwtHelpers.jsonBase64Url(headerFields)

        let now = Int(Date().timeIntervalSince1970)
        var claimFields: [String: Any] = ["aud": audience, "iat": now, "nonce": nonce]
        if let did { claimFields["iss"] = did }
        let claims = JwtHelpers.jsonBase64Url(claimFields)

        let signingInput = "\(header).\(claims)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        return "\(signingInput).\(sigB64)"
    }

    public func generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: [String: String]
    ) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        guard let key = keys[keyId] else {
            throw KeystoreError.keyNotFound("Key not found: \(keyId)")
        }
        let pubJwk = JwtHelpers.publicKeyJwk(key)

        let header = JwtHelpers.jsonBase64Url([
            "alg": "ES256",
            "typ": typ,
            "jwk": pubJwk,
        ] as [String: Any])

        let now = Int(Date().timeIntervalSince1970)
        var claimsDict: [String: Any] = [
            "iss": issuer,
            "aud": audience,
            "iat": now,
            "exp": now + 5 * 60,
            "jti": UUID().uuidString.lowercased(),
        ]
        for (k, v) in extraClaims { claimsDict[k] = v }
        let claims = JwtHelpers.jsonBase64Url(claimsDict)

        let signingInput = "\(header).\(claims)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        return "\(signingInput).\(sigB64)"
    }

    public func generateDPoPProof(
        keyId: String,
        htm: String,
        htu: String,
        nonce: String?,
        accessTokenHash: String?
    ) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        guard let key = keys[keyId] else {
            throw KeystoreError.keyNotFound("Key not found: \(keyId)")
        }
        let header = JwtHelpers.jsonBase64Url([
            "alg": "ES256",
            "typ": "dpop+jwt",
            "jwk": JwtHelpers.publicKeyJwk(key),
        ] as [String: Any])
        let claims = JwtHelpers.jsonBase64Url(dpopClaims(htm: htm, htu: htu, nonce: nonce, accessTokenHash: accessTokenHash))

        let signingInput = "\(header).\(claims)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        return "\(signingInput).\(sigB64)"
    }

    public func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        let (keyId, key) = try selectSigningKey(kid: kid)

        let header = JwtHelpers.jsonBase64Url([
            "alg": "ES256",
            "kid": keyId,
        ])

        let now = Int(Date().timeIntervalSince1970)
        let claims = JwtHelpers.jsonBase64Url([
            "aud": audience,
            "iat": now,
            "nonce": nonce,
            "jti": UUID().uuidString.lowercased(),
        ] as [String: Any])

        let signingInput = "\(header).\(claims)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        return "\(signingInput).\(sigB64)"
    }

    public func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        kid: String?
    ) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        // The credential's own `cnf` is authoritative about which key it is
        // bound to and how that key is named. An issuer may bind by `cnf.jwk`
        // even when this wallet names its keys by did:jwk URL (and vice
        // versa), so both the lookup and the KB-JWT header follow the
        // credential rather than this wallet's configuration.
        let cnf = HolderIdentity.cnf(of: credential)
        let cnfKid = HolderIdentity.resolveCnfKid(cnf)
        // "cnf present" means the MEMBER is present, not just parsed as an
        // object (review finding): `{"cnf":"malformed"}` must not collapse
        // to the same nil an ABSENT cnf gives.
        let cnfPresent = cnf != nil || HolderIdentity.hasCnfClaim(of: credential)
        // cnf, when present, decides BOTH the key and the header below, not
        // `kid ?? cnfKid` (review finding): a disagreeing kid could sign
        // with a different key than the header announces. kid only matters
        // with no cnf at all; unresolvable-but-present must refuse.
        let effectiveKid = cnfPresent ? cnfKid : kid
        if cnfPresent, effectiveKid == nil {
            throw KeystoreError.keyNotFound("Credential's cnf does not resolve to a usable holder-key binding")
        }
        let (_, key) = try selectSigningKey(kid: effectiveKid)

        // Split SD-JWT: IssuerJWT~disclosure1~disclosure2~...~
        let parts = credential.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        let issuerJwt = parts[0]
        let disclosures = parts.dropFirst().filter { !$0.isEmpty }

        // Filter disclosures if specific claims requested
        let selectedDisclosures: [String]
        if let claims = disclosedClaims, !claims.isEmpty {
            selectedDisclosures = filterDisclosures(disclosures, claimNames: claims)
        } else {
            selectedDisclosures = Array(disclosures)
        }

        // Build SD-JWT presentation (with trailing ~)
        var sdJwtPresentation = issuerJwt
        for d in selectedDisclosures {
            sdJwtPresentation += "~\(d)"
        }
        sdJwtPresentation += "~"

        // Compute sd_hash = base64url(SHA-256(sdJwtPresentation))
        let sdHashDigest = SHA256.hash(data: Data(sdJwtPresentation.utf8))
        let sdHash = EncryptedContainer.base64UrlEncode(Data(sdHashDigest))

        // Build KB-JWT. When the credential binds the holder by name
        // (`cnf.kid`, which is what DIIP requires), the KB-JWT names the same
        // verification method rather than re-embedding the key. A `cnf.jwk`
        // binding keeps the embedded-key form it was issued under.
        //
        // Keys off an EXPLICIT cnf.kid, not cnfKid != nil - also non-nil for
        // a jwk-only credential (its thumbprint, for lookup, not a shape signal).
        var kbHeaderFields: [String: Any] = ["alg": "ES256", "typ": "kb+jwt"]
        if let explicitCnfKid = cnf?["kid"] as? String {
            kbHeaderFields["kid"] = explicitCnfKid
        } else {
            kbHeaderFields["jwk"] = JwtHelpers.publicKeyJwk(key)
        }
        let kbHeader = JwtHelpers.jsonBase64Url(kbHeaderFields)

        let now = Int(Date().timeIntervalSince1970)
        let kbClaims = JwtHelpers.jsonBase64Url([
            "aud": audience,
            "iat": now,
            "nonce": nonce,
            "sd_hash": sdHash,
        ] as [String: Any])

        let signingInput = "\(kbHeader).\(kbClaims)"
        let signature = try key.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        let kbJwt = "\(signingInput).\(sigB64)"

        return sdJwtPresentation + kbJwt
    }

    public func exportEncryptedContainer() async throws -> Data {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()

        // swiftlint:disable:next force_unwrapping
        let currentMainKey = _mainKey! // safe: requireUnlocked() above guarantees non-nil
        let walletState = buildWalletStateV3()
        let payload = try JSONSerialization.data(withJSONObject: walletState)

        let jweString = try encryptJwe(payload, mainKey: currentMainKey)
        guard var meta = containerMetadata else {
            throw KeystoreError.containerMissing("No container metadata")
        }
        meta.jwe = jweString
        containerMetadata = meta

        return try EncryptedContainer.serialize(meta)
    }

    public func listKeys() -> [KeyInfo] {
        mutex.lock()
        defer { mutex.unlock() }
        return keys.map { KeyInfo(keyId: $0.key, algorithm: "ES256") }
    }

    /// Every hardware-backed WSCD plugin's persisted key metadata, keyed by
    /// plugin ID (see `wscdCredentials`'s doc comment) - read after `unlock`
    /// to restore a previously-enrolled key (e.g. via
    /// `WscdManager.registerFido2PluginWithState`).
    public func exportWscdCredentials() async -> [String: String] {
        mutex.lock()
        defer { mutex.unlock() }
        return wscdCredentials
    }

    /// Record a WSCD plugin's freshly-exported key metadata so the next
    /// `exportEncryptedContainer` call folds it into `S.wscdCredentials` and
    /// it survives to the next `unlock` (on this device or any other sharing
    /// this account).
    public func setWscdCredentials(pluginId: String, state: String) async {
        mutex.lock()
        defer { mutex.unlock() }
        wscdCredentials[pluginId] = state
    }

    // MARK: - ExtensionStore

    /// One namespace's entries - privatedata-spec §6.1 `S.extensions`.
    ///
    /// Returns an empty dictionary for a namespace this container does not
    /// carry, which is not an error: a namespace only exists once something
    /// writes to it.
    ///
    /// Deliberately readable while locked, unlike `setExtensionEntry` and
    /// `removeExtensionEntry`. A locked keystore holds no entries, so the
    /// answer is the same empty dictionary a never-written namespace gives,
    /// and the caller's contract for that answer is already "this cannot be
    /// presented" - see `BbsHolderStateVault.get`. Throwing would turn a
    /// credential that cannot be presented right now into a crash on the
    /// presentation path.
    public func extensionEntries(namespace: String) async -> [String: String] {
        mutex.lock()
        defer { mutex.unlock() }
        return extensions[namespace] ?? [:]
    }

    /// Write one entry, so the next `exportEncryptedContainer` folds it into
    /// `S.extensions` and it survives to the next `unlock` on this device or
    /// any other sharing this account.
    ///
    /// - Parameter key: MUST name a single entity the wallet already tracks
    ///   - a kid, a credential id, a batch id - and MUST NOT name a
    ///   subsystem or plugin (§6.1.1). See the `extensions` field comment
    ///   for why that is a correctness rule.
    /// - Throws: `KeystoreError.locked` if the keystore is locked. A write to
    ///   a locked keystore has nowhere to go: `lock` has already dropped the
    ///   in-memory dictionary, and the next `unlock` loads the container it
    ///   is given rather than merging into what is there, so the entry would
    ///   be silently discarded. Failing loudly matters more here than for
    ///   most state, because for BBS the value being written cannot be
    ///   reconstructed after the fact.
    public func setExtensionEntry(namespace: String, key: String, value: String) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        extensions[namespace, default: [:]][key] = value
    }

    /// Remove one entry.
    ///
    /// §6.1.2 requires that deleting the entity an entry names deletes the
    /// entry; this is how a caller honours that. An emptied namespace is
    /// dropped rather than left as an empty object, so a container carries no
    /// trace of a namespace nothing uses.
    ///
    /// - Throws: `KeystoreError.locked` if the keystore is locked - same
    ///   reason as `setExtensionEntry`. A deletion that appears to succeed
    ///   while locked would leave the entry in the container it was meant to
    ///   be removed from.
    public func removeExtensionEntry(namespace: String, key: String) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        guard var ns = extensions[namespace] else { return }
        ns.removeValue(forKey: key)
        extensions[namespace] = ns.isEmpty ? nil : ns
    }

    /// Every credential batch's durable renewal candidate, keyed by
    /// batchId (see `CredentialRefreshTokenEntry`'s doc comment) - read
    /// after `unlock` to look up the refresh_token/DPoP key for a renewal
    /// request without depending on in-memory state surviving a restart.
    public func exportCredentialRefreshTokens() async -> [Int64: CredentialRefreshTokenEntry] {
        mutex.lock()
        defer { mutex.unlock() }
        return credentialRefreshTokens
    }

    /// Record (or overwrite) a credential batch's renewal candidate so the
    /// next `exportEncryptedContainer` call folds it into
    /// `S.credentialRefreshTokens` and it survives to the next `unlock`.
    public func setCredentialRefreshToken(batchId: Int64, entry: CredentialRefreshTokenEntry) async {
        mutex.lock()
        defer { mutex.unlock() }
        credentialRefreshTokens[batchId] = entry
    }

    /// Remove a batch's renewal candidate - MUST be called whenever that
    /// batch's credentials are deleted (e.g. superseded by a successful
    /// renewal, or the user removes the credential), per
    /// privatedata-spec §6.2's requirement that a stale entry pointing at
    /// a no-longer-existing batch never lingers.
    public func removeCredentialRefreshToken(batchId: Int64) async {
        mutex.lock()
        defer { mutex.unlock() }
        credentialRefreshTokens.removeValue(forKey: batchId)
    }

    // MARK: - Credential storage

    public func saveCredential(id: Int64, json: String) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        credentials[id] = json
    }

    public func getCredential(id: Int64) async throws -> String? {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        return credentials[id]
    }

    public func getAllCredentials() async throws -> [Int64: String] {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        return credentials
    }

    public func deleteCredential(id: Int64) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        credentials.removeValue(forKey: id)
    }

    public func clearCredentials() async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        credentials.removeAll()
    }

    // MARK: - Presentation history storage

    public func savePresentationRecord(id: Int64, json: String) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        presentationRecords[id] = json
    }

    public func getAllPresentationRecords() async throws -> [Int64: String] {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        return presentationRecords
    }

    public func clearPresentationRecords() async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        presentationRecords.removeAll()
    }

    public func generateKeypairs(count: Int) async throws -> [KeypairInfo] {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        var result: [KeypairInfo] = []
        for _ in 0..<count {
            let (keyId, privateKey) = registerNewKey()
            let jwk = JwtHelpers.publicKeyJwk(privateKey)
            // Convert [String: String] to [String: Any]
            var jwkAny: [String: Any] = [:]
            for (k, v) in jwk { jwkAny[k] = v }
            result.append(KeypairInfo(keyId: keyId, publicKeyJWK: jwkAny))
        }
        return result
    }

    /// Generate `count` fresh keypairs and self-attest them in a single OID4VCI
    /// Key Attestation JWT. This is a pure in-memory software keystore with no
    /// hardware backing or user-authentication gate, so the only truthful
    /// claim is the baseline "basic" attack-potential level.
    public func generateKeyAttestation(nonce: String, count: Int) async throws -> String {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        guard count >= 1 else {
            throw KeystoreError.invalidParameter("count must be >= 1")
        }

        // Inlined key generation (not generateKeypairs(), which also takes
        // this lock - NSLock isn't reentrant).
        var generated: [(keyId: String, privateKey: P256.Signing.PrivateKey)] = []
        for _ in 0..<count {
            let (keyId, privateKey) = registerNewKey()
            generated.append((keyId: keyId, privateKey: privateKey))
        }

        let signingKey = generated[0]
        let signingJwk = JwtHelpers.publicKeyJwk(signingKey.privateKey)

        let header = JwtHelpers.jsonBase64Url([
            "alg": "ES256",
            "typ": "key-attestation+jwt",
            "jwk": signingJwk,
        ] as [String: Any])

        let attestedKeys = generated.map { JwtHelpers.publicKeyJwk($0.privateKey) }
        let claims = JwtHelpers.jsonBase64Url([
            "iat": Int(Date().timeIntervalSince1970),
            "nonce": nonce,
            "attested_keys": attestedKeys,
            "key_storage": ["iso_18045_basic"],
        ] as [String: Any])

        let signingInput = "\(header).\(claims)"
        let signature = try signingKey.privateKey.signature(for: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature.rawRepresentation)
        return "\(signingInput).\(sigB64)"
    }

    // MARK: - Private helpers

    private func requireUnlocked() throws {
        guard _mainKey != nil else {
            throw KeystoreError.locked
        }
    }

    /// Pick the key to sign a presentation with. See
    /// `WscdKeystoreAdapter.selectSigningKey`'s doc comment for why, when
    /// `kid` is given (the credential being presented has a known bound key
    /// - see `StoredCredential.kid`), that EXACT key must be used - throwing
    /// rather than silently falling back to an arbitrary one if it's
    /// missing. `kid` is nil only for genuinely credential-less call shapes,
    /// where "first available key" (generating one if none exist yet) is
    /// the only meaningful choice.
    private func selectSigningKey(kid: String?) throws -> (keyId: String, key: P256.Signing.PrivateKey) {
        if let kid {
            guard let found = findKeypair(kid: kid) else {
                throw KeystoreError.keyNotFound("Signing key '\(kid)' not found - this credential's bound key is unavailable")
            }
            return found
        }
        if let first = keys.first {
            return (first.key, first.value)
        }
        return registerNewKey()
    }

    private func filterDisclosures(_ disclosures: [String], claimNames: [String]) -> [String] {
        let requested = Set(claimNames)
        return disclosures.filter { disclosure in
            let decoded = EncryptedContainer.base64UrlDecode(disclosure)
            guard let str = String(data: decoded, encoding: .utf8),
                  let arr = try? JSONSerialization.jsonObject(with: Data(str.utf8)) as? [Any],
                  arr.count >= 2,
                  let claimName = arr[1] as? String else {
                return true // include unparseable disclosures to be safe
            }
            return requested.contains(claimName)
        }
    }

    // MARK: - Wallet state

    private func loadWalletState(_ json: [String: Any]) {
        // V3 format: { S: { keypairs: [...], credentials: [...], ... } }
        if let state = json["S"] as? [String: Any] {
            loadFromWalletStateV3(state)
        } else if json["keys"] != nil {
            // Legacy Kotlin-only format
            loadLegacyState(json)
        }
    }

    private func loadFromWalletStateV3(_ state: [String: Any]) {
        loadKeypairs(from: state)
        loadCredentials(from: state)
        loadPresentations(from: state)
        loadWscdCredentials(from: state)
        loadExtensions(from: state)
        loadCredentialRefreshTokens(from: state)
    }

    private func loadKeypairs(from state: [String: Any]) {
        guard let keypairsArray = state["keypairs"] as? [[String: Any]] else { return }
        for entry in keypairsArray {
            guard let keypairObj = entry["keypair"] as? [String: Any],
                  let kid = keypairObj["kid"] as? String,
                  let privateKeyJwk = keypairObj["privateKey"] as? [String: Any],
                  let dStr = privateKeyJwk["d"] as? String else { continue }
            let dData = EncryptedContainer.base64UrlDecode(dStr)
            if let key = try? P256.Signing.PrivateKey(rawRepresentation: dData) {
                keys[kid] = key
                if let did = keypairObj["did"] as? String, !did.isEmpty {
                    keyDids[kid] = did
                }
            }
        }
    }

    // credentialId/batchId are privatedata-spec `number`s on the wire
    // (matching wallet-frontend's WalletStateCredential exactly) - read
    // via asInt64/asInt (which accept both NSNumber and String) rather
    // than a strict numeric cast, so a value that arrives quoted (e.g.
    // from a not-yet-migrated container) still parses instead of
    // silently dropping the entry.
    private func loadCredentials(from state: [String: Any]) {
        guard let credsArray = state["credentials"] as? [[String: Any]] else { return }
        for entry in credsArray {
            guard let credId = Self.asInt64(entry["credentialId"]),
                  let data = entry["data"] as? String else { continue }
            let credKid = entry["kid"] as? String
            let credFormat = (entry["format"] as? String) ?? ""
            let credIssuerIdent = entry["credentialIssuerIdentifier"] as? String
            let credConfigId = entry["credentialConfigurationId"] as? String
            let batchId = Self.asInt64(entry["batchId"]) ?? 0
            let instanceId = Self.asInt(entry["instanceId"]) ?? 0

            // Reconstruct a StoredCredential-shaped JSON blob (snake_case
            // matching StoredCredential's CodingKeys) to preserve kid/
            // batchId/instanceId/etc binding - credentialIssuerIdentifier/
            // credentialConfigurationId are part of privatedata-spec's
            // normative fields (already written by buildWalletStateV3()
            // below) - reconstructing them here too is what lets
            // SirosWallet re-fetch VCTM display metadata after a fresh
            // login.
            var storedDict: [String: Any] = [
                "id": credId,
                "format": credFormat,
                "raw": data,
                "batch_id": batchId,
                "instance_id": instanceId,
            ]
            if let credKid, !credKid.isEmpty { storedDict["kid"] = credKid }
            if let credIssuerIdent, !credIssuerIdent.isEmpty {
                storedDict["credential_issuer_identifier"] = credIssuerIdent
            }
            if let credConfigId, !credConfigId.isEmpty {
                storedDict["credential_configuration_id"] = credConfigId
            }

            if let storedData = try? JSONSerialization.data(withJSONObject: storedDict),
               let storedJson = String(data: storedData, encoding: .utf8) {
                credentials[credId] = storedJson
            }
        }
    }

    // Parse presentations: [{ presentationId, transactionId, data,
    // usedCredentialIds, presentationTimestampSeconds, audience }] -
    // privatedata-spec's normative shape (wallet-frontend's
    // WalletStatePresentation). transactionId/data have no
    // PresentationRecord counterpart (see its doc comment) and are
    // intentionally dropped on reload, not round-tripped.
    private func loadPresentations(from state: [String: Any]) {
        guard let presentationsArray = state["presentations"] as? [[String: Any]] else { return }
        for entry in presentationsArray {
            guard let presId = Self.asInt64(entry["presentationId"]) else { continue }
            let usedCredentialIds = (entry["usedCredentialIds"] as? [Any])?.compactMap { Self.asInt64($0) } ?? []
            let timestampSeconds = Self.asInt64(entry["presentationTimestampSeconds"]) ?? 0
            let audience = entry["audience"] as? String

            var recordDict: [String: Any] = [
                "id": presId,
                "flow_id": "",
                "credential_ids": usedCredentialIds,
                "timestamp": timestampSeconds * 1000,
            ]
            if let audience, !audience.isEmpty { recordDict["verifier_name"] = audience }

            if let recordData = try? JSONSerialization.data(withJSONObject: recordDict),
               let recordJson = String(data: recordData, encoding: .utf8) {
                presentationRecords[presId] = recordJson
            }
        }
    }

    // Parse wscdCredentials: { [pluginId]: "<opaque exported state>" } -
    // privatedata-spec §6.1, a native-SDK-only extension (see
    // wscdCredentials field's own doc comment above).
    private func loadWscdCredentials(from state: [String: Any]) {
        guard let wscdCredsObj = state["wscdCredentials"] as? [String: Any] else { return }
        for (pluginId, value) in wscdCredsObj {
            if let str = value as? String {
                wscdCredentials[pluginId] = str
            }
        }
    }

    // Parse extensions: { [namespace]: { [key]: "<opaque>" } } -
    // privatedata-spec §6.1. Anything that is not a JSON string is skipped
    // rather than rejected: a namespace this build does not implement may
    // legitimately hold a shape it has never seen, and failing to load the
    // whole container over it would be worse than carrying it.
    //
    // Skipped, specifically, rather than coerced: §6.1 makes an entry value
    // a string, and `exportEncryptedContainer` writes every entry back as
    // one. Taking a number or a boolean here would hand the peer that wrote
    // it a re-typed value on the next round trip - quietly changing another
    // client's data is worse than declining to carry a value the spec does
    // not allow in the first place, and it treats primitives the same way
    // objects and arrays are already treated. (JSONSerialization surfaces
    // numbers, booleans and null as NSNumber/NSNull, none of which bridge to
    // String, so the single `as? String` cast is the whole filter.)
    //
    // The dictionary is cleared first because this is a load, not a merge:
    // the same instance unlocked against a second container (a different
    // account, or a re-unlock after entries were dropped) must not carry the
    // first one's entries into it and write them back on export.
    private func loadExtensions(from state: [String: Any]) {
        extensions.removeAll()
        guard let extensionsObj = state["extensions"] as? [String: Any] else { return }
        for (namespace, nsValue) in extensionsObj {
            guard let entries = nsValue as? [String: Any] else { continue }
            var target: [String: String] = [:]
            for (key, value) in entries {
                guard let str = value as? String else { continue }
                target[key] = str
            }
            if !target.isEmpty {
                extensions[namespace] = target
            }
        }
    }

    // Parse credentialRefreshTokens: { [batchId]: {refreshToken, dpopJwk,
    // credentialIssuerIdentifier, credentialConfigurationId} } -
    // privatedata-spec §6.2, a native-SDK-only extension (see
    // credentialRefreshTokens field's own doc comment above).
    private func loadCredentialRefreshTokens(from state: [String: Any]) {
        guard let refreshTokensObj = state["credentialRefreshTokens"] as? [String: Any] else { return }
        for (batchIdStr, value) in refreshTokensObj {
            guard let batchId = Int64(batchIdStr),
                  let entryObj = value as? [String: Any],
                  let entry = CredentialRefreshTokenEntry.fromJsonObject(entryObj) else { continue }
            credentialRefreshTokens[batchId] = entry
        }
    }

    /// Coerce a JSON value (parsed via `JSONSerialization`, so numbers surface
    /// as `NSNumber`) or a string-encoded number into an `Int64`. Accepting
    /// both keeps parsing robust to a not-yet-migrated container where a
    /// privatedata-spec `number` field might still arrive quoted.
    private static func asInt64(_ value: Any?) -> Int64? {
        if let n = value as? NSNumber { return n.int64Value }
        if let s = value as? String { return Int64(s) }
        return nil
    }

    private static func asInt(_ value: Any?) -> Int? {
        if let n = value as? NSNumber { return n.intValue }
        if let s = value as? String { return Int(s) }
        return nil
    }

    private func parseJsonObject(_ jsonString: String) -> [String: Any]? {
        guard let data = jsonString.data(using: .utf8) else { return nil }
        return try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    }

    private func loadLegacyState(_ json: [String: Any]) {
        guard let keysArr = json["keys"] as? [[String: Any]] else { return }
        for stored in keysArr {
            guard let keyId = stored["keyId"] as? String,
                  let jwkStr = stored["jwk"] as? String,
                  let jwkData = jwkStr.data(using: .utf8),
                  let jwk = try? JSONSerialization.jsonObject(with: jwkData) as? [String: Any],
                  let dStr = jwk["d"] as? String else { continue }
            let dData = EncryptedContainer.base64UrlDecode(dStr)
            if let key = try? P256.Signing.PrivateKey(rawRepresentation: dData) {
                keys[keyId] = key
            }
        }
        // Legacy Kotlin-only container predates numeric credential ids
        // entirely - defaults any unparseable (pre-migration UUID-string)
        // key to 0, since this path is only reachable from a container
        // exported before the privatedata-spec numeric-id alignment.
        if let creds = json["credentials"] as? [String: String] {
            credentials = creds.reduce(into: [Int64: String]()) { result, entry in
                result[Int64(entry.key) ?? 0] = entry.value
            }
        }
    }

    /// The top-level `S` members `buildWalletStateV3()` produces from its own
    /// in-memory state. Every OTHER member of the loaded `S` is passed through
    /// untouched - see the pass-through loop at the end of that function.
    /// Adding a new field this class owns means adding it here too, or the
    /// stale loaded copy would overwrite the freshly built one on export.
    private static let ownedWalletStateMembers: Set<String> = [
        "schemaVersion",
        "keypairs",
        "credentials",
        "presentations",
        "settings",
        "credentialIssuanceSessions",
        "wscdCredentials",
        "extensions",
        "credentialRefreshTokens",
    ]

    private func buildWalletStateV3() -> [String: Any] {
        // Preserve existing state if available, otherwise initialize fresh.
        // NOTE: this must NOT short-circuit and return existingState verbatim -
        // credentials/keys added via saveCredential()/generateKey() since unlock()
        // only live in the `keys`/`credentials` dictionaries below, not in
        // preservedWalletState, so an early return here would silently drop any
        // credential added by a returning user (preservedWalletState is only
        // ever non-nil when unlock() loaded an existing container).
        let existingState = preservedWalletState
        let existingS = existingState?["S"] as? [String: Any]

        let originalKeypairsByKid: [String: [String: Any]] = {
            guard let arr = existingS?["keypairs"] as? [[String: Any]] else { return [:] }
            var result: [String: [String: Any]] = [:]
            for entry in arr {
                if let kid = (entry["keypair"] as? [String: Any])?["kid"] as? String {
                    result[kid] = entry
                }
            }
            return result
        }()

        // credentialId is a privatedata-spec number on the wire (matching
        // wallet-frontend), so compare it numerically rather than as a string.
        let originalCredsById: [Int64: [String: Any]] = {
            guard let arr = existingS?["credentials"] as? [[String: Any]] else { return [:] }
            var result: [Int64: [String: Any]] = [:]
            for entry in arr {
                if let credId = Self.asInt64(entry["credentialId"]) {
                    result[credId] = entry
                }
            }
            return result
        }()

        let keypairs: [[String: Any]] = keys.map { (kid, ecKey) in
            let publicKey = ecKey.publicKey
            let x963 = publicKey.x963Representation
            let x = Data(x963[1..<33])
            let y = Data(x963[33..<65])
            let d = ecKey.rawRepresentation

            let pubJwk: [String: Any] = [
                "kty": "EC",
                "crv": "P-256",
                "x": EncryptedContainer.base64UrlEncode(x),
                "y": EncryptedContainer.base64UrlEncode(y),
            ]
            let privJwk: [String: Any] = [
                "kty": "EC",
                "crv": "P-256",
                "x": EncryptedContainer.base64UrlEncode(x),
                "y": EncryptedContainer.base64UrlEncode(y),
                "d": EncryptedContainer.base64UrlEncode(d),
            ]
            // A key generated this session knows its own DID; otherwise
            // preserve whatever the loaded container recorded. Never
            // recomputed, so a wallet reconfigured to a different
            // `didKeyVersion` cannot re-identify an existing key.
            let originalKeypair = originalKeypairsByKid[kid]?["keypair"] as? [String: Any]
            let did = keyDids[kid] ?? originalKeypair?["did"] as? String ?? ""
            return [
                "kid": kid,
                "keypair": [
                    "kid": kid,
                    "did": did,
                    "alg": "ES256",
                    "publicKey": pubJwk,
                    "privateKey": privJwk,
                ] as [String: Any],
            ]
        }

        // Preserve all metadata fields from the original entry (if this
        // credential already existed in the loaded container); fall back to
        // the credential's own saved JSON (parsed) for a credential added
        // THIS session (saveCredential() then export, with no matching entry
        // in the previously-imported container yet) - without this fallback,
        // a freshly-saved batch credential's batchId/instanceId would
        // silently reset to 0 on every export until the container is
        // reloaded once.
        let creds: [[String: Any]] = credentials.map { (id, data) in
            let original = originalCredsById[id]
            let parsed = parseJsonObject(data)
            let format = (original?["format"] as? String) ?? (parsed?["format"] as? String) ?? ""
            let kid = (original?["kid"] as? String) ?? (parsed?["kid"] as? String) ?? ""
            let instanceId = Self.asInt(original?["instanceId"]) ?? Self.asInt(parsed?["instance_id"]) ?? 0
            let batchId = Self.asInt64(original?["batchId"]) ?? Self.asInt64(parsed?["batch_id"]) ?? 0
            let issuerIdent = (original?["credentialIssuerIdentifier"] as? String)
                ?? (parsed?["credential_issuer_identifier"] as? String) ?? ""
            let configId = (original?["credentialConfigurationId"] as? String)
                ?? (parsed?["credential_configuration_id"] as? String) ?? ""
            let credData = (original?["data"] as? String) ?? (parsed?["raw"] as? String) ?? data
            let entry: [String: Any] = [
                "credentialId": id,
                "format": format,
                "data": credData,
                "kid": kid,
                "instanceId": instanceId,
                "batchId": batchId,
                "credentialIssuerIdentifier": issuerIdent,
                "credentialConfigurationId": configId,
            ]
            return entry
        }

        // presentations is privatedata-spec's normative S.presentations[]
        // (wallet-frontend's WalletStatePresentation) - genuinely built from
        // the in-memory presentationRecords map, not passed through verbatim,
        // so a presentation recorded THIS session actually survives
        // export/reload (see savePresentationRecord). transactionId has no
        // PresentationRecord counterpart (see its doc comment) - each
        // Swift-recorded presentation is treated as its own single-VP
        // transaction, reusing the same id for both fields. `data` (the raw
        // VP) isn't captured at PresentationRecord construction time
        // (recorded at credential-selection time, before the VP is actually
        // signed) - written as "" rather than restructuring that flow, a
        // known, deliberate gap.
        let presentations: [[String: Any]] = presentationRecords.map { (id, data) in
            let parsed = parseJsonObject(data)
            let usedCredentialIds = (parsed?["credential_ids"] as? [Any])?.compactMap { Self.asInt64($0) } ?? []
            let timestampMillis = Self.asInt64(parsed?["timestamp"]) ?? 0
            let audience = (parsed?["verifier_name"] as? String) ?? ""

            return [
                "presentationId": id,
                "transactionId": id,
                "data": "",
                "usedCredentialIds": usedCredentialIds,
                "presentationTimestampSeconds": timestampMillis / 1000,
                "audience": audience,
            ] as [String: Any]
        }

        let lastEventHash = existingState?["lastEventHash"] as? String ?? ""
        let events = existingState?["events"] as? [Any] ?? []
        let settings = existingS?["settings"] as? [String: Any] ?? [
            "openidRefreshTokenMaxAgeInSeconds": "0",
        ]
        let credentialIssuanceSessions = existingS?["credentialIssuanceSessions"] as? [Any] ?? []

        var sDict: [String: Any] = [
            "schemaVersion": 3,
            "keypairs": keypairs,
            "credentials": creds,
            "presentations": presentations,
            "settings": settings,
            "credentialIssuanceSessions": credentialIssuanceSessions,
        ]
        appendExtensionMembers(to: &sDict, existingS: existingS)

        return [
            "lastEventHash": lastEventHash,
            "events": events,
            "S": sDict,
        ]
    }

    /// The `S` members beyond privatedata-spec's normative core: the
    /// native-SDK extension fields this class owns, then everything else the
    /// loaded container carried. Split out of `buildWalletStateV3()` only to
    /// keep that function's body within the lint limit; the two are one
    /// export step.
    private func appendExtensionMembers(to sDict: inout [String: Any], existingS: [String: Any]?) {
        // wscdCredentials (privatedata-spec §6.1, native-SDK-only extension)
        // - wscdCredentials the in-memory dictionary IS the source of truth
        // once loaded (see loadFromWalletStateV3), no need to merge against
        // existingState separately. Omitted entirely (not emitted as `{}`)
        // when empty.
        if !wscdCredentials.isEmpty {
            sDict["wscdCredentials"] = wscdCredentials
        }

        // extensions (privatedata-spec §6.1) - written before the legacy
        // fields below so a reader sees the normative shape first.
        // Namespaces this build does not implement are written back exactly
        // as they were read; an emptied namespace is omitted rather than
        // emitted as `{}`. Same "in-memory dictionary IS the source of truth
        // once loaded" rationale as wscdCredentials above.
        let nonEmptyNamespaces = extensions.filter { !$0.value.isEmpty }
        if !nonEmptyNamespaces.isEmpty {
            sDict["extensions"] = nonEmptyNamespaces
        }

        // credentialRefreshTokens (privatedata-spec §6.2, native-SDK-only
        // extension) - same "in-memory dictionary IS the source of truth
        // once loaded" rationale as wscdCredentials above.
        if !credentialRefreshTokens.isEmpty {
            sDict["credentialRefreshTokens"] = credentialRefreshTokens.reduce(into: [String: Any]()) { result, entry in
                result[String(entry.key)] = entry.value.toJsonObject()
            }
        }

        // Every other top-level `S` member is carried verbatim from the
        // container this session was unlocked against. `S` is shared with
        // wallet-frontend and siros-sdk-kotlin, and either may write members
        // this build has never heard of (privatedata-spec §6.1 `S.extensions`
        // is the normative example); rebuilding `S` from the closed key list
        // above used to drop all of them on export - and a member such as
        // `extensions["org.siros.bbs"]`, another client's blind-BBS holder
        // state, cannot be recomputed once it is gone. Only members this
        // class itself produces are excluded: for those the in-memory state
        // IS the source of truth, and carrying the loaded copy would
        // resurrect entries the session deliberately removed (see
        // `wscdCredentials`/`credentialRefreshTokens` above).
        if let existingS {
            for (member, value) in existingS where !Self.ownedWalletStateMembers.contains(member) {
                sDict[member] = value
            }
        }
    }

    // MARK: - JWE encrypt/decrypt (A256GCMKW / A256GCM)

    /// Decrypt a JWE compact serialization using A256GCMKW / A256GCM.
    private func decryptJwe(_ jweString: String, mainKey: SymmetricKey) throws -> [String: Any] {
        let parts = jweString.split(separator: ".").map(String.init)
        guard parts.count == 5 else {
            throw KeystoreError.invalidContainer("JWE must have 5 parts")
        }

        let headerData = EncryptedContainer.base64UrlDecode(parts[0])
        let encryptedKeyData = EncryptedContainer.base64UrlDecode(parts[1])
        let ivData = EncryptedContainer.base64UrlDecode(parts[2])
        let ciphertextData = EncryptedContainer.base64UrlDecode(parts[3])
        let tagData = EncryptedContainer.base64UrlDecode(parts[4])

        guard let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any] else {
            throw KeystoreError.invalidContainer("Invalid JWE header")
        }

        // Extract the IV from the header for key unwrapping (A256GCMKW)
        guard let headerIv = header["iv"] as? String,
              let headerTag = header["tag"] as? String else {
            throw KeystoreError.invalidContainer("Missing iv/tag in JWE header for A256GCMKW")
        }

        let kwIv = EncryptedContainer.base64UrlDecode(headerIv)
        let kwTag = EncryptedContainer.base64UrlDecode(headerTag)

        // Unwrap the Content Encryption Key (CEK) using A256GCMKW
        let kwNonce = try AES.GCM.Nonce(data: kwIv)
        let kwSealedBox = try AES.GCM.SealedBox(nonce: kwNonce, ciphertext: encryptedKeyData, tag: kwTag)
        let cekData = try AES.GCM.open(kwSealedBox, using: mainKey)
        let cek = SymmetricKey(data: cekData)

        // Decrypt content with A256GCM using the CEK
        let contentNonce = try AES.GCM.Nonce(data: ivData)
        // AAD = base64url-encoded protected header
        let aadData = Data(parts[0].utf8)
        let contentSealedBox = try AES.GCM.SealedBox(
            nonce: contentNonce,
            ciphertext: ciphertextData,
            tag: tagData
        )
        let plaintext = try AES.GCM.open(contentSealedBox, using: cek, authenticating: aadData)

        guard let json = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else {
            throw KeystoreError.invalidContainer("JWE payload is not valid JSON object")
        }
        return json
    }

    /// Encrypt a payload as JWE compact serialization using A256GCMKW / A256GCM.
    private func encryptJwe(_ plaintext: Data, mainKey: SymmetricKey) throws -> String {
        // Generate a random CEK (256-bit)
        var cekBytes = Data(count: 32)
        // swiftlint:disable:next force_unwrapping
        cekBytes.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        let cek = SymmetricKey(data: cekBytes)

        // Wrap CEK with A256GCMKW
        let kwNonce = AES.GCM.Nonce()
        let kwSealed = try AES.GCM.seal(cekBytes, using: mainKey, nonce: kwNonce)
        let encryptedKey = kwSealed.ciphertext
        let kwIv = Data(kwNonce)
        let kwTag = kwSealed.tag

        // Build JWE header
        let headerObj: [String: Any] = [
            "alg": "A256GCMKW",
            "enc": "A256GCM",
            "iv": EncryptedContainer.base64UrlEncode(kwIv),
            "tag": EncryptedContainer.base64UrlEncode(kwTag),
        ]
        let headerData = try JSONSerialization.data(withJSONObject: headerObj)
        let headerB64 = EncryptedContainer.base64UrlEncode(headerData)

        // Encrypt content with A256GCM
        let contentNonce = AES.GCM.Nonce()
        let aad = Data(headerB64.utf8)
        let sealed = try AES.GCM.seal(plaintext, using: cek, nonce: contentNonce, authenticating: aad)

        let parts = [
            headerB64,
            EncryptedContainer.base64UrlEncode(encryptedKey),
            EncryptedContainer.base64UrlEncode(Data(contentNonce)),
            EncryptedContainer.base64UrlEncode(sealed.ciphertext),
            EncryptedContainer.base64UrlEncode(sealed.tag),
        ]
        return parts.joined(separator: ".")
    }

    #else
    // Stub for non-Apple platforms where CryptoKit is unavailable
    public init() {}
    public var isUnlocked: Bool { false }
    public func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func lock() {}
    public func generateKey(algorithm: String = "ES256") async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func sign(keyId: String, payload: Data, algorithm: String = "ES256") async throws -> Data {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func generateProof(
        audience: String,
        nonce: String,
        freshKey: Bool,
        holderBinding: HolderBinding?
    ) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func exportEncryptedContainer() async throws -> Data {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func listKeys() -> [KeyInfo] { [] }
    public func exportWscdCredentials() async -> [String: String] { [:] }
    public func setWscdCredentials(pluginId: String, state: String) async {}
    public func extensionEntries(namespace: String) async -> [String: String] { [:] }
    public func setExtensionEntry(namespace: String, key: String, value: String) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func removeExtensionEntry(namespace: String, key: String) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func saveCredential(id: Int64, json: String) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func getCredential(id: Int64) async throws -> String? {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func getAllCredentials() async throws -> [Int64: String] {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func deleteCredential(id: Int64) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func clearCredentials() async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func savePresentationRecord(id: Int64, json: String) async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func getAllPresentationRecords() async throws -> [Int64: String] {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func clearPresentationRecords() async throws {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    public func generateKeypairs(count: Int) async throws -> [KeypairInfo] {
        throw KeystoreError.cryptoError("CryptoKit not available on this platform")
    }
    #endif
}
