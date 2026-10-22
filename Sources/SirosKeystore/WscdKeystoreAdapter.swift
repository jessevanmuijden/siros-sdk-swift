// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit

/// Transaction data item of the pre-TS12 API.
///
/// Kept only so existing callers still compile. The signing overload that took
/// it did not implement EC TS12 (it hashed a re-serialised form), so it now
/// refuses a non-empty list; the wallet presents transactions through
/// ``SirosWallet`` once ``SirosWallet/transactionDataEnabled`` is on.
@available(*, deprecated, message: "Use SirosWallet's transaction_data handling (SirosWallet.transactionDataEnabled and transactionConsentHandler).")
public struct TransactionDataItem: Sendable {
    /// Transaction type.
    public let type: String
    /// Serialization of this transaction data item.
    public let rawJson: String

    public init(type: String, rawJson: String) {
        self.type = type
        self.rawJson = rawJson
    }
}

/// Adapts a `Signer` (e.g. backed by WSCD/UniFFI bindings) into the
/// full `KeystoreManager` protocol expected by `SirosWallet`.
///
/// This adapter delegates raw key operations (generate, sign, list)
/// to the underlying `Signer` implementation while handling
/// higher-level operations (JWT construction, SD-JWT VP tokens,
/// credential storage) locally.
///
/// Usage:
/// ```swift
/// let wscdSigner: Signer = ... // UniFFI-generated WSCD binding
/// let keystore = WscdKeystoreAdapter(signer: wscdSigner)
/// let wallet = SirosWallet(keystore: keystore)
/// ```
public final class WscdKeystoreAdapter: @unchecked Sendable, KeystoreManager, WscdManager, ExtensionStore {

    private let signer: Signer

    /// Owns the PRF-protected container (mainKey/prfKeys/jwe -> V3
    /// WalletStateContainer) for this adapter's *credentials* - the WSCD
    /// manages its own signing-key protection, but SIROS ID's core tenet is
    /// that private data, including issued credentials, is always protected
    /// by the passkey's PRF-derived secret independent of whichever WSCD
    /// backs key signing. Reusing `JweKeystore` here (rather than an
    /// adapter-local format) guarantees byte-for-byte compatibility with
    /// wallet-frontend and JweKeystore-backed native clients per
    /// privatedata-spec - the SAME passkey must unlock the SAME credentials
    /// on any client. It's also what lets `S.wscdCredentials` (see
    /// `exportWscdCredentialsState`/`setWscdCredentialsState`) actually
    /// round-trip through backend sync for a WSCD-backed wallet, rather than
    /// only existing in this process's memory.
    ///
    /// Unlike Kotlin's `WscdKeystoreAdapter`, this adapter's `Signer`
    /// protocol has no `exportPrivateKeypairs`/`importPrivateKeypairs`
    /// precedent yet, so a "softkey" plugin's own private key material isn't
    /// folded into `credentialsKeystore.keys` here - a known gap, not
    /// introduced by this change.
    private let credentialsKeystore = JweKeystore()

    /// Non-nil only when `signer` is itself WSCD-backed (i.e. a
    /// `UniFFISigner`) - a plain software `Signer` has no lifecycle or
    /// plugin-registration concept.
    private var wscdManager: WscdManager? { signer as? WscdManager }

    private func requireWscdManager() throws -> WscdManager {
        guard let manager = wscdManager else {
            throw KeystoreError.invalidParameter(
                "WSCD lifecycle/plugin registration not supported by this keystore"
            )
        }
        return manager
    }

    /// The interoperability profile this keystore signs for - see
    /// ``InteropProfile``. Unlike ``JweKeystore``, the key ids themselves come
    /// from the WSCD (which assigns RFC 7638 thumbprints) and are not changed
    /// by this setting; what it controls is the identifier presented to
    /// Issuers. A `did:jwk` carries the public key inside the identifier, so a
    /// `cnf.kid` naming one can always be mapped back to the WSCD key that
    /// signs for it - see `resolveSigningKey`.
    private let profile: InteropProfile

    public init(signer: Signer, profile: InteropProfile = .default) {
        self.signer = signer
        self.profile = profile
    }

    // MARK: - WscdManager conformance

    public func lifecycleStatus(pluginId: String, contextId: String) async throws -> LifecycleStatus {
        try await requireWscdManager().lifecycleStatus(pluginId: pluginId, contextId: contextId)
    }

    public func registerLifecycle(request: RegisterLifecycleRequest) async throws -> RegistrationOutcome {
        try await requireWscdManager().registerLifecycle(request: request)
    }

    public func activateLifecycle(request: ActivateLifecycleRequest) async throws -> ActivationOutcome {
        try await requireWscdManager().activateLifecycle(request: request)
    }

    public func rotateLifecycle(request: RotateLifecycleRequest) async throws -> RotationOutcome {
        try await requireWscdManager().rotateLifecycle(request: request)
    }

    public func destroyLifecycle(request: DestroyLifecycleRequest) async throws -> DestructionOutcome {
        try await requireWscdManager().destroyLifecycle(request: request)
    }

    public func registerFido2Plugin(transport: Ctap2TransportProvider) throws {
        try requireWscdManager().registerFido2Plugin(transport: transport)
    }

    public func registerFido2PluginWithState(transport: Ctap2TransportProvider, state: Data) throws {
        try requireWscdManager().registerFido2PluginWithState(transport: transport, state: state)
    }

    public func exportFido2State() throws -> Data {
        try requireWscdManager().exportFido2State()
    }

    public func registerR2psPlugin(config: R2psConfig, transport: R2psTransportProvider) throws {
        try requireWscdManager().registerR2psPlugin(config: config, transport: transport)
    }

    // MARK: - KeystoreManager conformance

    public var isUnlocked: Bool {
        credentialsKeystore.isUnlocked
    }

    public func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data
    ) async throws {
        // The WSCD manages its own signing-key protection (no PRF unlock for
        // key material itself), but this adapter's *credentials* (and now
        // `S.wscdCredentials`) are still PRF-protected via
        // `credentialsKeystore` - see its doc comment.
        try await credentialsKeystore.unlock(
            prfOutput: prfOutput,
            encryptedContainer: encryptedContainer,
            hkdfSalt: hkdfSalt,
            hkdfInfo: hkdfInfo
        )
    }

    /// See `KeystoreManager.unlock(prfOutput:encryptedContainer:hkdfSalt:hkdfInfo:prfSalt:)`.
    /// Forwarded straight to `credentialsKeystore`, same as the four-parameter
    /// overload above - `prfSalt` only matters to the `JweKeystore` that
    /// actually owns the PRF-protected container.
    public func unlock(
        prfOutput: Data,
        encryptedContainer: Data,
        hkdfSalt: Data,
        hkdfInfo: Data,
        prfSalt: Data
    ) async throws {
        try await credentialsKeystore.unlock(
            prfOutput: prfOutput,
            encryptedContainer: encryptedContainer,
            hkdfSalt: hkdfSalt,
            hkdfInfo: hkdfInfo,
            prfSalt: prfSalt
        )
    }

    public func lock() {
        credentialsKeystore.lock()
    }

    /// The persisted (privatedata-synced) copy of every hardware-backed WSCD
    /// plugin's key metadata - see `JweKeystore.exportWscdCredentials`'s doc
    /// comment. Read this after `unlock` to restore a previously-enrolled
    /// key via e.g. `registerFido2PluginWithState`, rather than
    /// `exportFido2State` which only reflects the CURRENT process's live
    /// plugin state.
    public func exportWscdCredentialsState() async -> [String: String] {
        await credentialsKeystore.exportWscdCredentials()
    }

    /// Record a WSCD plugin's freshly-exported key metadata so it round-trips
    /// through privatedata on the next `exportEncryptedContainer` - see
    /// `JweKeystore.setWscdCredentials`.
    public func setWscdCredentialsState(pluginId: String, state: String) async {
        await credentialsKeystore.setWscdCredentials(pluginId: pluginId, state: state)
    }

    /// The persisted (privatedata-synced) renewal candidates for every
    /// credential batch - see `JweKeystore.exportCredentialRefreshTokens`'s
    /// doc comment.
    public func exportCredentialRefreshTokens() async -> [Int64: CredentialRefreshTokenEntry] {
        await credentialsKeystore.exportCredentialRefreshTokens()
    }

    /// See `JweKeystore.setCredentialRefreshToken`.
    public func setCredentialRefreshToken(batchId: Int64, entry: CredentialRefreshTokenEntry) async {
        await credentialsKeystore.setCredentialRefreshToken(batchId: batchId, entry: entry)
    }

    /// See `JweKeystore.removeCredentialRefreshToken`.
    public func removeCredentialRefreshToken(batchId: Int64) async {
        await credentialsKeystore.removeCredentialRefreshToken(batchId: batchId)
    }

    // MARK: - ExtensionStore conformance

    // Extension state has to land in the same blob the credentials do, or
    // it does not reach the account's other devices - and
    // `credentialsKeystore` is the JweKeystore that owns this adapter's
    // container. Swift has no `by`-delegation, so each method forwards
    // explicitly; the semantics (including throwing while locked) are
    // `JweKeystore`'s.

    /// See `JweKeystore.extensionEntries`.
    public func extensionEntries(namespace: String) async -> [String: String] {
        await credentialsKeystore.extensionEntries(namespace: namespace)
    }

    /// See `JweKeystore.setExtensionEntry`.
    public func setExtensionEntry(namespace: String, key: String, value: String) async throws {
        try await credentialsKeystore.setExtensionEntry(namespace: namespace, key: key, value: value)
    }

    /// See `JweKeystore.removeExtensionEntry`.
    public func removeExtensionEntry(namespace: String, key: String) async throws {
        try await credentialsKeystore.removeExtensionEntry(namespace: namespace, key: key)
    }

    public func generateKey(algorithm: String) async throws -> String {
        try checkUnlocked()
        return try await signer.generateKey(algorithm: algorithm)
    }

    public func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data {
        try checkUnlocked()
        return try await signer.sign(keyId: keyId, data: payload)
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
        try checkUnlocked()
        var keys = try await signer.listKeys()
        if keys.isEmpty || freshKey {
            // Auto-generate a key for VCI proof-of-possession
            let newKeyId = try await signer.generateKey(algorithm: "ES256")
            keys = try await signer.listKeys()
            if freshKey {
                keys = keys.filter { $0.keyId == newKeyId }
            }
        }
        guard let key = keys.first else {
            throw KeystoreError.keyNotFound("no keys available")
        }
        let pubKeyData = try await signer.exportPublicKey(keyId: key.keyId)
        let pubKeyJwk = try jsonDict(from: pubKeyData)

        // DIIP requires the `jwt` proof type to carry the Holder's did:jwk as
        // `iss` and to name the key with a `kid` from that DID document; HAIP
        // carries the key in the header instead. The caller may know which
        // this issuer speaks; when it does not, this keystore's own profile
        // decides. The DID is derived from the public key rather than stored:
        // a did:jwk *is* its key, so it needs no bookkeeping and cannot drift
        // out of sync with the WSCD.
        let did = try holderDid(forPublicKey: pubKeyJwk, binding: holderBinding ?? profile.holderBinding)

        var headerFields: [String: Any] = [
            "alg": algorithmJoseId(key.algorithm),
            "typ": "openid4vci-proof+jwt",
        ]
        if let did {
            headerFields["kid"] = Did.didJwkKeyId(did)
        } else {
            // `exportPublicKey` only promises a public JWK, not a `kid` of
            // its own - a third-party WSCD plugin's native key id (unlike
            // the thumbprint-style ids the default/softkey WSCD assigns) is
            // otherwise nowhere in this proof at all. Without it, the
            // wallet's proof bookkeeping (`SirosWallet.generateProofs`'s
            // `extractProofKeyId`) still recovers a usable id - it falls
            // back to the RFC 7638 thumbprint of the embedded key - but
            // `resolveSigningKey` then has to find this exact key by
            // exporting and thumbprinting every key the WSCD holds, one at a
            // time, instead of matching `key.keyId` directly on the first,
            // cheap attempt (review finding).
            var jwkWithKid = pubKeyJwk
            jwkWithKid["kid"] = key.keyId
            headerFields["jwk"] = jwkWithKid
        }
        let header = JwtHelpers.jsonBase64Url(headerFields)

        let now = Int(Date().timeIntervalSince1970)
        var claimFields: [String: Any] = ["aud": audience, "iat": now, "nonce": nonce]
        if let did { claimFields["iss"] = did }
        let claims = JwtHelpers.jsonBase64Url(claimFields)

        let signingInput = "\(header).\(claims)"
        let signature = try await signer.sign(keyId: key.keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        return "\(signingInput).\(sigB64)"
    }

    public func generateKeyProof(
        keyId: String,
        typ: String,
        issuer: String,
        audience: String,
        extraClaims: [String: String]
    ) async throws -> String {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        guard let key = keys.first(where: { $0.keyId == keyId }) else {
            throw KeystoreError.keyNotFound("Key not found: \(keyId)")
        }
        let pubKeyData = try await signer.exportPublicKey(keyId: keyId)
        let pubKeyJwk = try jsonDict(from: pubKeyData)

        let header = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId(key.algorithm),
            "typ": typ,
            "jwk": pubKeyJwk,
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
        let signature = try await signer.sign(keyId: keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        return "\(signingInput).\(sigB64)"
    }

    public func generateDPoPProof(
        keyId: String,
        htm: String,
        htu: String,
        nonce: String?,
        accessTokenHash: String?
    ) async throws -> String {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        guard let key = keys.first(where: { $0.keyId == keyId }) else {
            throw KeystoreError.keyNotFound("Key not found: \(keyId)")
        }
        let pubKeyJwk = try jsonDict(from: try await signer.exportPublicKey(keyId: keyId))

        let header = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId(key.algorithm),
            "typ": "dpop+jwt",
            "jwk": pubKeyJwk,
        ] as [String: Any])
        let claims = JwtHelpers.jsonBase64Url(dpopClaims(htm: htm, htu: htu, nonce: nonce, accessTokenHash: accessTokenHash))

        let signingInput = "\(header).\(claims)"
        let signature = try await signer.sign(keyId: keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        return "\(signingInput).\(sigB64)"
    }

    public func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        let key = try selectSigningKey(keys, kid: kid)

        let header = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId(key.algorithm),
            "kid": key.keyId,
        ])

        let now = Int(Date().timeIntervalSince1970)
        let claims = JwtHelpers.jsonBase64Url([
            "aud": audience,
            "iat": now,
            "nonce": nonce,
            "jti": UUID().uuidString.lowercased(),
        ] as [String: Any])

        let signingInput = "\(header).\(claims)"
        let signature = try await signer.sign(keyId: key.keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        return "\(signingInput).\(sigB64)"
    }

    public func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        kid: String?
    ) async throws -> String {
        try await signVpToken(
            credential: credential,
            disclosedClaims: disclosedClaims,
            nonce: nonce,
            audience: audience,
            transactionData: nil,
            kid: kid
        )
    }

    /// The pre-TS12 overload. A list of items is refused (it never produced
    /// TS12-conformant claims); `nil` or an empty list signs as a plain presentation.
    @available(*, deprecated, message: "Use the overload taking a TransactionDataBinding, built by the SDK.")
    @_disfavoredOverload
    public func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        transactionData: [TransactionDataItem]?,
        kid: String? = nil
    ) async throws -> String {
        guard transactionData?.isEmpty ?? true else {
            throw KeystoreError.invalidParameter("transaction data items are no longer supported by this API; the wallet handles transaction_data itself")
        }
        return try await signVpToken(
            credential: credential, disclosedClaims: disclosedClaims, nonce: nonce, audience: audience,
            transactionData: nil as TransactionDataBinding?, kid: kid
        )
    }

    /// VP token signing with EC TS12 payment-SCA claims (see
    /// ``KeystoreManager/signVpToken(credential:disclosedClaims:nonce:audience:transactionData:kid:)``).
    public func signVpToken(
        credential: String,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        transactionData: TransactionDataBinding?,
        kid: String?
    ) async throws -> String {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        // The credential's own `cnf` is authoritative about which key it is
        // bound to and how that key is named - an issuer may bind by `cnf.jwk`
        // even when this wallet presents did:jwk identifiers, and vice versa.
        let cnf = HolderIdentity.cnf(of: credential)
        let cnfKid = HolderIdentity.resolveCnfKid(cnf)
        // "cnf present" means the MEMBER is present, not just that it parsed
        // as an object (review finding): `{"cnf":"malformed"}` must not
        // collapse to the same nil `cnf(of:)` gives an ABSENT cnf.
        let cnfPresent = cnf != nil || HolderIdentity.hasCnfClaim(of: credential)
        // cnf, when present, decides BOTH the signing key and the header
        // below - the caller's `kid` is ignored rather than merely
        // preferred (review finding): a caller-supplied id that disagreed
        // with cnf could otherwise select a DIFFERENT key than the header
        // (always built from cnf) then announced, producing a presentation
        // no verifier accepts either way. `kid` only still matters for a
        // credential with NO cnf at all. Unresolvable-but-present cnf must
        // refuse, not reach resolveSigningKey(kid: nil)'s
        // first-available-key fallback - that's for a credential with no
        // binding, not an unparsed one.
        let effectiveKid = cnfPresent ? cnfKid : kid
        if cnfPresent, effectiveKid == nil {
            throw KeystoreError.keyNotFound("Credential's cnf does not resolve to a usable holder-key binding")
        }
        let key = try await resolveSigningKey(keys, kid: effectiveKid)
        // The factors in the binding were established for the key the CALLER named. The credential's
        // `cnf` decides which key signs, so if they differ the claim would describe a different key
        // than the one that signs: refuse rather than assert possession of the wrong one.
        if transactionData != nil, key.keyId != kid {
            throw KeystoreError.invalidParameter("the key the credential is bound to is not the key the authentication factors were established for")
        }

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

        // Build KB-JWT
        let pubKeyData = try await signer.exportPublicKey(keyId: key.keyId)
        let pubKeyJwk = try jsonDict(from: pubKeyData)

        // When the credential binds the holder by name (`cnf.kid`, which is
        // what DIIP requires), the KB-JWT names the same verification method
        // rather than re-embedding the key. A `cnf.jwk` binding keeps the
        // embedded-key form it was issued under.
        // Follows whether `cnf` carries an EXPLICIT `kid` member, not whether
        // `cnfKid` (resolveCnfKid's result) is non-nil (review finding, with
        // a correction - cnfKid is also non-nil for a `cnf.jwk`-only
        // credential, where it holds that jwk's THUMBPRINT for key lookup,
        // not a wire-shape decision): resolveCnfKid gives `cnf.kid`
        // precedence over `cnf.jwk` for SELECTING the key, and the header
        // must follow that same precedence - a credential carrying BOTH
        // must announce `kid`, matching the key that precedence actually
        // selected, never the unrelated embedded jwk instead.
        var kbHeaderFields: [String: Any] = [
            "alg": algorithmJoseId(key.algorithm),
            "typ": "kb+jwt",
        ]
        if let explicitCnfKid = cnf?["kid"] as? String {
            kbHeaderFields["kid"] = explicitCnfKid
        } else {
            kbHeaderFields["jwk"] = pubKeyJwk
        }
        let kbHeader = JwtHelpers.jsonBase64Url(kbHeaderFields)

        let now = Int(Date().timeIntervalSince1970)
        var kbClaimsDict: [String: Any] = [
            "aud": audience,
            "iat": now,
            "nonce": nonce,
            "sd_hash": sdHash,
        ]

        let baseClaims = kbClaimsDict
        if let binding = transactionData {
            // EC TS12 (section 3.6): hashes over the verifier's raw strings, a string algorithm,
            // a fresh jti, the request's response_mode and the two-category amr. The factors are
            // those the signing operation itself reports (see `Signer.signForSca`): the claim
            // set is built from them inside the sign and the token is refused unless the sign
            // applied exactly what it claims. This replaces the RFC 8176 `amr` of a plain
            // presentation: TS12 requires the object form.
            let header = kbHeader
            let outcome = try await signer.signForSca(keyId: key.keyId) { factors in
                var claims = baseClaims
                for (name, value) in try binding.kbJwtClaims(factors: factors) { claims[name] = value }
                return Data("\(header).\(JwtHelpers.jsonBase64Url(claims))".utf8)
            }
            guard let signingInput = String(data: outcome.signedData, encoding: .utf8) else {
                throw KeystoreError.cryptoError("the signed KB-JWT input is not text")
            }
            return sdJwtPresentation + "\(signingInput).\(EncryptedContainer.base64UrlEncode(outcome.signature))"
        }
        if let props = try? await signer.securityProperties(keyId: key.keyId),
           !props.amr.isEmpty {
            // Include amr from WSCD security properties (E7)
            kbClaimsDict["amr"] = props.amr
        }

        let kbClaims = JwtHelpers.jsonBase64Url(kbClaimsDict)

        let signingInput = "\(kbHeader).\(kbClaims)"
        let signature = try await signer.sign(keyId: key.keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        let kbJwt = "\(signingInput).\(sigB64)"

        return sdJwtPresentation + kbJwt
    }

    public func signMdocPresentation(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        audience: String,
        responseUri: String,
        verifierJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        let key = try await resolveSigningKey(keys, kid: kid)

        let builder = MdocDeviceResponseBuilder(
            issuerSignedBytes: credentialBytes,
            algorithm: key.algorithm
        )

        return try await builder.build(
            nonce: nonce,
            audience: audience,
            responseUri: responseUri,
            verifierJwkThumbprint: verifierJwkThumbprint,
            disclosedClaims: disclosedClaims,
            signer: { data in try await self.signer.sign(keyId: key.keyId, data: data) }
        )
    }

    public func signMdocPresentationForDCAPI(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        nonce: String,
        origin: String,
        encryptionPublicJwkThumbprint: String?,
        kid: String?
    ) async throws -> Data {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        let key = try await resolveSigningKey(keys, kid: kid)

        let builder = MdocDeviceResponseBuilder(
            issuerSignedBytes: credentialBytes,
            algorithm: key.algorithm
        )

        return try await builder.buildForDCAPI(
            nonce: nonce,
            origin: origin,
            encryptionPublicJwkThumbprint: encryptionPublicJwkThumbprint,
            disclosedClaims: disclosedClaims,
            signer: { data in try await self.signer.sign(keyId: key.keyId, data: data) }
        )
    }

    public func signMdocPresentationForProximity(
        credentialBytes: Data,
        disclosedClaims: [String]?,
        sessionTranscriptBytes: Data,
        kid: String?
    ) async throws -> Data {
        try checkUnlocked()
        let keys = try await signer.listKeys()
        let key = try await resolveSigningKey(keys, kid: kid)

        let builder = MdocDeviceResponseBuilder(
            issuerSignedBytes: credentialBytes,
            algorithm: key.algorithm
        )

        return try await builder.buildForProximity(
            sessionTranscriptBytes: sessionTranscriptBytes,
            disclosedClaims: disclosedClaims,
            signer: { data in try await self.signer.sign(keyId: key.keyId, data: data) }
        )
    }

    public var unsupportedSchemaVersion: UnsupportedSchemaVersion? { credentialsKeystore.unsupportedSchemaVersion }

    public func exportEncryptedContainer() async throws -> Data {
        // WSCD signing keys themselves are not exportable as a JWE container
        // - they live in the hardware/remote HSM - but this adapter's
        // credentials, presentation records, and S.wscdCredentials ARE
        // PRF-protected and backend-synced via credentialsKeystore (see its
        // doc comment), exactly like a plain JweKeystore-backed wallet.
        try await credentialsKeystore.exportEncryptedContainer()
    }

    public func listKeys() -> [KeyInfo] {
        let semaphore = DispatchSemaphore(value: 0)
        let box = UnsafeMutablePointer<[KeyInfo]>.allocate(capacity: 1)
        box.initialize(to: [])
        Task.detached { [signer, box] in
            let signerKeys = (try? await signer.listKeys()) ?? []
            box.pointee = signerKeys.map {
                KeyInfo(keyId: $0.keyId, algorithm: $0.algorithm, pluginId: $0.pluginId)
            }
            semaphore.signal()
        }
        semaphore.wait()
        let result = box.pointee
        box.deinitialize(count: 1)
        box.deallocate()
        return result
    }

    // MARK: - Attestation (WSCD-specific)

    /// Returns the attestation certificate chain for a key, if available.
    ///
    /// For hardware-backed keys (FIDO2/CTAP2), this provides the
    /// attestation statement that proves key provenance for OID4VCI.
    public func attestationChain(keyId: String) async throws -> AttestationChain? {
        return try await signer.attestationChain(keyId: keyId)
    }

    /// Export the public key in JWK format.
    public func exportPublicKey(keyId: String) async throws -> Data {
        return try await signer.exportPublicKey(keyId: keyId)
    }

    // MARK: - Migration

    /// Migrate a key to a different WSCD plugin.
    ///
    /// If the migration result is `.reEnrollmentRequired`, the wallet
    /// should trigger credential re-issuance with the issuer.
    public func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult {
        return try await signer.migrateKey(keyId: keyId, targetPlugin: targetPlugin)
    }

    /// Return the security properties for a key, or nil if unavailable.
    public func securityProperties(keyId: String) async -> SignerSecurityProperties? {
        return try? await signer.securityProperties(keyId: keyId)
    }

    /// Asked by the wallet before the user is shown a transaction. A failure to
    /// obtain the answer is "cannot" (fail closed).
    public func scaAuthenticationCapability(keyId: String) async -> SignerFactorCapability {
        do {
            // The manager's probe can answer positively for a key it does not hold (it may route an unknown id to
            // the default plugin), which would fail only after consent: the key must exist, under this exact id,
            // which is also what the SCA sign requires.
            guard try await signer.listKeys().contains(where: { $0.keyId == keyId }) else {
                return .cannot("the signing key is not held by this keystore")
            }
            let capability = try await signer.authenticationCapability(keyId: keyId)
            // A factor only the host could supply is not usable: an SCA sign requires a fresh
            // authentication, which the manager refuses for the plugins that need one.
            guard capability.canReachTwoCategories, !capability.requiresHostVerifiedFactor else {
                return .cannot(capability.reason ?? "the key cannot reach two authentication categories")
            }
            return capability
        } catch {
            return .cannot("the key's authentication capability could not be determined")
        }
    }

    // MARK: - Credential storage (PRF-protected via credentialsKeystore)

    public func saveCredential(id: Int64, json: String) async throws {
        try await credentialsKeystore.saveCredential(id: id, json: json)
    }

    public func getCredential(id: Int64) async throws -> String? {
        try await credentialsKeystore.getCredential(id: id)
    }

    public func getAllCredentials() async throws -> [Int64: String] {
        try await credentialsKeystore.getAllCredentials()
    }

    public func deleteCredential(id: Int64) async throws {
        try await credentialsKeystore.deleteCredential(id: id)
    }

    public func clearCredentials() async throws {
        try await credentialsKeystore.clearCredentials()
    }

    // MARK: - Presentation history storage (PRF-protected via credentialsKeystore)

    public func savePresentationRecord(id: Int64, json: String) async throws {
        try await credentialsKeystore.savePresentationRecord(id: id, json: json)
    }

    public func getAllPresentationRecords() async throws -> [Int64: String] {
        try await credentialsKeystore.getAllPresentationRecords()
    }

    public func clearPresentationRecords() async throws {
        try await credentialsKeystore.clearPresentationRecords()
    }

    public func generateKeypairs(count: Int) async throws -> [KeypairInfo] {
        try checkUnlocked()
        guard count >= 1 else {
            throw KeystoreError.invalidParameter("count must be >= 1")
        }
        var result: [KeypairInfo] = []
        for _ in 0..<count {
            let keyId = try await generateKey(algorithm: "ES256")
            let pubData = try await signer.exportPublicKey(keyId: keyId)
            guard let jwk = try JSONSerialization.jsonObject(with: pubData) as? [String: Any],
                  jwk["kty"] != nil else {
                throw KeystoreError.invalidParameter("failed to parse exported public key as JWK")
            }
            result.append(KeypairInfo(keyId: keyId, publicKeyJWK: jwk))
        }
        return result
    }

    /// Generate `count` fresh keypairs and self-attest them in a single OID4VCI
    /// Key Attestation JWT (Appendix F.3, "attestation" proof type) - signed
    /// by the first freshly generated key itself, matching the spec's
    /// "issued... by the Wallet's key storage component itself" option, since
    /// this WSCD plugin has no separate wallet-provider/hardware attestation
    /// authority.
    public func generateKeyAttestation(nonce: String, count: Int) async throws -> String {
        try checkUnlocked()
        let keypairs = try await generateKeypairs(count: count)
        guard let signingKey = keypairs.first else {
            throw KeystoreError.invalidParameter("no keys generated for attestation")
        }

        let securityProps = try? await signer.securityProperties(keyId: signingKey.keyId)

        let header = JwtHelpers.jsonBase64Url([
            "alg": algorithmJoseId("ES256"),
            "typ": "key-attestation+jwt",
            "jwk": signingKey.publicKeyJWK,
        ] as [String: Any])

        var claims: [String: Any] = [
            "iat": Int(Date().timeIntervalSince1970),
            "nonce": nonce,
            "attested_keys": keypairs.map { $0.publicKeyJWK },
        ]

        if let keyStorage = securityProps?.keyStorage, !keyStorage.isEmpty {
            claims["key_storage"] = orderedUnique(keyStorage.map { toIso18045AttackPotential($0) ?? "iso_18045_basic" })
        } else {
            claims["key_storage"] = ["iso_18045_basic"]
        }

        if let userAuthentication = securityProps?.userAuthentication, !userAuthentication.isEmpty {
            let mapped = orderedUnique(userAuthentication.compactMap { toIso18045AttackPotential($0, omitIfNone: true) })
            if !mapped.isEmpty {
                claims["user_authentication"] = mapped
            }
        }

        let claimsB64 = JwtHelpers.jsonBase64Url(claims)
        let signingInput = "\(header).\(claimsB64)"
        let signature = try await signer.sign(keyId: signingKey.keyId, data: Data(signingInput.utf8))
        let sigB64 = EncryptedContainer.base64UrlEncode(signature)
        return "\(signingInput).\(sigB64)"
    }

    // MARK: - Private helpers

    private func checkUnlocked() throws {
        guard credentialsKeystore.isUnlocked else {
            throw KeystoreError.locked
        }
    }

    /// Pick the key to sign a presentation with. When `kid` is given (the
    /// credential being presented has a known bound key - see
    /// `StoredCredential.kid`), that EXACT key must be used - a wallet
    /// holding more than one key (e.g. after a batch issuance where each
    /// credential instance is bound to its own device key) would otherwise
    /// silently sign every credential with whichever key happens to be
    /// first, producing a structurally valid but cryptographically wrong
    /// signature for every credential except that one. Throws rather than
    /// silently falling back if the specified key isn't found, since signing
    /// with a different key is never a safe substitute. `kid` is nil only
    /// for genuinely credential-less call shapes (e.g. `signPresentation`'s
    /// legacy no-credential form), where "first available key" is the only
    /// meaningful choice.
    private func selectSigningKey(_ keys: [SignerKeyInfo], kid: String?) throws -> SignerKeyInfo {
        if let kid {
            guard let key = keys.first(where: { $0.keyId == kid }) else {
                throw KeystoreError.keyNotFound("Signing key '\(kid)' not found - this credential's bound key is unavailable")
            }
            return key
        }
        guard let key = keys.first else {
            throw KeystoreError.keyNotFound("no keys available for signing")
        }
        return key
    }

    /// ``selectSigningKey(_:kid:)``, but able to map the `kid` a credential
    /// names its holder key by onto the WSCD key that signs for it.
    ///
    /// The WSCD assigns its own key ids (RFC 7638 thumbprints), but a
    /// credential may name the key any of three ways: by that id, by a
    /// `did:jwk` verification method, or by a thumbprint computed elsewhere
    /// (an mdoc device key, an SD-JWT `cnf.jwk`). A `did:jwk` resolves offline
    /// - the key is the identifier - so all three reduce to a thumbprint
    /// comparison, and no mapping needs to be persisted.
    private func resolveSigningKey(_ keys: [SignerKeyInfo], kid: String?) async throws -> SignerKeyInfo {
        guard let kid else { return try selectSigningKey(keys, kid: nil) }
        if let exact = keys.first(where: { $0.keyId == kid }) { return exact }

        let wanted = thumbprintOfDidJwk(kid) ?? kid
        if let match = keys.first(where: { $0.keyId == wanted }) { return match }

        for key in keys {
            guard let data = try? await signer.exportPublicKey(keyId: key.keyId),
                  let jwk = try? jsonDict(from: data),
                  JwtHelpers.jwkThumbprint(jwk) == wanted
            else { continue }
            return key
        }
        throw KeystoreError.keyNotFound(
            "Signing key '\(kid)' not found - this credential's bound key is unavailable"
        )
    }

    /// The JWK thumbprint of the key a `did:jwk` embeds, or nil if `kid` is not
    /// one of its verification methods - see
    /// ``HolderIdentity/thumbprintOfDidJwk(_:)``, which this defers to. A
    /// did:jwk document has only `#0`, so any other fragment names nothing and
    /// must not select a key.
    private func thumbprintOfDidJwk(_ kid: String) -> String? {
        HolderIdentity.thumbprintOfDidJwk(kid)
    }

    /// The `did:jwk` for a public key, when this issuance identifies the
    /// holder that way. Nil for ``HolderBinding/embeddedJwk``, where the proof
    /// carries the key instead of naming it.
    private func holderDid(forPublicKey jwk: [String: Any], binding: HolderBinding) throws -> String? {
        guard binding == .didJwk else { return nil }
        let stringMembers = jwk.compactMapValues { $0 as? String }
        // No fallback: `.didJwk` is what this issuance negotiated, and the
        // embedded-jwk shape is a different profile the Issuer did not agree
        // to. Failing here says so; falling back would send a proof the Issuer
        // cannot verify and report it as success.
        //
        // Checking only `kty` is not enough (review finding): a malformed
        // WSCD export such as `{"kty": "EC"}` with no `x`/`y` would still
        // mint a `did:jwk`, just one `Did.resolveDidJwk` itself rejects as
        // unusable - sending a DIIP proof whose `iss`/`kid` cannot be
        // resolved by anyone, including this wallet. Validating with the
        // SAME check `resolveDidJwk` applies catches it here instead.
        guard Did.isUsablePublicJwk(stringMembers) else {
            throw KeystoreError.cryptoError(
                "Could not derive a did:jwk for the negotiated DIIP holder binding"
            )
        }
        return Did.createDidJwk(stringMembers)
    }

    /// Translate SIROS's internal WSCD key-storage/user-authentication
    /// vocabulary (`software`/`hardware`/`trusted_execution`/`remote_hsm`,
    /// see `SignerSecurityProperties`) into the OID4VCI Key Attestation JWT's
    /// registered `iso_18045_*` attack-potential-resistance values.
    ///
    /// Confirmed via a real conformance-test issuer that passing the raw
    /// internal string through unmapped (e.g. `"software"`) produces a
    /// `key_storage`/`user_authentication` value the issuer doesn't
    /// recognize. Mappings are necessarily approximate (SIROS's vocabulary is
    /// coarser than the ISO 18045 scale) - conservative/lower tiers are
    /// preferred over overclaiming resistance we can't actually back up.
    private func toIso18045AttackPotential(_ raw: String, omitIfNone: Bool = false) -> String? {
        if raw.hasPrefix("iso_18045_") { return raw }
        switch raw.lowercased() {
        case "none": return omitIfNone ? nil : "iso_18045_basic"
        case "software": return "iso_18045_basic"
        case "hardware": return "iso_18045_moderate"
        case "trusted_execution": return "iso_18045_enhanced-basic"
        case "remote_hsm": return "iso_18045_high"
        default: return "iso_18045_basic"
        }
    }

    private func orderedUnique(_ items: [String]) -> [String] {
        var seen = Set<String>()
        return items.filter { seen.insert($0).inserted }
    }

    private func algorithmJoseId(_ algorithm: String) -> String {
        switch algorithm.uppercased() {
        case "ES256", "P-256": return "ES256"
        case "EDDSA", "ED25519": return "EdDSA"
        default: return algorithm
        }
    }

    private func jsonDict(from data: Data) throws -> [String: Any] {
        guard let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw KeystoreError.cryptoError("Invalid JWK JSON")
        }
        return dict
    }

    private func filterDisclosures(_ disclosures: [String], claimNames: [String]) -> [String] {
        disclosures.filter { disclosure in
            guard let data = Data(base64Encoded: padBase64(disclosure)),
                  let array = try? JSONSerialization.jsonObject(with: data) as? [Any],
                  array.count >= 2,
                  let name = array[1] as? String else {
                return false
            }
            return claimNames.contains(name)
        }
    }

    private func padBase64(_ str: String) -> String {
        var s = str.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = s.count % 4
        if remainder > 0 {
            s += String(repeating: "=", count: 4 - remainder)
        }
        return s
    }
}

#endif // canImport(CryptoKit)
