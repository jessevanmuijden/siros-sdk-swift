// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit
@preconcurrency import SwiftCBOR

/// A configurable `Signer` test double, mirroring the Kotlin test suite's
/// MockK-based `createMockSigner()`.
private final class MockSigner: Signer, @unchecked Sendable {
    var generatedKeyIds: [String] = []
    var securityPropertiesResult: Result<SignerSecurityProperties, Error> = .success(
        SignerSecurityProperties(keyStorage: ["hardware"], userAuthentication: ["pin"])
    )
    var exportPublicKeyOverride: Data?

    private var keyCounter = 0
    private let realKey = P256.Signing.PrivateKey()

    func generateKey(algorithm: String) async throws -> String {
        keyCounter += 1
        let keyId = "test-key-\(keyCounter)"
        generatedKeyIds.append(keyId)
        return keyId
    }

    func sign(keyId: String, data: Data) async throws -> Data {
        Data(repeating: 0, count: 64)
    }

    func listKeys() async throws -> [SignerKeyInfo] {
        [SignerKeyInfo(keyId: "test-key-1", algorithm: "ES256")]
    }

    func deleteKey(keyId: String) async throws {}

    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }

    func exportPublicKey(keyId: String) async throws -> Data {
        if let override = exportPublicKeyOverride { return override }
        let jwk = JwtHelpers.publicKeyJwk(realKey)
        return try JSONSerialization.data(withJSONObject: jwk)
    }

    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult {
        .migrated(newKeyId: keyId)
    }

    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        switch securityPropertiesResult {
        case .success(let props): return props
        case .failure(let error): throw error
        }
    }
}

final class WscdKeystoreAdapterTest: XCTestCase {

    private func unlockedAdapter(_ signer: MockSigner = MockSigner()) async throws -> WscdKeystoreAdapter {
        let adapter = WscdKeystoreAdapter(signer: signer)
        try await adapter.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())
        return adapter
    }

    func testInitiallyLocked() {
        let adapter = WscdKeystoreAdapter(signer: MockSigner())
        XCTAssertFalse(adapter.isUnlocked)
    }

    func testUnlockSetsState() async throws {
        let adapter = try await unlockedAdapter()
        XCTAssertTrue(adapter.isUnlocked)
    }

    func testLockClearsState() async throws {
        let adapter = try await unlockedAdapter()
        adapter.lock()
        XCTAssertFalse(adapter.isUnlocked)
    }

    // MARK: - wscdCredentials

    /// Mirrors `JweKeystoreTests.testWscdCredentialsRoundTripThroughExportAndReimport`
    /// one layer up: `WscdKeystoreAdapter.exportWscdCredentialsState`/
    /// `setWscdCredentialsState` must actually round-trip through this
    /// adapter's own `exportEncryptedContainer` (backed by its internal
    /// `credentialsKeystore`), not just exist as inert forwarding methods -
    /// this is what lets a FIDO2 key enrolled via this WSCD-backed keystore
    /// stay addressable after an app restart / on another device.
    func testWscdCredentialsStateRoundTripsThroughAdapterExport() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)

        let fido2State = "{\"keys\":[{\"kid\":\"fido-0\",\"credential_id\":\"AQID\"}],\"next_id\":1}"
        await adapter.setWscdCredentialsState(pluginId: "fido2", state: fido2State)
        let before = await adapter.exportWscdCredentialsState()
        XCTAssertEqual(before["fido2"], fido2State)

        let exported = try await adapter.exportEncryptedContainer()
        adapter.lock()
        XCTAssertFalse(adapter.isUnlocked)

        let reloaded = WscdKeystoreAdapter(signer: MockSigner())
        try await reloaded.unlock(prfOutput: Data(), encryptedContainer: exported, hkdfSalt: Data(), hkdfInfo: Data())
        let after = await reloaded.exportWscdCredentialsState()
        XCTAssertEqual(after["fido2"], fido2State)
    }

    // MARK: - generateKeyAttestation

    /// Raw WSCD vocabulary ("hardware"/"pin") must be translated to the
    /// OID4VCI spec's registered iso_18045_* values, not passed through -
    /// confirmed via a real conformance-test issuer that an unrecognized enum
    /// value here gets rejected.
    func testGenerateKeyAttestationBuildsValidJwtWithAttestedKeysAndSecurityProperties() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyAttestation(nonce: "test-nonce-123", count: 3)

        let parts = jwt.split(separator: ".")
        XCTAssertEqual(parts.count, 3)

        let header = JwtHelpers.parseJwtHeader(jwt)
        XCTAssertEqual(header?["typ"] as? String, "key-attestation+jwt")
        XCTAssertEqual(header?["alg"] as? String, "ES256")
        XCTAssertNotNil(header?["jwk"])

        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertEqual(claims?["nonce"] as? String, "test-nonce-123")
        let attestedKeys = claims?["attested_keys"] as? [[String: Any]]
        XCTAssertEqual(attestedKeys?.count, 3)
        XCTAssertEqual(claims?["key_storage"] as? [String], ["iso_18045_moderate"])
        XCTAssertEqual(claims?["user_authentication"] as? [String], ["iso_18045_basic"])

        // 3 keys generated for the batch, matching count - not reusing a
        // single pre-existing key.
        XCTAssertEqual(signer.generatedKeyIds.count, 3)
    }

    /// The exact real-world case that caused a conformance-test issuer to
    /// reject the attestation: the "softkey" WSCD plugin reports raw
    /// key_storage=["software"], which isn't a registered iso_18045_* value
    /// on its own.
    func testGenerateKeyAttestationMapsSoftwareKeyStorageToIso18045Basic() async throws {
        let signer = MockSigner()
        signer.securityPropertiesResult = .success(
            SignerSecurityProperties(keyStorage: ["software"], userAuthentication: [])
        )
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyAttestation(nonce: "n", count: 1)
        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertEqual(claims?["key_storage"] as? [String], ["iso_18045_basic"])
    }

    func testGenerateKeyAttestationDefaultsKeyStorageWhenSecurityPropertiesUnavailable() async throws {
        let signer = MockSigner()
        signer.securityPropertiesResult = .failure(KeystoreError.invalidParameter("not supported"))
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyAttestation(nonce: "n", count: 1)
        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertEqual(claims?["key_storage"] as? [String], ["iso_18045_basic"])
        XCTAssertNil(claims?["user_authentication"])
    }

    // MARK: - generateKeyProof

    func testGenerateKeyProofBuildsValidPopJwt() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyProof(
            keyId: "test-key-1",
            typ: "oauth-client-attestation-pop+jwt",
            issuer: "siros-sample://callback",
            audience: "https://wallet-backend.example.com",
            extraClaims: ["nonce": "challenge-abc"]
        )

        let header = JwtHelpers.parseJwtHeader(jwt)
        XCTAssertEqual(header?["typ"] as? String, "oauth-client-attestation-pop+jwt")
        XCTAssertEqual(header?["alg"] as? String, "ES256")
        XCTAssertNotNil(header?["jwk"])

        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertEqual(claims?["aud"] as? String, "https://wallet-backend.example.com")
        XCTAssertEqual(claims?["nonce"] as? String, "challenge-abc")
        XCTAssertEqual(claims?["iss"] as? String, "siros-sample://callback")
        XCTAssertNotNil(claims?["iat"])
        XCTAssertNotNil(claims?["exp"])
        XCTAssertNotNil(claims?["jti"])
    }

    func testGenerateKeyProofOmitsExtraClaimsWhenNoneGiven() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateKeyProof(
            keyId: "test-key-1",
            typ: "oauth-client-attestation-pop+jwt",
            issuer: "siros-sample://callback",
            audience: "https://issuer.example.com",
            extraClaims: [:]
        )

        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertNil(claims?["nonce"])
    }

    /// Regression (review finding): `exportPublicKey` only promises a public
    /// JWK, not a `kid` of its own - a HAIP proof's embedded `jwk` must carry
    /// the WSCD's own `key.keyId` so `resolveSigningKey` can match it
    /// directly on its first, cheap attempt instead of falling back to
    /// exporting and thumbprinting every key the WSCD holds.
    func testGenerateProofEmbedsTheWscdKeyIdAsTheJwkKidForHaip() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateProof(
            audience: "https://issuer.example.com",
            nonce: "n",
            freshKey: false,
            holderBinding: .embeddedJwk
        )

        let header = JwtHelpers.parseJwtHeader(jwt)
        let jwk = header?["jwk"] as? [String: Any]
        XCTAssertEqual(jwk?["kid"] as? String, "test-key-1")
        // The key's own public-key members are still exactly what
        // `exportPublicKey` returned, untouched.
        XCTAssertNotNil(jwk?["x"])
        XCTAssertNotNil(jwk?["y"])
        XCTAssertNil(header?["kid"], "HAIP must not ALSO carry a top-level header kid")
    }

    func testGenerateDPoPProofBuildsProofThroughSigner() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)

        let jwt = try await adapter.generateDPoPProof(
            keyId: "test-key-1",
            htm: "POST",
            htu: "https://issuer.example.com/credential",
            nonce: "n-1",
            accessTokenHash: "ath-value"
        )

        let header = JwtHelpers.parseJwtHeader(jwt)
        XCTAssertEqual(header?["typ"] as? String, "dpop+jwt")
        XCTAssertEqual(header?["alg"] as? String, "ES256")
        XCTAssertNotNil(header?["jwk"])

        let claims = JwtHelpers.parseJwtPayload(jwt)
        XCTAssertEqual(claims?["htm"] as? String, "POST")
        XCTAssertEqual(claims?["htu"] as? String, "https://issuer.example.com/credential")
        XCTAssertEqual(claims?["nonce"] as? String, "n-1")
        XCTAssertEqual(claims?["ath"] as? String, "ath-value")
        XCTAssertNotNil(claims?["jti"])
        XCTAssertNil(claims?["iss"])
        XCTAssertNil(claims?["exp"])
    }

    func testGenerateKeyProofThrowsForUnknownKeyId() async throws {
        let adapter = try await unlockedAdapter()

        do {
            _ = try await adapter.generateKeyProof(keyId: "does-not-exist", typ: "x", issuer: "iss", audience: "aud", extraClaims: [:])
            XCTFail("expected keyNotFound")
        } catch KeystoreError.keyNotFound {
            // expected
        }
    }

    // MARK: - signMdocPresentationForDCAPI

    private func buildTaggedItem(digestId: UInt64, elementIdentifier: String, elementValue: String) -> CBOR {
        let item: CBOR = .map([
            .utf8String("digestID"): .unsignedInt(digestId),
            .utf8String("random"): .byteString([UInt8](repeating: 0, count: 16)),
            .utf8String("elementIdentifier"): .utf8String(elementIdentifier),
            .utf8String("elementValue"): .utf8String(elementValue),
        ])
        return .tagged(.encodedCBORDataItem, .byteString(item.encode()))
    }

    /// Build a synthetic mdoc credential's raw bytes: a DeviceResponse-shaped
    /// envelope, matching `MdocCbor.parseStoredCredential`'s expected shape
    /// (mirrors `CredentialUtilsTests.buildMdocRaw`).
    private func buildIssuerSignedEnvelope() -> Data {
        let items: CBOR = .array([
            buildTaggedItem(digestId: 0, elementIdentifier: "family_name", elementValue: "Doe"),
        ])
        let nameSpaces: CBOR = .map([.utf8String("org.iso.18013.5.1"): items])
        let issuerAuth: CBOR = .array(Array(repeating: .byteString([]), count: 4))
        let issuerSigned: CBOR = .map([
            .utf8String("nameSpaces"): nameSpaces,
            .utf8String("issuerAuth"): issuerAuth,
        ])
        let document: CBOR = .map([
            .utf8String("docType"): .utf8String("org.iso.18013.5.1.mDL"),
            .utf8String("issuerSigned"): issuerSigned,
        ])
        let envelope: CBOR = .map([
            .utf8String("documents"): .array([document]),
            .utf8String("status"): .unsignedInt(0),
        ])
        return Data(envelope.encode())
    }

    func testSignMdocPresentationForDCAPIProducesDeviceResponse() async throws {
        let adapter = try await unlockedAdapter()

        let responseBytes = try await adapter.signMdocPresentationForDCAPI(
            credentialBytes: buildIssuerSignedEnvelope(),
            disclosedClaims: nil,
            nonce: "test-nonce",
            origin: "https://verifier.example.com",
            encryptionPublicJwkThumbprint: nil,
            kid: nil
        )

        let decoded = try CBOR.decode([UInt8](responseBytes))
        guard case .map(let root)? = decoded else {
            return XCTFail("expected a top-level CBOR map")
        }
        XCTAssertEqual(root[.utf8String("version")], .utf8String("1.0"))
        guard case .array(let documents)? = root[.utf8String("documents")], documents.count == 1,
              case .map(let doc) = documents[0] else {
            return XCTFail("expected a single document in the DeviceResponse")
        }
        guard case .map(let deviceSigned)? = doc[.utf8String("deviceSigned")],
              case .map(let deviceAuth)? = deviceSigned[.utf8String("deviceAuth")],
              deviceAuth[.utf8String("deviceSignature")] != nil else {
            return XCTFail("expected deviceSigned.deviceAuth.deviceSignature to be present")
        }
    }

    /// Regression (review finding): `signMdocPresentation`,
    /// `signMdocPresentationForDCAPI`, and `signMdocPresentationForProximity`
    /// called `selectSigningKey` (exact `keyId` match only) instead of
    /// `resolveSigningKey` (which also matches a thumbprint, the way a
    /// DIIP-bound mdoc device key names it) - a credential whose `kid` is a
    /// thumbprint rather than the WSCD's own key id threw `keyNotFound` on
    /// every mdoc presentation path even though the matching key WAS held.
    func testSignMdocPresentationForDCAPIResolvesAKidNamedByThumbprintNotWscdKeyId() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)
        let jwkData = try await adapter.exportPublicKey(keyId: "test-key-1")
        let jwk = try JSONSerialization.jsonObject(with: jwkData) as? [String: Any]
        let thumbprint = try XCTUnwrap(jwk.flatMap { JwtHelpers.jwkThumbprint($0) })
        XCTAssertNotEqual(
            thumbprint, "test-key-1",
            "the test must exercise the thumbprint-fallback path, not an accidental exact keyId match"
        )

        let responseBytes = try await adapter.signMdocPresentationForDCAPI(
            credentialBytes: buildIssuerSignedEnvelope(),
            disclosedClaims: nil,
            nonce: "test-nonce",
            origin: "https://verifier.example.com",
            encryptionPublicJwkThumbprint: nil,
            kid: thumbprint
        )
        XCTAssertFalse(responseBytes.isEmpty)
    }

    // MARK: - cnf fail-closed (review findings)

    private func sdJwt(_ payload: String) -> String {
        func b64(_ text: String) -> String {
            EncryptedContainer.base64UrlEncode(Data(text.utf8))
        }
        return "\(b64(#"{"alg":"ES256","typ":"dc+sd-jwt"}"#)).\(b64(payload)).sig~"
    }

    /// Regression (review finding): a `cnf` present but malformed (`kid` not
    /// a string, no `jwk`) must refuse rather than reach
    /// `resolveSigningKey(kid: nil)`'s "use the first available key"
    /// fallback.
    func testAMalformedCnfRefusesRatherThanSigningWithAnUnrelatedKey() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)
        let credential = sdJwt(#"{"vct":"urn:example:x","cnf":{"kid":123}}"#)

        do {
            _ = try await adapter.signVpToken(
                credential: credential, disclosedClaims: nil, nonce: "n",
                audience: "https://verifier.example", kid: nil
            )
            XCTFail("a cnf this adapter cannot resolve must refuse, not sign with an unrelated key")
        } catch {
            // expected
        }
    }

    /// Regression (review finding): the KB-JWT header must follow the SAME
    /// `cnf.kid`-over-`cnf.jwk` precedence `resolveCnfKid` applies when
    /// selecting the signing key, not a separate "is cnf.jwk present"
    /// re-check - a credential carrying both must be presented with a `kid`
    /// header, not an embedded jwk.
    func testACredentialWithBothCnfKidAndCnfJwkFollowsCnfKidNotCnfJwk() async throws {
        let signer = MockSigner()
        let adapter = try await unlockedAdapter(signer)
        // MockSigner always has exactly one key, "test-key-1" - cnf.kid names
        // it directly, so no DID/thumbprint resolution is needed to observe
        // the header precedence this test is about.
        let unrelatedJwk: [String: Any] = ["kty": "EC", "crv": "P-256", "x": "aa", "y": "bb"]
        let jwkJson = String(
            data: try JSONSerialization.data(withJSONObject: unrelatedJwk, options: .sortedKeys),
            encoding: .utf8
        )!
        let credential = sdJwt(#"{"vct":"urn:example:x","cnf":{"kid":"test-key-1","jwk":\#(jwkJson)}}"#)

        let vp = try await adapter.signVpToken(
            credential: credential, disclosedClaims: nil, nonce: "n",
            audience: "https://verifier.example", kid: nil
        )
        let kb = try XCTUnwrap(vp.split(separator: "~").last.map(String.init))
        let header = JwtHelpers.parseJwtHeader(kb)
        XCTAssertEqual(header?["kid"] as? String, "test-key-1", "cnf.kid wins, per resolveCnfKid's own precedence")
        XCTAssertNil(header?["jwk"], "must not also embed the unrelated cnf.jwk key")
    }

    /// Review finding (go-wallet-backend#502): a non-nil EMPTY `disclosedClaims` used to fall into the same "no
    /// filter" branch as `nil` and disclose every disclosure the credential carried. It must disclose NONE -
    /// distinct from `nil`, which still means "no filter was given at all" for callers outside the consent-gated
    /// `sign_presentation` path.
    func testSignVpTokenWithExplicitEmptyDisclosedClaimsDisclosesNothing() async throws {
        let adapter = try await unlockedAdapter()
        let issuerJwt = sdJwt(#"{"vct":"urn:example:x"}"#).replacingOccurrences(of: "~", with: "")
        let d1 = EncryptedContainer.base64UrlEncode(Data(#"["salt1","given_name","Alice"]"#.utf8))
        let d2 = EncryptedContainer.base64UrlEncode(Data(#"["salt2","family_name","Smith"]"#.utf8))
        let credential = "\(issuerJwt)~\(d1)~\(d2)~"

        let vp = try await adapter.signVpToken(
            credential: credential, disclosedClaims: [], nonce: "n",
            audience: "https://verifier.example", kid: nil
        )

        let parts = vp.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        // Should have ONLY: issuerJwt, KB-JWT - no disclosures at all.
        XCTAssertEqual(parts.count, 2, "an explicit empty disclosedClaims must disclose zero claims, not every claim")
        XCTAssertEqual(parts[0], issuerJwt)
        XCTAssertEqual(parts[1].split(separator: ".").count, 3) // KB-JWT
    }

    /// Regression (review finding): checking only `kty` let a malformed WSCD
    /// export (no `x`/`y`) mint a `did:jwk` that `Did.resolveDidJwk` itself
    /// would reject - this must fail at mint time instead.
    func testGenerateProofForDiipRefusesAnIncompleteExportedPublicKey() async throws {
        let signer = MockSigner()
        signer.exportPublicKeyOverride = try JSONSerialization.data(withJSONObject: ["kty": "EC"])
        let adapter = WscdKeystoreAdapter(signer: signer, profile: .diip)
        try await adapter.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())

        do {
            _ = try await adapter.generateProof(
                audience: "https://issuer.example.com", nonce: "n", freshKey: false, holderBinding: nil
            )
            XCTFail("an incomplete exported public key must not mint a did:jwk nothing can resolve")
        } catch {
            // expected
        }
    }
}

#else
// On non-Apple platforms, CryptoKit is unavailable
// so we just have a placeholder test
final class WscdKeystoreAdapterTest: XCTestCase {
    func testCryptoKitUnavailable() {
        XCTAssertTrue(true)
    }
}
#endif
