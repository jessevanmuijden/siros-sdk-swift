// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosWallet
#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1, including
// SHA256 - needed only to compute the expected thumbprint independently in
// `testGenerateProofsRecoversKeyIdFromThumbprintWhenJwkHasNoKid` below.
import Crypto
#endif

/// Integration-level wiring tests for `SirosWallet.requestBackendKeyAttestation`'s
/// use of `WscdSelectionPolicy` (see `WscdSelectionPolicyTests` for exhaustive
/// coverage of the policy's own branch logic in isolation).
///
/// Unlike `SirosWalletKeyAttestationTests`, these don't need CryptoKit / a
/// real `JweKeystore`: `SirosWallet.init?` only falls back to `JweKeystore()`
/// when the `keystore` parameter is nil, so passing an explicit stub
/// keystore (as every test here does) works identically on Linux and Apple
/// platforms.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// Minimal `KeystoreManager` stub - `label` is baked into every generated
/// key ID so a test can tell which stub instance actually produced a given
/// batch of keys without needing to compare object identity.
private final class StubKeystoreManager: KeystoreManager, @unchecked Sendable {
    let label: String
    private(set) var generateKeypairsCallCount = 0
    private(set) var generateKeyAttestationCallCount = 0
    /// Overrides `generateProof`'s return value, one entry per call in
    /// order (falls back to `"\(label)-proof"` once exhausted) - lets a test
    /// hand back a realistic JWT (with an embedded `jwk.kid` header) instead
    /// of the default placeholder string.
    var proofJwtOverrides: [String] = []
    private var proofCallCount = 0
    /// The binding the wallet asked for on the last proof - lets a test assert
    /// that an issuer's advertised methods reached the keystore.
    private(set) var lastHolderBinding: HolderBinding?

    /// What `isWscdPluginOnboarded` reports - `false` simulates a user with no onboarded token.
    var onboarded = true
    func isWscdPluginOnboarded(pluginId: String) async -> Bool { onboarded }

    init(label: String) { self.label = label }

    var isUnlocked: Bool { true }
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { "\(label)-key" }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String {
        try await generateProof(audience: audience, nonce: nonce, freshKey: freshKey, holderBinding: nil)
    }
    func generateProof(
        audience: String, nonce: String, freshKey: Bool, holderBinding: HolderBinding?
    ) async throws -> String {
        lastHolderBinding = holderBinding
        defer { proofCallCount += 1 }
        return proofCallCount < proofJwtOverrides.count ? proofJwtOverrides[proofCallCount] : "\(label)-proof"
    }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
    func exportEncryptedContainer() async throws -> Data { Data() }
    func listKeys() -> [KeyInfo] { [] }
    func saveCredential(id: Int64, json: String) async throws {}
    func getCredential(id: Int64) async throws -> String? { nil }
    func getAllCredentials() async throws -> [Int64: String] { [:] }
    func deleteCredential(id: Int64) async throws {}
    func clearCredentials() async throws {}
    func savePresentationRecord(id: Int64, json: String) async throws {}
    func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
    func clearPresentationRecords() async throws {}

    func generateKeypairs(count: Int) async throws -> [KeypairInfo] {
        generateKeypairsCallCount += 1
        return (0..<count).map { KeypairInfo(keyId: "\(label)-key-\($0)", publicKeyJWK: ["kty": "EC"]) }
    }

    // Overrides `KeystoreManager`'s default (which throws "not supported") -
    // tags its output with `label` so a regression test can tell which
    // instance actually produced the self-signed fallback attestation
    // without needing object identity.
    func generateKeyAttestation(nonce: String, count: Int) async throws -> String {
        generateKeyAttestationCallCount += 1
        return "\(label)-attestation"
    }
}

final class SirosWalletWscdSelectionTests: XCTestCase {

    private func fakeApiClient(keyAttestationJwt: String = "fake-jwt") -> BackendApiClient {
        BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, _, _, _ in
            try! JSONSerialization.data(withJSONObject: ["key_attestation": keyAttestationJwt])
        })
    }

    private func offer(issuer: String, configId: String) -> CredentialOffer {
        CredentialOffer(
            credentialConfigurationId: configId,
            credentialIssuerIdentifier: issuer,
            credentialName: "Test Credential",
            issuerName: "Test Issuer"
        )
    }

    func testBackwardCompatibleWhenAvailableKeystoresNotSet() async throws {
        // No `availableKeystores` at all - even with a declared requirement
        // on the active VCTM, selection logic must not engage, and
        // generation must use the wallet's single default keystore exactly
        // as it did before this feature existed.
        let defaultKeystore = StubKeystoreManager(label: "default")
        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        XCTAssertNotNil(wallet)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        let (result, effectiveKeystore) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)

        XCTAssertEqual(result?.keyIds.first, "default-key-0")
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 1)
        XCTAssert(effectiveKeystore === defaultKeystore, "no availableKeystores configured - the resolved keystore must be the default")
    }

    func testUsesDefaultMappingSelectedPluginInsteadOfDefaultKeystore() async throws {
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")

        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]
        config.defaultWscdMapping = ["https://issuer.example.com|urn:example:pid": "fido2"]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeOffer = offer(issuer: "https://issuer.example.com", configId: "urn:example:pid")
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        let (result, effectiveKeystore) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)

        XCTAssertEqual(result?.keyIds.first, "fido2-key-0", "must generate via the selected fido2 keystore, not the default")
        XCTAssertEqual(fidoKeystore.generateKeypairsCallCount, 1)
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 0, "must NOT touch the default keystore once a plugin is selected")
        XCTAssert(effectiveKeystore === fidoKeystore, "the resolved keystore returned to the caller must be the one actually used")
    }

    func testUsesMddlSchemaRequirementForMdocCredentials() async throws {
        // Same wiring, but the active type metadata is the mdoc analogue
        // (`activeMddlSchema`), not `activeVctm` - proves the mdoc path is
        // also threaded through, not just SD-JWT.
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")

        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeOffer = offer(issuer: "https://issuer.example.com", configId: "org.iso.18013.5.1.mDL")
        w.activeMddlSchema = MddlSchema(
            format: "mso_mdoc",
            doctype: "org.iso.18013.5.1.mDL",
            requiredKeyStorage: "iso_18045_high"
        )

        let (result, _) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)

        // Only one eligible plugin ("fido2") is registered - auto-picked, no prompt needed.
        XCTAssertEqual(result?.keyIds.first, "fido2-key-0")
    }

    func testNotOnboardedFido2FailsBeforeAnyKeyGenerationOrPin() async throws {
        // iso_18045_high needed, fido2 is the only sufficient plugin but its
        // token is not onboarded: must throw wscdNotOnboarded without ever reaching
        // generateKeypairs (where the PIN prompt would happen) - neither on the
        // fido2 keystore nor by falling back to the default one.
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")
        fidoKeystore.onboarded = false
        defaultKeystore.onboarded = false  // the wallet's main keystore has no record either
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore, "softkey": defaultKeystore]

        let w = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        do {
            _ = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
            XCTFail("expected WscdSelectionError.wscdNotOnboarded to propagate")
        } catch WscdSelectionError.wscdNotOnboarded(_, _, let tier, let notOnboarded) {
            XCTAssertEqual(tier, "iso_18045_high")
            XCTAssertEqual(notOnboarded, ["fido2"])
        }
        XCTAssertEqual(fidoKeystore.generateKeypairsCallCount, 0)
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 0)
    }

    func testOnboardingRecordedOnMainKeystoreCounts() async throws {
        // The fido2 adapter itself knows nothing, but the wallet's main keystore
        // (where `wscdCredentials` lives) reports the plugin onboarded.
        let mainKeystore = StubKeystoreManager(label: "main")
        let fidoKeystore = StubKeystoreManager(label: "fido2")
        fidoKeystore.onboarded = false
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]
        let w = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: mainKeystore)!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        let (result, _) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
        XCTAssertEqual(result?.keyIds.first, "fido2-key-0")
    }

    #if canImport(CryptoKit)
    func testDefaultJweMainKeystoreDoesNotVouchForNonOnboardedFido2() async throws {
        // The default main store (JweKeystore) has no onboarding knowledge: it must NOT
        // make a non-onboarded fido2 adapter look onboarded via the main-keystore fallback.
        let fidoKeystore = StubKeystoreManager(label: "fido2")
        fidoKeystore.onboarded = false
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]
        let w = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: JweKeystore())!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        do {
            _ = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
            XCTFail("expected WscdSelectionError.wscdNotOnboarded")
        } catch WscdSelectionError.wscdNotOnboarded(_, _, _, let notOnboarded) {
            XCTAssertEqual(notOnboarded, ["fido2"])
        }
        XCTAssertEqual(fidoKeystore.generateKeypairsCallCount, 0)
    }

    func testJweMainKeystoreWithRecordedFido2StateCountsAsOnboarded() async throws {
        // Enrollment metadata lives only in the JWE main keystore (synced S.wscdCredentials);
        // the fido2 adapter itself reports nothing. The account IS onboarded.
        let fidoKeystore = StubKeystoreManager(label: "fido2")
        fidoKeystore.onboarded = false
        let jwe = JweKeystore()
        await jwe.setWscdCredentials(pluginId: "fido2", state: "c3RhdGU")
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]
        let w = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: jwe)!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        let (result, _) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
        XCTAssertEqual(result?.keyIds.first, "fido2-key-0")
    }
    #endif

    func testOnboardedFido2StillGeneratesKeys() async throws {
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]
        let w = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        let (result, _) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
        XCTAssertEqual(result?.keyIds.first, "fido2-key-0")
    }

    func testThrowsNoEligiblePluginWhenNoneMeetTheRequirement() async throws {
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        var config = WalletConfig(backendUrl: "https://example.invalid")
        // Registered under a plugin ID not in `WscdPluginCapabilities`'s
        // static table - nothing meets any requirement.
        config.availableKeystores = ["some-unknown-plugin": StubKeystoreManager(label: "unknown")]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        do {
            _ = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
            XCTFail("expected WscdSelectionError.noEligiblePlugin to propagate")
        } catch WscdSelectionError.noEligiblePlugin {
            // Expected - and critically, `defaultKeystore.generateKeypairs`
            // must never have been reached (see assertion below): this must
            // never silently fall back to an insufficient plugin.
        }
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 0)
    }

    func testNoRequirementDeclaredUsesDefaultKeystoreEvenWithAvailableKeystoresSet() async throws {
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]
        // No activeVctm/activeMddlSchema at all -> requiredTier resolves to nil -> no-op.

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()

        let (result, _) = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)

        XCTAssertEqual(result?.keyIds.first, "softkey-key-0")
        XCTAssertEqual(fidoKeystore.generateKeypairsCallCount, 0)
    }

    func testThrowsNoEligiblePluginWhenAvailableKeystoresIsExplicitlyEmpty() async throws {
        // `availableKeystores` set to a non-nil but EMPTY dictionary - the
        // host app opted into multi-plugin selection but has zero plugins
        // registered right now. This must throw `noEligiblePlugin` (like any
        // other zero-eligible case), not silently skip selection entirely
        // and fall back to the default keystore.
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = [:]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        w.apiClient = fakeApiClient()
        w.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        do {
            _ = try await w.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
            XCTFail("expected WscdSelectionError.noEligiblePlugin to propagate")
        } catch WscdSelectionError.noEligiblePlugin {
            // Expected.
        }
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 0, "must never silently fall back to the default keystore")
    }

    // Regression test for the fallback-keystore-bypass bug: when
    // `requestBackendKeyAttestation` resolves a non-default plugin (via
    // `WscdSelectionPolicy`) but the backend attestation call itself then
    // fails (forcing `generateProofs`'s self-signed fallback), the fallback
    // must run on that SAME resolved plugin, not silently on `self.keystore`
    // - otherwise a resolved higher-tier plugin is bypassed and a
    // lower-tier self-signed attestation is generated instead.
    func testFallbackAfterFailedBackendAttestationUsesResolvedKeystoreNotDefault() async throws {
        let defaultKeystore = StubKeystoreManager(label: "softkey")
        let fidoKeystore = StubKeystoreManager(label: "fido2")

        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fidoKeystore]

        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: defaultKeystore)
        let w = wallet!
        // A backend session IS present, but its response is malformed (no
        // "key_attestation" field), so `requestKeyAttestation` throws and
        // `requestBackendKeyAttestation` returns a nil result - exercising
        // the self-signed fallback path in `generateProofs`.
        w.apiClient = BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, _, _, _ in
            try! JSONSerialization.data(withJSONObject: [String: Any]())
        })
        w.activeOffer = offer(issuer: "https://issuer.example.com", configId: "org.iso.18013.5.1.mDL")
        w.activeMddlSchema = MddlSchema(
            format: "mso_mdoc",
            doctype: "org.iso.18013.5.1.mDL",
            requiredKeyStorage: "iso_18045_high"
        )

        let proofs = try await w.generateProofs(
            audience: "https://issuer.example.com",
            nonce: "n",
            count: 1,
            proofTypesSupported: nil,
            proofTypeHint: "attestation"
        )

        XCTAssertEqual(proofs.count, 1)
        XCTAssertEqual(
            proofs[0].attestation, "fido2-attestation",
            "self-signed fallback must run on the resolved fido2 keystore, not the default"
        )
        XCTAssertEqual(fidoKeystore.generateKeypairsCallCount, 1)
        XCTAssertEqual(fidoKeystore.generateKeyAttestationCallCount, 1)
        XCTAssertEqual(defaultKeystore.generateKeypairsCallCount, 0, "must never touch the default keystore once a plugin is resolved")
        XCTAssertEqual(defaultKeystore.generateKeyAttestationCallCount, 0, "the self-signed fallback must not silently use self.keystore")
    }

    // MARK: - `generateProofs`' `extractProofKeyId` recovery (jwt proof type)
    //
    // Regression coverage for the bug fixed in `SirosWallet.extractProofKeyId`
    // (see its doc comment at `SirosWallet.swift:2407-2423`): for the "jwt"
    // proof type, `activeAttestedKeyIds` must be populated from the proof
    // JWT's own `jwk.kid` header claim, since `KeystoreManager.generateProof`
    // doesn't return the key ID directly. Mirrors the equivalent, already-
    // merged Kotlin regression tests.

    /// Builds a fake `jwt`-proof-type proof-of-possession JWT with the given
    /// `kid` embedded in its `jwk` header claim - matching the real shape
    /// `extractProofKeyId` parses (header.payload.signature, header carrying
    /// `alg`/`typ`/`jwk`). The payload and signature segments are irrelevant
    /// to `extractProofKeyId` (it only ever looks at the header), so they're
    /// left as unparsed placeholders.
    private func fakeProofJwt(kid: String) -> String {
        let header: [String: Any] = [
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": [
                "kty": "EC",
                "crv": "P-256",
                "kid": kid,
                "x": "eA",
                "y": "eQ",
            ],
        ]
        let headerData = try! JSONSerialization.data(withJSONObject: header)
        let headerB64 = WebAuthnAuthClient.base64UrlEncode(headerData)
        let payloadB64 = WebAuthnAuthClient.base64UrlEncode(Data("{}".utf8))
        return "\(headerB64).\(payloadB64).sig"
    }

    func testGenerateProofsSingleJwtRecoversKeyIdFromJwkHeader() async throws {
        let keystore = StubKeystoreManager(label: "default")
        keystore.proofJwtOverrides = [fakeProofJwt(kid: "sw-0")]

        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: keystore)
        let w = wallet!

        let proofs = try await w.generateProofs(
            audience: "https://issuer.example.com",
            nonce: "n",
            count: 1,
            proofTypesSupported: nil,
            proofTypeHint: "jwt"
        )

        XCTAssertEqual(proofs.count, 1)
        XCTAssertEqual(proofs[0].attestedKeyIds, ["sw-0"])
    }

    func testGenerateProofsBatchOfThreeJwtsEachRecoverOwnKeyIdInOrder() async throws {
        let keystore = StubKeystoreManager(label: "default")
        keystore.proofJwtOverrides = [
            fakeProofJwt(kid: "sw-0"),
            fakeProofJwt(kid: "sw-1"),
            fakeProofJwt(kid: "sw-2"),
        ]

        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: keystore)
        let w = wallet!

        let proofs = try await w.generateProofs(
            audience: "https://issuer.example.com",
            nonce: "n",
            count: 3,
            proofTypesSupported: nil,
            proofTypeHint: "jwt"
        )

        XCTAssertEqual(proofs.count, 3)
        // Each proof carries its OWN single-element attestedKeyIds list, in
        // call order - the concatenation into the batch-wide
        // `activeAttestedKeyIds` happens in the private
        // handleWmpSignRequest/handleSignRequest call sites, not reachable
        // from here, so asserting the per-proof lists is what actually
        // proves the fix.
        XCTAssertEqual(proofs[0].attestedKeyIds, ["sw-0"])
        XCTAssertEqual(proofs[1].attestedKeyIds, ["sw-1"])
        XCTAssertEqual(proofs[2].attestedKeyIds, ["sw-2"])
    }

    /// Regression (review finding): a HAIP proof's embedded `jwk` header, as
    /// actually built by `JweKeystore`/`WscdKeystoreAdapter`, carries only
    /// `kty`/`crv`/`x`/`y` - no `kid` member of its own, unlike every fixture
    /// above. `extractProofKeyId` must fall back to the RFC 7638 thumbprint
    /// of that embedded key in that case, not stay nil - the same value
    /// `KeypairIdentity.matches` already accepts when looking up a
    /// HAIP-bound credential's key, so `activeAttestedKeyIds` only works for
    /// HAIP proofs if this recovers it too.
    func testGenerateProofsRecoversKeyIdFromThumbprintWhenJwkHasNoKid() async throws {
        let x = "eA", y = "eQ"
        let header: [String: Any] = [
            "typ": "openid4vci-proof+jwt",
            "alg": "ES256",
            "jwk": ["kty": "EC", "crv": "P-256", "x": x, "y": y],
        ]
        let headerB64 = WebAuthnAuthClient.base64UrlEncode(try! JSONSerialization.data(withJSONObject: header))
        let payloadB64 = WebAuthnAuthClient.base64UrlEncode(Data("{}".utf8))
        let keystore = StubKeystoreManager(label: "default")
        keystore.proofJwtOverrides = ["\(headerB64).\(payloadB64).sig"]

        let config = WalletConfig(backendUrl: "https://example.invalid")
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider(), keystore: keystore)
        let w = wallet!

        let proofs = try await w.generateProofs(
            audience: "https://issuer.example.com",
            nonce: "n",
            count: 1,
            proofTypesSupported: nil,
            proofTypeHint: "jwt"
        )

        let canonical = "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"\(x)\",\"y\":\"\(y)\"}"
        let expectedThumbprint = Data(SHA256.hash(data: Data(canonical.utf8))).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        XCTAssertEqual(proofs.count, 1)
        XCTAssertEqual(proofs[0].attestedKeyIds, [expectedThumbprint])
    }
}
