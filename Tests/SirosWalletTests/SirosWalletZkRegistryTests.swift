// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosWallet

/// Wiring tests for `SirosWallet.init`'s `zkProofSystemRegistry` assembly -
/// specifically the `BbsProofSystem` registration gap this closes (see
/// `WalletConfig.bbsCredentialTypes`'s doc comment): BBS must be registered
/// exactly when the deployment declares BBS credential types AND the
/// keystore in use can hold extension entries, never unconditionally and
/// never silently dropped when both are available.
///
/// Longfellow/Vega/BBS are all iOS-only (each one's native XCFramework ships
/// iOS slices only - see `Package.swift`), so the registry is only ever
/// non-empty when this test target itself is built for iOS; on every other
/// platform `SirosWallet.zkProofSystemRegistry` is unconditionally empty by
/// construction (see `SirosWallet.init`'s `#else` branch), which is already
/// covered by this simply never asserting non-emptiness there.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// Full `KeystoreManager` conformance, copied verbatim from
/// `SirosWalletWscdSelectionTests.StubKeystoreManager` (proven to satisfy
/// the protocol - see that file) rather than re-derived by hand, since the
/// protocol has grown enough surface (`signMdocPresentation`,
/// `signMdocPresentationForDCAPI`, etc., each with a default extension
/// implementation this stub relies on) that hand-listing requirements here
/// risks silently drifting from what the protocol actually needs.
private class BaseStubKeystoreManager: KeystoreManager, @unchecked Sendable {
    var isUnlocked: Bool { true }
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { "stub-key" }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String {
        try await generateProof(audience: audience, nonce: nonce, freshKey: freshKey, holderBinding: nil)
    }
    func generateProof(
        audience: String, nonce: String, freshKey: Bool, holderBinding: HolderBinding?
    ) async throws -> String { "stub-proof" }
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
        (0..<count).map { KeypairInfo(keyId: "stub-key-\($0)", publicKeyJWK: ["kty": "EC"]) }
    }
    func generateKeyAttestation(nonce: String, count: Int) async throws -> String { "stub-attestation" }
}

/// A `KeystoreManager` that also answers `ExtensionStore` - the shape
/// `WscdKeystoreAdapter`/`JweKeystore` both have in production, needed here
/// because `SirosWallet.init` only constructs a `BbsHolderStateVault` when
/// `keystore as? ExtensionStore` succeeds.
private final class StubExtensionKeystore: BaseStubKeystoreManager, ExtensionStore, @unchecked Sendable {
    private var entries: [String: [String: String]] = [:]

    func extensionEntries(namespace: String) async -> [String: String] {
        entries[namespace] ?? [:]
    }
    func setExtensionEntry(namespace: String, key: String, value: String) async throws {
        entries[namespace, default: [:]][key] = value
    }
    func removeExtensionEntry(namespace: String, key: String) async throws {
        entries[namespace]?.removeValue(forKey: key)
    }
}

/// A `KeystoreManager` with no `ExtensionStore` conformance at all - the
/// shape a host-supplied, non-SIROS keystore could plausibly have.
private final class StubPlainKeystore: BaseStubKeystoreManager, @unchecked Sendable {}

final class SirosWalletZkRegistryTests: XCTestCase {

    private func makeConfig(bbsCredentialTypes: Set<String>, credentialStore: CredentialStore) -> WalletConfig {
        WalletConfig(backendUrl: "https://wallet.example", credentialStore: credentialStore, bbsCredentialTypes: bbsCredentialTypes)
    }

    #if os(iOS)
    func testBbsIsRegisteredWhenConfiguredWithAnExtensionCapableKeystore() throws {
        let wallet = try XCTUnwrap(
            SirosWallet(
                config: makeConfig(bbsCredentialTypes: ["urn:eu.europa.ec.eudi:bbs_test:1"], credentialStore: InMemoryCredentialStore()),
                authProvider: StubAuthProvider(),
                keystore: StubExtensionKeystore()
            )
        )
        XCTAssertTrue(wallet.zkProofSystemRegistry.registeredSystemIds.contains(BbsProofSystem.systemIdentifier))
    }

    func testBbsIsNotRegisteredWhenNoCredentialTypesAreConfigured() throws {
        let wallet = try XCTUnwrap(
            SirosWallet(
                config: makeConfig(bbsCredentialTypes: [], credentialStore: InMemoryCredentialStore()),
                authProvider: StubAuthProvider(),
                keystore: StubExtensionKeystore()
            )
        )
        XCTAssertFalse(wallet.zkProofSystemRegistry.registeredSystemIds.contains(BbsProofSystem.systemIdentifier))
    }

    func testBbsIsNotRegisteredWhenTheKeystoreCannotHoldExtensionEntries() throws {
        let wallet = try XCTUnwrap(
            SirosWallet(
                config: makeConfig(bbsCredentialTypes: ["urn:eu.europa.ec.eudi:bbs_test:1"], credentialStore: InMemoryCredentialStore()),
                authProvider: StubAuthProvider(),
                keystore: StubPlainKeystore()
            )
        )
        XCTAssertFalse(wallet.zkProofSystemRegistry.registeredSystemIds.contains(BbsProofSystem.systemIdentifier))
    }

    func testLongfellowAndVegaAreAlwaysRegisteredAlongsideBbs() throws {
        let wallet = try XCTUnwrap(
            SirosWallet(
                config: makeConfig(bbsCredentialTypes: ["urn:eu.europa.ec.eudi:bbs_test:1"], credentialStore: InMemoryCredentialStore()),
                authProvider: StubAuthProvider(),
                keystore: StubExtensionKeystore()
            )
        )
        let ids = Set(wallet.zkProofSystemRegistry.registeredSystemIds)
        XCTAssertTrue(ids.contains(vegaZkSystemId))
        XCTAssertEqual(ids.count, 3, "expected Longfellow + Vega + BBS, got \(ids)")
    }

    /// Exercises the full join `SirosWallet.init` wires: the proof system
    /// resolves holder state by looking up, among every stored credential,
    /// the one whose raw JWP text matches - mirroring Kotlin's
    /// `bbsHolderStateStore.stateFor`.
    func testBbsHolderStateResolvesViaTheCredentialStoreJoin() async throws {
        let credentialStore = InMemoryCredentialStore()
        let jwp = "stub.issued.jwp"
        await credentialStore.save(
            StoredCredential(id: 42, format: "jwp", raw: jwp, batchId: 1, instanceId: 0)
        )
        let keystore = StubExtensionKeystore()
        let vault = BbsHolderStateVault(keystore: keystore)
        try await vault.put(
            credentialId: "42",
            state: BbsHolderState(issuerPublicKey: [1], secretProverBlind: [2], committedMessages: [[3]], keybindPublicKeys: [])
        )

        let credentialTypeId = "urn:eu.europa.ec.eudi:bbs_test:1"
        let wallet = try XCTUnwrap(
            SirosWallet(
                config: makeConfig(bbsCredentialTypes: [credentialTypeId], credentialStore: credentialStore),
                authProvider: StubAuthProvider(),
                keystore: keystore
            )
        )
        XCTAssertTrue(wallet.zkProofSystemRegistry.registeredSystemIds.contains(BbsProofSystem.systemIdentifier))

        // Exercises the actual join `SirosWallet.init` wires in, not just
        // that something got registered (Copilot review, PR #194: an
        // earlier version of this test only repeated the assertion above).
        // Resolve the wallet-registered system exactly as a real
        // presentation would, then call `generateProof` on it - `jwp` is
        // not a real, parseable JWP, so this cannot succeed, but
        // `BbsProofSystem.generateProof` looks up holder state BEFORE
        // attempting to parse the JWP (`guard let state = try await
        // holderState(jwp) else { throw .missingHolderState }` runs ahead
        // of `jwpInspect`) - so whether it fails with `.missingHolderState`
        // or something else entirely is exactly the signal this test needs:
        // `.missingHolderState` would mean the join `SirosWallet.init`
        // assembled (credentialStore lookup by raw JWP -> vault lookup by
        // the matched credential's id) failed to find the entry this test
        // put there, which is the one thing registration alone cannot show.
        guard let (system, spec) = wallet.zkProofSystemRegistry.resolve(
            credentialType: CredentialTypeRef(format: .jwp, typeId: credentialTypeId),
            requestedSpecs: [ZkSystemSpec(id: BbsProofSystem.systemIdentifier, system: BbsProofSystem.systemIdentifier)],
            numAttributes: 0
        ) else {
            return XCTFail("expected the wallet-registered BbsProofSystem to resolve '\(credentialTypeId)'")
        }
        do {
            _ = try await system.generateProof(
                spec: spec,
                document: .jwp(jwp),
                sessionTranscript: [],
                requestedClaims: [],
                verifierIdentity: nil,
                signer: { _, _ in [] },
                priorState: nil
            )
            XCTFail("expected generateProof to fail past holder-state lookup (the JWP fixture here is not real)")
        } catch BbsProofError.missingHolderState {
            XCTFail("the wallet-wired credentialStore/vault join must have resolved the stored holder state - got .missingHolderState")
        } catch {
            // Expected: the fake JWP string fails real parsing further
            // along (jwpInspect) - the join itself already succeeded by the
            // time that happens, which is what this test actually checks.
        }
    }
    #else
    func testRegistryIsEmptyOnNonIOSPlatforms() throws {
        let wallet = try XCTUnwrap(
            SirosWallet(
                config: makeConfig(bbsCredentialTypes: ["urn:eu.europa.ec.eudi:bbs_test:1"], credentialStore: InMemoryCredentialStore()),
                authProvider: StubAuthProvider(),
                keystore: StubExtensionKeystore()
            )
        )
        XCTAssertTrue(wallet.zkProofSystemRegistry.registeredSystemIds.isEmpty)
    }
    #endif
}
