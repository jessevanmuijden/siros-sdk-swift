// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)

/// What "onboarded" resolves to for a WSCD plugin: its key metadata is recorded in
/// the privatedata-synced `S.wscdCredentials`, or the live signer already holds a
/// key for it. Anything else - including a failure to ask - is NOT onboarded.
final class WscdOnboardingTests: XCTestCase {

    private final class KeyListSigner: Signer, @unchecked Sendable {
        var keys: Result<[SignerKeyInfo], Error> = .success([])
        func generateKey(algorithm: String) async throws -> String { "k" }
        func sign(keyId: String, data: Data) async throws -> Data { Data() }
        func listKeys() async throws -> [SignerKeyInfo] { try keys.get() }
        func deleteKey(keyId: String) async throws {}
        func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
        func exportPublicKey(keyId: String) async throws -> Data { Data() }
        func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
        func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
            SignerSecurityProperties(keyStorage: ["hardware"], userAuthentication: ["pin"])
        }
    }

    private struct Boom: Error {}

    func testFido2NotOnboardedWithNoStateAndNoKeys() async {
        let adapter = WscdKeystoreAdapter(signer: KeyListSigner())
        let onboarded = await adapter.isWscdPluginOnboarded(pluginId: "fido2")
        XCTAssertFalse(onboarded)
    }

    func testFido2OnboardedWhenCredentialsStateRecorded() async {
        let adapter = WscdKeystoreAdapter(signer: KeyListSigner())
        await adapter.setWscdCredentialsState(pluginId: "fido2", state: "c3RhdGU")
        let onboarded = await adapter.isWscdPluginOnboarded(pluginId: "fido2")
        XCTAssertTrue(onboarded)
    }

    func testEmptyCredentialsStateIsNotOnboarded() async {
        let adapter = WscdKeystoreAdapter(signer: KeyListSigner())
        await adapter.setWscdCredentialsState(pluginId: "fido2", state: "")
        let onboarded = await adapter.isWscdPluginOnboarded(pluginId: "fido2")
        XCTAssertFalse(onboarded)
    }

    func testFido2OnboardedWhenSignerHoldsAKeyForIt() async {
        let signer = KeyListSigner()
        signer.keys = .success([SignerKeyInfo(keyId: "k1", algorithm: "ES256", pluginId: "fido2")])
        let adapter = WscdKeystoreAdapter(signer: signer)
        let onboarded = await adapter.isWscdPluginOnboarded(pluginId: "fido2")
        XCTAssertTrue(onboarded)
    }

    func testAnotherPluginsKeyDoesNotOnboardFido2() async {
        let signer = KeyListSigner()
        signer.keys = .success([SignerKeyInfo(keyId: "k1", algorithm: "ES256", pluginId: "softkey")])
        let adapter = WscdKeystoreAdapter(signer: signer)
        let onboarded = await adapter.isWscdPluginOnboarded(pluginId: "fido2")
        XCTAssertFalse(onboarded)
    }

    func testFailureToListKeysFailsClosed() async {
        let signer = KeyListSigner()
        signer.keys = .failure(Boom())
        let adapter = WscdKeystoreAdapter(signer: signer)
        let onboarded = await adapter.isWscdPluginOnboarded(pluginId: "fido2")
        XCTAssertFalse(onboarded)
    }

    func testSoftkeyNeedsNoOnboarding() async {
        let adapter = WscdKeystoreAdapter(signer: KeyListSigner())
        let onboarded = await adapter.isWscdPluginOnboarded(pluginId: "softkey")
        XCTAssertTrue(onboarded)
    }
}
#endif
