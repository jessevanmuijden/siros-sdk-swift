// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
@testable import SirosKeystore
@testable import SirosWallet

// `WscdKeystoreAdapter` (and the real onboarding check) only exist where CryptoKit does.
#if canImport(CryptoKit)

/// The WSCD onboarding gate (`WscdSelectionPolicy.resolve(..., isPluginOnboarded:)`, `wscdNotOnboarded`) applies to
/// ISSUANCE with a token that must already be onboarded. It must not block ENROLMENT of a fresh key: enrolment goes
/// straight to the plugin, where the new-PIN request (`requestNewPin`, setPIN) happens.
final class WscdEnrolmentGateTests: XCTestCase {

    private final class RecordingSigner: Signer, @unchecked Sendable {
        private let lock = NSLock()
        private(set) var generateKeyCalls = 0
        func generateKey(algorithm: String) async throws -> String {
            lock.lock(); generateKeyCalls += 1; lock.unlock()
            return "k"
        }
        func sign(keyId: String, data: Data) async throws -> Data { Data(count: 64) }
        func listKeys() async throws -> [SignerKeyInfo] { [] }
        func deleteKey(keyId: String) async throws {}
        func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
        func exportPublicKey(keyId: String) async throws -> Data { Data() }
        func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
        func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
            SignerSecurityProperties(keyStorage: ["hardware"], userAuthentication: ["pin"])
        }
    }

    private final class NoAuthProvider: AuthProvider, @unchecked Sendable {
        struct NotImplemented: Error {}
        func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
    }

    private func unlocked(_ signer: Signer) async throws -> WscdKeystoreAdapter {
        let adapter = WscdKeystoreAdapter(signer: signer)
        try await adapter.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())
        return adapter
    }

    func testEnrolmentOfAFreshKeyReachesThePluginWhileIssuanceBeforeEnrolmentIsRefused() async throws {
        let fidoSigner = RecordingSigner()
        let fido = try await unlocked(fidoSigner)
        let main = try await unlocked(RecordingSigner())
        var config = WalletConfig(backendUrl: "https://example.invalid")
        config.availableKeystores = ["fido2": fido]
        let wallet = SirosWallet(config: config, authProvider: NoAuthProvider(), keystore: main)!
        wallet.activeVctm = Vctm(vct: "urn:example:pid", requiredKeyStorage: "iso_18045_high")

        // Issuance with a token that is not onboarded yet: refused before any key is generated (no PIN prompt).
        do {
            _ = try await wallet.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
            XCTFail("expected WscdSelectionError.wscdNotOnboarded")
        } catch WscdSelectionError.wscdNotOnboarded(_, _, _, let notOnboarded) {
            XCTAssertEqual(notOnboarded, ["fido2"])
        }
        XCTAssertEqual(fidoSigner.generateKeyCalls, 0, "the issuance gate stops before the plugin")

        // Enrolment of the fresh key is NOT gated by onboarding: it reaches the plugin, where the new-PIN request happens.
        _ = try await fido.generateKey(algorithm: "ES256")
        XCTAssertEqual(fidoSigner.generateKeyCalls, 1, "enrolment must reach the plugin (requestNewPin / setPIN)")

        // The host records the enrolment (as it does after `exportFido2State`): issuance now passes the gate.
        await fido.setWscdCredentialsState(pluginId: "fido2", state: "c3RhdGU")
        let (_, keystore) = try await wallet.requestBackendKeyAttestation(audience: "https://issuer.example.com", nonce: "n", count: 1)
        XCTAssertTrue(keystore === fido, "the onboarded fido2 plugin is now the one issuance resolves to")
    }
}
#endif
