// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosKeystore

#if canImport(CryptoKit)

private final class KeyedSigner: Signer, @unchecked Sendable {
    struct Boom: Error, LocalizedError { var errorDescription: String? { "boom" } }
    var keys: [SignerKeyInfo]
    var failing: Set<String> = []
    private(set) var deleted: [String] = []
    init(keys: [SignerKeyInfo]) { self.keys = keys }

    func generateKey(algorithm: String) async throws -> String { "k" }
    func sign(keyId: String, data: Data) async throws -> Data { Data(count: 64) }
    func listKeys() async throws -> [SignerKeyInfo] { keys }
    func deleteKey(keyId: String) async throws {
        if failing.contains(keyId) { throw Boom() }
        deleted.append(keyId)
    }
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func exportPublicKey(keyId: String) async throws -> Data { Data() }
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        SignerSecurityProperties(keyStorage: ["software"], userAuthentication: [])
    }
}

/// An account wipe must erase the signing keys the adapter's `Signer` holds,
/// which `clearCredentials()` and `lock()` never touched.
final class WscdKeystoreAdapterEraseKeyMaterialTests: XCTestCase {
    func testEverySignerKeyIsDeletedExceptThoseOnAnExternalAuthenticator() async throws {
        let signer = KeyedSigner(keys: [
            SignerKeyInfo(keyId: "soft-1", algorithm: "ES256", pluginId: "softkey"),
            SignerKeyInfo(keyId: "hsm-1", algorithm: "ES256", pluginId: "r2ps"),
            SignerKeyInfo(keyId: "token-1", algorithm: "ES256", pluginId: "fido2"),
            SignerKeyInfo(keyId: "bare-1", algorithm: "ES256"),
        ])
        try await WscdKeystoreAdapter(signer: signer).eraseKeyMaterial()
        XCTAssertEqual(signer.deleted, ["soft-1", "hsm-1", "bare-1"])
    }

    func testAFailingKeyIsReportedAndTheRestAreStillDeleted() async {
        let signer = KeyedSigner(keys: [
            SignerKeyInfo(keyId: "a", algorithm: "ES256", pluginId: "softkey"),
            SignerKeyInfo(keyId: "b", algorithm: "ES256", pluginId: "softkey"),
        ])
        signer.failing = ["a"]
        do {
            try await WscdKeystoreAdapter(signer: signer).eraseKeyMaterial()
            XCTFail("a key that could not be erased must be reported")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("a: boom"), error.localizedDescription)
        }
        XCTAssertEqual(signer.deleted, ["b"])
    }
}
#endif
