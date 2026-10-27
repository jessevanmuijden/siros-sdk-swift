// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosKeystore

#if canImport(CryptoKit)

private final class NoKeysSigner: Signer, @unchecked Sendable {
    func generateKey(algorithm: String) async throws -> String { "k" }
    func sign(keyId: String, data: Data) async throws -> Data { Data(count: 64) }
    func listKeys() async throws -> [SignerKeyInfo] { [] }
    func deleteKey(keyId: String) async throws {}
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func exportPublicKey(keyId: String) async throws -> Data { Data() }
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        SignerSecurityProperties(keyStorage: ["software"], userAuthentication: [])
    }
}

/// `addPasskey` review fixes that live in the keystores.
final class PrfEnrolmentOwnershipTests: XCTestCase {
    private let prf = Data(repeating: 0x42, count: 32)
    private let hkdfSalt = Data(repeating: 0x11, count: 32)
    private let hkdfInfo = Data("SIROS Wallet PRF".utf8)

    /// The adapter used to inherit the no-op default, so a WSCD-backed wallet's
    /// original PRF entry stayed anonymous and could not be found by credential id.
    func testTheAdapterTagsTheOriginalPasskeysEntry() async throws {
        let adapter = WscdKeystoreAdapter(signer: NoKeysSigner())
        try await adapter.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        adapter.setCredentialId(Data("original".utf8))

        let container = try EncryptedContainer.parse(try await adapter.exportEncryptedContainer())
        XCTAssertEqual(container.prfKeys.first?.credentialId, Data("original".utf8))
    }

    /// A key prepared in one unlocked session must not be committed into
    /// another: the keystore is a single reused instance, and after a lock and
    /// an unlock for another account it holds different contents.
    func testAPreparedKeyCannotBeCommittedAfterTheKeystoreWasLockedAndUnlockedAgain() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let prepared = try await keystore.preparePrfKey(
            credentialId: Data("second".utf8), prfOutput: Data(repeating: 0x43, count: 32),
            prfSalt: Data(repeating: 0x01, count: 32), hkdfSalt: Data(repeating: 0x22, count: 32), hkdfInfo: hkdfInfo
        )

        keystore.lock()
        try await keystore.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)

        do {
            try await keystore.commitPrfKey(prepared)
            XCTFail("a key prepared in an earlier unlocked session must be refused")
        } catch KeystoreError.invalidParameter {}
        let container = try EncryptedContainer.parse(try await keystore.exportEncryptedContainer())
        XCTAssertFalse(container.prfKeys.contains { $0.credentialId == Data("second".utf8) })
    }

    func testAPreparedKeyCommitsInTheSessionItWasPreparedIn() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        let prepared = try await keystore.preparePrfKey(
            credentialId: Data("second".utf8), prfOutput: Data(repeating: 0x43, count: 32),
            prfSalt: Data(repeating: 0x01, count: 32), hkdfSalt: Data(repeating: 0x22, count: 32), hkdfInfo: hkdfInfo
        )
        try await keystore.commitPrfKey(prepared)
        let container = try EncryptedContainer.parse(try await keystore.exportEncryptedContainer())
        XCTAssertTrue(container.prfKeys.contains { $0.credentialId == Data("second".utf8) })
    }
}
#endif
