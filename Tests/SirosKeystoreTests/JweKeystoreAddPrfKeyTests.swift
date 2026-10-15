// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)

/// `JweKeystore.addPrfKey` / `removePrfKey`: a second passkey gets its own key
/// to the container's one main key, sharing the account's HKDF salt.
final class JweKeystoreAddPrfKeyTests: XCTestCase {

    private let prf1 = Data(0..<32)
    private let prf2 = Data((0..<32).map { UInt8($0 + 0x40) })
    private let hkdfSalt = Data((0..<32).map { UInt8($0 + 0x10) })
    private let hkdfInfo = Data("SIROS Wallet PRF".utf8)
    private let cred1 = Data("cred-1".utf8)
    private let cred2 = Data("cred-2".utf8)

    private func firstContainer() async throws -> (JweKeystore, Data, String) {
        let keystore = JweKeystore()
        try await keystore.unlock(
            prfOutput: prf1, encryptedContainer: Data(), hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo, prfSalt: Data(repeating: 7, count: 32)
        )
        keystore.setCredentialId(cred1)
        let keyId = try await keystore.generateKey()
        return (keystore, try await keystore.exportEncryptedContainer(), keyId)
    }


    private let hkdfSalt2 = Data((0..<32).map { UInt8($0 + 0x70) })

    private func prepare(_ keystore: JweKeystore, cred: Data? = nil) async throws -> PreparedPrfKey {
        try await keystore.preparePrfKey(
            credentialId: cred ?? cred2, prfOutput: prf2, prfSalt: Data(repeating: 9, count: 32),
            hkdfSalt: hkdfSalt2, hkdfInfo: hkdfInfo
        )
    }

    func testTheNewPasskeyOpensTheSameContainerAndTheOldOneStillDoes() async throws {
        let (keystore, _, keyId) = try await firstContainer()
        let prepared = try await prepare(keystore)
        try await keystore.commitPrfKey(prepared)
        let container = try await keystore.exportEncryptedContainer()

        let parsed = try EncryptedContainer.parse(container)
        XCTAssertEqual(parsed.prfKeys.map(\.credentialId), [cred1, cred2])
        XCTAssertEqual(parsed.prfKeys[1].prfSalt, Data(repeating: 9, count: 32))
        XCTAssertEqual(parsed.prfKeys[1].hkdfSalt, hkdfSalt2)

        // Each passkey opens it with its own PRF output and its own entry's salt.
        for (prf, salt) in [(prf2, hkdfSalt2), (prf1, hkdfSalt)] {
            let reopened = JweKeystore()
            try await reopened.unlock(prfOutput: prf, encryptedContainer: container, hkdfSalt: salt, hkdfInfo: hkdfInfo)
            XCTAssertEqual(reopened.listKeys().map(\.keyId), [keyId], "the same wallet data, not a fresh container")
        }
    }

    func testThePreparedContainerOpensWithTheNewPasskeyBeforeAnythingIsCommitted() async throws {
        let (keystore, _, keyId) = try await firstContainer()
        let before = try await keystore.exportEncryptedContainer()
        let prepared = try await prepare(keystore)

        let reopened = JweKeystore()
        try await reopened.unlock(prfOutput: prf2, encryptedContainer: prepared.container, hkdfSalt: hkdfSalt2, hkdfInfo: hkdfInfo)
        XCTAssertEqual(reopened.listKeys().map(\.keyId), [keyId])

        // Not committed: the keystore's own container is as it was, so a
        // refused enrolment leaves nothing behind.
        let after = try await keystore.exportEncryptedContainer()
        XCTAssertEqual(try EncryptedContainer.parse(after).prfKeys.map(\.credentialId), [cred1])
        XCTAssertEqual(try EncryptedContainer.parse(before).prfKeys.map(\.credentialId), [cred1])
    }

    func testAnUncommittedKeyIsLostOnTheNextExportAndACommittedOneIsKept() async throws {
        let (keystore, _, _) = try await firstContainer()
        _ = try await prepare(keystore)
        var parsed = try EncryptedContainer.parse(try await keystore.exportEncryptedContainer())
        XCTAssertEqual(parsed.prfKeys.count, 1)

        try await keystore.commitPrfKey(try await prepare(keystore))
        // Later exports (any credential change syncs the container) keep it.
        _ = try await keystore.generateKey()
        parsed = try EncryptedContainer.parse(try await keystore.exportEncryptedContainer())
        XCTAssertEqual(parsed.prfKeys.map(\.credentialId), [cred1, cred2])
    }

    func testAnUnrelatedPrfOutputOpensNothing() async throws {
        let (keystore, _, _) = try await firstContainer()
        let prepared = try await prepare(keystore)
        let reopened = JweKeystore()
        do {
            try await reopened.unlock(
                prfOutput: Data(repeating: 0xEE, count: 32), encryptedContainer: prepared.container,
                hkdfSalt: hkdfSalt2, hkdfInfo: hkdfInfo
            )
            XCTFail("a PRF output no entry was wrapped for must not unlock")
        } catch {}
    }

    func testRefusesADuplicateCredentialAndALockedKeystore() async throws {
        let (keystore, _, _) = try await firstContainer()
        do {
            _ = try await prepare(keystore, cred: cred1)
            XCTFail("duplicate credential")
        } catch KeystoreError.invalidParameter {}

        keystore.lock()
        do {
            _ = try await prepare(keystore)
            XCTFail("locked")
        } catch KeystoreError.locked {}
    }
}

#endif
