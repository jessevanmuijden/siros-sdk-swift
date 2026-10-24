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

    /// When set, `generateKey` announces itself and waits for `releaseGeneration()` before creating the key.
    private let lock = NSLock()
    private var parkGeneration = false
    private var entered = false
    private var releaseContinuation: CheckedContinuation<Void, Never>?
    private var released = false
    func parkNextGeneration() { lock.lock(); parkGeneration = true; lock.unlock() }
    var generationEntered: Bool { lock.lock(); defer { lock.unlock() }; return entered }
    func releaseGeneration() {
        lock.lock(); released = true; let c = releaseContinuation; releaseContinuation = nil; lock.unlock()
        c?.resume()
    }
    func generateKey(algorithm: String) async throws -> String {
        lock.lock(); let park = parkGeneration; if park { entered = true; parkGeneration = false }; lock.unlock()
        if park {
            await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
                lock.lock()
                if released { lock.unlock(); c.resume() } else { releaseContinuation = c; lock.unlock() }
            }
        }
        lock.lock(); keys.append(SignerKeyInfo(keyId: "created", algorithm: algorithm, pluginId: "softkey")); lock.unlock()
        return "created"
    }
    func sign(keyId: String, data: Data) async throws -> Data { Data(count: 64) }
    func listKeys() async throws -> [SignerKeyInfo] { keys }
    func deleteKey(keyId: String) async throws {
        if failing.contains(keyId) { throw Boom() }
        lock.lock(); deleted.append(keyId); keys.removeAll { $0.keyId == keyId }; lock.unlock()
    }
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func exportPublicKey(keyId: String) async throws -> Data { Data() }
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        SignerSecurityProperties(keyStorage: ["software"], userAuthentication: [])
    }
}

private final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    var value: Bool { lock.lock(); defer { lock.unlock() }; return flag }
    func set() { lock.lock(); flag = true; lock.unlock() }
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

    /// A key being created while the erase begins must be waited for and then
    /// erased with the rest; one requested after it began is refused. Without
    /// the gate the erase snapshots an empty list and the key survives.
    func testAKeyBeingCreatedWhileTheEraseBeginsIsErasedNotLeftBehind() async throws {
        let signer = KeyedSigner(keys: [])
        signer.parkNextGeneration()
        let adapter = WscdKeystoreAdapter(signer: signer)
        try await adapter.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())

        let creating = Task { try await adapter.generateKey(algorithm: "ES256") }
        while !signer.generationEntered { try await Task.sleep(nanoseconds: 5_000_000) }
        let erased = Flag()
        let erasing = Task { try await adapter.eraseKeyMaterial(); erased.set() }
        try await Task.sleep(nanoseconds: 100_000_000)   // the erase is now waiting for the admitted creation
        XCTAssertFalse(erased.value, "the erase must wait for the key being created")
        do {
            _ = try await adapter.generateKey(algorithm: "ES256")
            XCTFail("a key requested after the erase began must be refused")
        } catch KeystoreError.locked {}
        signer.releaseGeneration()

        _ = try await creating.value
        try await erasing.value
        let remaining = try await signer.listKeys()
        XCTAssertTrue(remaining.isEmpty, "the key created during the erase must not survive it: \(remaining)")
    }

    /// An unlock that races the erase must not admit key creation: the key would finish behind the erase's
    /// key-list snapshot and survive it. Only the wallet's new-session `reopenKeyOperations()` admits again.
    func testAnUnlockDuringTheEraseDoesNotAdmitKeyCreation() async throws {
        let signer = KeyedSigner(keys: [])
        signer.parkNextGeneration()
        let adapter = WscdKeystoreAdapter(signer: signer)
        try await adapter.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())
        let creating = Task { try await adapter.generateKey(algorithm: "ES256") }
        while !signer.generationEntered { try await Task.sleep(nanoseconds: 5_000_000) }
        let erasing = Task { try await adapter.eraseKeyMaterial() }
        try await Task.sleep(nanoseconds: 100_000_000)       // the erase is draining the admitted creation

        try await adapter.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())
        do {
            _ = try await adapter.generateKey(algorithm: "ES256")
            XCTFail("an unlock must not reopen key creation while the erase is under way")
        } catch KeystoreError.locked {}

        signer.releaseGeneration()
        _ = try await creating.value
        try await erasing.value
        let remaining = try await signer.listKeys()
        XCTAssertTrue(remaining.isEmpty, "\(remaining)")

        adapter.reopenKeyOperations()
        let again = try await adapter.generateKey(algorithm: "ES256")
        XCTAssertEqual(again, "created", "a new session admits key creation again")
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
