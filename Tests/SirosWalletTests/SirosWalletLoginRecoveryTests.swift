// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosWallet

// `SirosWallet.init` requires a real `JweKeystore`, only available where
// CryptoKit is (Apple platforms / CI macOS runner) - matching this test
// target's existing `#if canImport(CryptoKit)` convention.
#if canImport(CryptoKit)

/// Unit tests for the two pure, directly-testable halves of the PRF-recovery
/// fix: `SirosWallet.recoverPrfKeyInfo` (finds the real salt in `privateData`)
/// and `SirosWallet.healAccountCache` (writes a successful recovery back to
/// the local account cache). Together with
/// `SirosWalletPasskeyAssertionTests.testCacheMissReturnsNilPrfWithoutASecondCeremony`,
/// these cover every piece of the recovery path that doesn't require a real
/// network round-trip.
///
/// `login()`'s full cache-miss branch (the two pieces above wired together
/// with a completed server-side login) is NOT driven end to end here, for
/// the same reason `SirosWalletPasskeyAssertionTests`'s doc comment gives for
/// `login()` itself: `setupApiClientWithTokens` always builds its
/// `BackendApiClient` over the real, non-injectable `defaultHttpFn`, so
/// `fetchPrivateData()` cannot be driven by a test double without a live
/// network round-trip. The Kotlin SDK's own PR for this fix shipped without a
/// recovery-path test for the identical reason (no fixture existed there for
/// a full successful login ceremony); Swift's test suite is in a better
/// position for the two pieces that don't depend on that seam, which is what
/// these tests cover.
final class SirosWalletLoginRecoveryTests: XCTestCase {

    private func makeWallet(authProvider: AuthProvider = NeverCalledAuthProvider()) -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid", tenantId: "default")
        let wallet = SirosWallet(
            config: config, authProvider: authProvider, sessionStore: InMemorySessionStore(),
            accountRegistry: .inMemory()
        )
        XCTAssertNotNil(wallet, "wallet should initialise with default keystore on CryptoKit platforms")
        return wallet!
    }

    /// A real, validly-encrypted container (built the same way a live
    /// first-time registration would, via `JweKeystore.unlock`'s
    /// first-time-setup branch) carrying `credentialId`'s real
    /// `prfSalt`/`hkdfSalt`/`hkdfInfo` - exactly what the backend's
    /// `privateData` holds for an account with one registered passkey.
    private func makePrivateData(
        credentialId: Data, prfSalt: Data, hkdfSalt: Data, hkdfInfo: Data
    ) async throws -> Data {
        let keystore = JweKeystore()
        try await keystore.unlock(
            prfOutput: Data(repeating: 0xAB, count: 32),
            encryptedContainer: Data(),
            hkdfSalt: hkdfSalt,
            hkdfInfo: hkdfInfo,
            prfSalt: prfSalt
        )
        keystore.setCredentialId(credentialId)
        return try await keystore.exportEncryptedContainer()
    }

    // MARK: - recoverPrfKeyInfo

    func testRecoverPrfKeyInfoFindsTheMatchingEntryByCredentialId() async throws {
        let credentialId = Data("cred-recover-me".utf8)
        let prfSalt = Data(repeating: 0x11, count: 32)
        let hkdfSalt = Data(repeating: 0x22, count: 32)
        let hkdfInfo = Data("info".utf8)
        let privateData = try await makePrivateData(
            credentialId: credentialId, prfSalt: prfSalt, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo
        )
        let wallet = makeWallet()

        let found = try wallet.recoverPrfKeyInfo(credentialId: credentialId, from: privateData)

        XCTAssertEqual(found.credentialId, credentialId)
        XCTAssertEqual(found.prfSalt, prfSalt, "the real registration-time salt, not a guess")
        XCTAssertEqual(found.hkdfSalt, hkdfSalt)
        XCTAssertEqual(found.hkdfInfo, hkdfInfo)
    }

    func testRecoverPrfKeyInfoThrowsWhenNoEntryMatchesTheCredential() async throws {
        let registeredCredentialId = Data("cred-registered".utf8)
        let privateData = try await makePrivateData(
            credentialId: registeredCredentialId,
            prfSalt: Data(repeating: 0x11, count: 32),
            hkdfSalt: Data(repeating: 0x22, count: 32),
            hkdfInfo: Data("info".utf8)
        )
        let wallet = makeWallet()
        let unrelatedCredentialId = Data("cred-not-in-container".utf8)

        XCTAssertThrowsError(
            try wallet.recoverPrfKeyInfo(credentialId: unrelatedCredentialId, from: privateData)
        ) { error in
            guard case let SirosError.wallet(message, _) = error else {
                XCTFail("expected SirosError.wallet, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("cannot decrypt wallet data"))
        }
    }

    func testRecoverPrfKeyInfoThrowsOnUnparsableContainer() {
        let wallet = makeWallet()

        XCTAssertThrowsError(
            try wallet.recoverPrfKeyInfo(credentialId: Data("any".utf8), from: Data("not json".utf8))
        ) { error in
            guard case SirosError.wallet = error else {
                XCTFail("expected SirosError.wallet, got \(error)")
                return
            }
        }
    }

    // MARK: - healAccountCache

    func testHealAccountCacheCreatesANewAccountWhenNoneExisted() {
        let wallet = makeWallet()
        let credentialId = Data("cred-1".utf8)
        let prfSalt = Data(repeating: 0x33, count: 32)
        let hkdfSalt = Data(repeating: 0x44, count: 32)
        let hkdfInfo = Data("info".utf8)

        wallet.healAccountCache(
            accountId: "default:user-1", userId: "user-1", displayName: "Alice",
            credentialId: credentialId, prfSalt: prfSalt, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo
        )

        guard let account = wallet.accountRegistry.findAccount(accountId: "default:user-1") else {
            return XCTFail("expected a newly-created cached account")
        }
        XCTAssertEqual(account.displayName, "Alice")
        XCTAssertEqual(account.passkeys.count, 1)
        XCTAssertEqual(account.passkeys.first?.credentialId, SirosWallet.b64UrlEncode(credentialId))
        XCTAssertEqual(account.passkeys.first?.prfSalt, SirosWallet.b64Encode(prfSalt))
        XCTAssertEqual(account.hkdfSalt, SirosWallet.b64Encode(hkdfSalt))
        XCTAssertEqual(account.hkdfInfo, SirosWallet.b64Encode(hkdfInfo))
    }

    /// The point of healing: an account that existed (perhaps with other
    /// passkeys, or with a stale/absent entry for THIS credential) gets this
    /// credential's real salt added, without losing its other passkeys.
    func testHealAccountCacheAddsToAnExistingAccountWithoutLosingOtherPasskeys() {
        let wallet = makeWallet()
        let otherCredentialId = Data("cred-other".utf8)
        let recoveredCredentialId = Data("cred-recovered".utf8)
        wallet.accountRegistry.upsertAccount(CachedAccount(
            userId: "user-1", tenantId: "default", displayName: "Alice", backendUrl: "https://example.invalid",
            passkeys: [CachedPasskey(
                credentialId: SirosWallet.b64UrlEncode(otherCredentialId),
                prfSalt: SirosWallet.b64Encode(Data(repeating: 0x01, count: 32))
            )],
            hkdfSalt: "stale-salt", hkdfInfo: "stale-info"
        ))
        let recoveredSalt = Data(repeating: 0x55, count: 32)

        wallet.healAccountCache(
            accountId: "default:user-1", userId: "user-1", displayName: "Alice",
            credentialId: recoveredCredentialId, prfSalt: recoveredSalt,
            hkdfSalt: Data(repeating: 0x66, count: 32), hkdfInfo: Data("new-info".utf8)
        )

        guard let account = wallet.accountRegistry.findAccount(accountId: "default:user-1") else {
            return XCTFail("expected the existing account to still be present")
        }
        XCTAssertEqual(account.passkeys.count, 2, "the pre-existing passkey must survive healing")
        XCTAssertTrue(account.passkeys.contains { $0.credentialId == SirosWallet.b64UrlEncode(otherCredentialId) })
        let healed = account.passkeys.first { $0.credentialId == SirosWallet.b64UrlEncode(recoveredCredentialId) }
        XCTAssertEqual(healed?.prfSalt, SirosWallet.b64Encode(recoveredSalt))
    }

    /// Healing the SAME credential twice (e.g. a second recovery after
    /// another cache wipe) must replace, not duplicate, its entry.
    func testHealAccountCacheReplacesAnExistingEntryForTheSameCredential() {
        let wallet = makeWallet()
        let credentialId = Data("cred-1".utf8)
        wallet.accountRegistry.upsertAccount(CachedAccount(
            userId: "user-1", tenantId: "default", displayName: "Alice", backendUrl: "https://example.invalid",
            passkeys: [CachedPasskey(
                credentialId: SirosWallet.b64UrlEncode(credentialId),
                prfSalt: SirosWallet.b64Encode(Data(repeating: 0x01, count: 32))
            )]
        ))
        let newSalt = Data(repeating: 0x77, count: 32)

        wallet.healAccountCache(
            accountId: "default:user-1", userId: "user-1", displayName: "Alice",
            credentialId: credentialId, prfSalt: newSalt,
            hkdfSalt: Data(repeating: 0x88, count: 32), hkdfInfo: Data("info".utf8)
        )

        let account = wallet.accountRegistry.findAccount(accountId: "default:user-1")
        XCTAssertEqual(account?.passkeys.count, 1, "must replace, not duplicate")
        XCTAssertEqual(account?.passkeys.first?.prfSalt, SirosWallet.b64Encode(newSalt))
    }
}

private final class NeverCalledAuthProvider: AuthProvider, @unchecked Sendable {
    struct Unexpected: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw Unexpected() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw Unexpected() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw Unexpected() }
}

#endif
