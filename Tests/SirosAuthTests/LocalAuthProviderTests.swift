// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosAuth

#if canImport(Security)
import Security
#endif

/// Verifies `LocalAuthProvider`'s biometric-ceremony hardening: unlike a bare
/// `SecKeyCreateRandomKey` key (which has no access-control gate at all, and
/// therefore signs unconditionally with zero device-authentication
/// guarantee), the signing key it generates must actually be protected by a
/// `kSecAttrAccessControl` object requiring user presence, and must not leave
/// orphaned real keychain entries behind after a rolled-back registration.
///
/// These assertions only run where `Security`/Keychain Services are
/// available (Apple platforms) — `LocalAuthProvider` throws
/// "not available on this platform" everywhere else (see the cross-platform
/// test below), so there is nothing to harden there.
final class LocalAuthProviderTests: XCTestCase {
    /// A relying party that requires verification (the account-deletion
    /// step-up) rejects an UP-only assertion. Every key is created with
    /// `.userPresence` access control, so UV is enforced and must be reported.
    func testAssertionFlagsReportUserPresenceAndVerification() {
        XCTAssertEqual(LocalAuthProvider.assertionFlags & 0x01, 0x01, "UP")
        XCTAssertEqual(LocalAuthProvider.assertionFlags & 0x04, 0x04, "UV")
    }

    #if canImport(Security)
    func testRegisteredKeyIsGatedByAccessControlRequiringUserPresence() async throws {
        let provider = LocalAuthProvider()
        let result = try await provider.register(options: RegisterOptions(
            rpId: "example.org",
            rpName: "Example",
            userId: Data([1, 2, 3]),
            userName: "user@example.org",
            userDisplayName: "Test User",
            challenge: Data([4, 5, 6])
        ))

        let tag = LocalAuthProvider.keyTag(for: result.credentialId)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecReturnAttributes as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        XCTAssertEqual(status, errSecSuccess, "register() must persist the signing key in the keychain")

        let attributes = item as? [String: Any]
        XCTAssertNotNil(
            attributes?[kSecAttrAccessControl as String],
            "Registered signing key must carry a kSecAttrAccessControl object — " +
                "a bare, ungated key would sign unconditionally with no device-authentication guarantee at all"
        )

        // Clean up regardless of assertion outcome above.
        provider.rollbackLastRegistration()
    }

    func testRollbackDeletesThePersistedKeychainKey() async throws {
        let provider = LocalAuthProvider()
        let result = try await provider.register(options: RegisterOptions(
            rpId: "example.org",
            rpName: "Example",
            userId: Data([7, 8, 9]),
            userName: "user2@example.org",
            userDisplayName: "Test User 2",
            challenge: Data([10, 11, 12])
        ))

        let tag = LocalAuthProvider.keyTag(for: result.credentialId)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
        ]

        provider.rollbackLastRegistration()

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        XCTAssertEqual(
            status, errSecItemNotFound,
            "rollbackLastRegistration() must delete the persisted key — a dev/test-only provider " +
                "must not leave real keychain entries behind after an abandoned registration"
        )
    }
    #else
    func testUnavailableOnNonSecurityPlatformsThrowsRatherThanSigningUngated() async {
        let provider = LocalAuthProvider()
        do {
            _ = try await provider.register(options: RegisterOptions(
                rpId: "example.org",
                rpName: "Example",
                userId: Data([1, 2, 3]),
                userName: "user@example.org",
                userDisplayName: "Test User",
                challenge: Data([4, 5, 6])
            ))
            XCTFail("Expected register() to throw where Security/Keychain Services are unavailable")
        } catch {
            // Expected: no Security framework means no way to enforce any
            // access control at all, so this platform must fail closed
            // rather than fall back to an ungated in-memory key.
        }
    }
    #endif
}
