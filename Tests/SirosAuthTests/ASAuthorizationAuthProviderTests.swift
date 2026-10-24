// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(AuthenticationServices)
import AuthenticationServices
import XCTest
@testable import SirosAuth

final class ASAuthorizationAuthProviderTests: XCTestCase {
    /// The deletion step-up asks for "required"; it must reach both assertion
    /// requests instead of falling back to Apple's `.preferred` default.
    func testUserVerificationStringMapsToApplesPreference() {
        let map = ASAuthorizationAuthProvider.userVerificationPreference(for:)
        XCTAssertEqual(map("required"), .required)
        XCTAssertEqual(map("preferred"), .preferred)
        XCTAssertEqual(map("discouraged"), .discouraged)
        XCTAssertEqual(map("something-else"), .preferred)
    }
}
#endif
