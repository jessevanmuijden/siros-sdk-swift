// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosTransport
@testable import SirosWallet

// `handleFlowComplete` persists via the keystore, and the default `JweKeystore`
// is only available where CryptoKit is (Apple platforms / CI macOS runner).
#if canImport(CryptoKit)

/// Minimal `AuthProvider` stub. `handleFlowComplete` never invokes the
/// authenticator, so all methods simply throw.
private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

final class SirosWalletNotificationTests: XCTestCase {

    /// Build a JWT-shaped string whose payload encodes the given claims.
    /// `parseJwtPayload` only base64url-decodes the second segment, so the
    /// header and signature can be arbitrary.
    private func makeJwt(exp: Int64, iat: Int64) -> String {
        let payload = ["exp": exp, "iat": iat]
        let json = try! JSONSerialization.data(withJSONObject: payload)
        let b64 = json.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        return "eyJ.\(b64).sig"
    }

    /// `FlowCompleteMessage` / `CredentialResult` expose only a synthesized
    /// `init(from:)` across module boundaries, so build them from JSON.
    private func makeFlowComplete(flowId: String, credentials: [[String: Any]]?) -> FlowCompleteMessage {
        var obj: [String: Any] = ["type": MessageTypes.flowComplete, "flow_id": flowId]
        if let credentials { obj["credentials"] = credentials }
        let data = try! JSONSerialization.data(withJSONObject: obj)
        var msg = try! JSONDecoder().decode(FlowCompleteMessage.self, from: data)
        msg.startTag = 0 // the wallet's initial issuance epoch: this completion's flow started under it
        return msg
    }

    private func makeWallet(store: InMemoryCredentialStore) -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid", credentialStore: store)
        let wallet = SirosWallet(config: config, authProvider: StubAuthProvider())
        XCTAssertNotNil(wallet, "wallet should initialise with default keystore on CryptoKit platforms")
        return wallet!
    }

    /// A `flow_complete` with one unexpired credential persists it and preserves
    /// its notification_id, and the wallet transitions to `.ready` with the
    /// stored credential.
    func testHandleFlowCompletePersistsCredentialAndNotificationId() async {
        let store = InMemoryCredentialStore()
        let wallet = makeWallet(store: store)
        wallet.setState(.ready(userId: "user-1", displayName: "User One", credentials: []))

        let now = Int64(Date().timeIntervalSince1970)
        let jwt = makeJwt(exp: now + 3600, iat: now)
        let msg = makeFlowComplete(flowId: "flow-1", credentials: [[
            "format": "vc+sd-jwt",
            "credential": jwt,
            "notification_id": "notif-123",
        ]])

        await wallet.handleFlowComplete(msg: msg)

        let stored = await store.getAll()
        XCTAssertEqual(stored.count, 1)
        XCTAssertEqual(stored.first?.notificationId, "notif-123")
        XCTAssertEqual(stored.first?.raw, jwt)
        XCTAssertEqual(stored.first?.format, "vc+sd-jwt")

        if case let .ready(userId, displayName, credentials, _) = wallet.state {
            XCTAssertEqual(userId, "user-1")
            XCTAssertEqual(displayName, "User One")
            XCTAssertEqual(credentials.count, 1)
        } else {
            XCTFail("expected .ready state, got \(wallet.state)")
        }
    }

    /// Expired credentials are skipped and never stored.
    func testHandleFlowCompleteSkipsExpiredCredential() async {
        let store = InMemoryCredentialStore()
        let wallet = makeWallet(store: store)

        let now = Int64(Date().timeIntervalSince1970)
        let jwt = makeJwt(exp: now - 3600, iat: now - 7200)
        let msg = makeFlowComplete(flowId: "flow-2", credentials: [[
            "format": "vc+sd-jwt",
            "credential": jwt,
            "notification_id": "notif-expired",
        ]])

        await wallet.handleFlowComplete(msg: msg)

        let stored = await store.getAll()
        XCTAssertTrue(stored.isEmpty, "expired credential must not be stored")
    }

    /// A `flow_complete` with no credentials array is a no-op for storage and
    /// still fires the flow-complete bookkeeping without crashing.
    func testHandleFlowCompleteWithNoCredentials() async {
        let store = InMemoryCredentialStore()
        let wallet = makeWallet(store: store)

        let msg = makeFlowComplete(flowId: "flow-3", credentials: nil)

        await wallet.handleFlowComplete(msg: msg)

        let stored = await store.getAll()
        XCTAssertTrue(stored.isEmpty)
    }
}

#endif
