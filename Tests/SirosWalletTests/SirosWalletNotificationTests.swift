// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
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

    // MARK: - Renewal never costs the credential it replaces

    private final class FlowListener: WalletEventListener, @unchecked Sendable {
        var errors: [String] = [], completed: [String] = []
        func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] { [] }
        func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) { errors.append(errorMessage) }
        func onFlowComplete(flowId: String, redirectUri: String?) { completed.append(flowId) }
    }

    /// A wallet holding batch 77 (one credential and its refresh token), mid-renewal of it.
    private func renewalWallet() async -> (SirosWallet, InMemoryCredentialStore, FlowListener) {
        let store = InMemoryCredentialStore()
        let wallet = makeWallet(store: store)
        let listener = FlowListener()
        wallet.eventListener = listener
        await store.save(StoredCredential(id: 1, format: "vc+sd-jwt", raw: "old.jwt.value", batchId: 77, instanceId: 0))
        await wallet.setCredentialRefreshToken(batchId: 77, entry: CredentialRefreshTokenEntry(
            refreshToken: "old-rt", dpopJwk: nil, credentialIssuerIdentifier: "https://i.example", credentialConfigurationId: "pid"
        ))
        wallet.lock.lock(); wallet.pendingRenewalSourceBatchId = 77; wallet.lock.unlock()
        return (wallet, store, listener)
    }

    private func renewalMessage(_ credentials: [[String: Any]]) -> FlowCompleteMessage {
        var obj: [String: Any] = [
            "type": MessageTypes.flowComplete, "flow_id": "renew", "credentials": credentials,
            "refresh_token": "new-rt", "credential_issuer": "https://i.example", "selected_credential_configuration_id": "pid",
        ]
        obj["redirect_uri"] = NSNull()
        var msg = try! JSONDecoder().decode(FlowCompleteMessage.self, from: try! JSONSerialization.data(withJSONObject: obj))
        msg.startTag = 0 // the wallet's initial issuance epoch, as in `makeFlowComplete`
        return msg
    }

    /// A plain completion with an entry that has no credential value is refused whole: the old batch and its refresh
    /// token stay, nothing new is stored, and the new refresh token is not kept.
    func testAnUnreadableReplacementLeavesTheOldBatchAndRefreshTokenAlone() async {
        let now = Int64(Date().timeIntervalSince1970)
        let good: [String: Any] = ["format": "vc+sd-jwt", "credential": makeJwt(exp: now + 3600, iat: now)]
        for (name, entries) in [("missing", [["format": "vc+sd-jwt"] as [String: Any]]), ("one of two", [good, ["format": "vc+sd-jwt"]]), ("empty", [["format": "vc+sd-jwt", "credential": ""] as [String: Any]])] {
            let (wallet, store, listener) = await renewalWallet()
            await wallet.handleFlowComplete(msg: renewalMessage(entries))
            let stored = await store.getAll()
            XCTAssertEqual(stored.map(\.id), [1], "\(name): only the old credential remains")
            let tokens = await wallet.exportCredentialRefreshTokens()
            XCTAssertEqual(tokens.keys.sorted(), [77], "\(name): the old refresh token stays, no new one is kept")
            XCTAssertEqual(tokens[77]?.refreshToken, "old-rt", name)
            XCTAssertEqual(listener.errors.count, 1, name)
            XCTAssertTrue(listener.completed.isEmpty, name)
        }
    }

    /// The same renewal with a readable replacement supersedes the old batch and keeps the new refresh token.
    func testAReadableReplacementSupersedesTheOldBatch() async {
        let now = Int64(Date().timeIntervalSince1970)
        let (wallet, store, listener) = await renewalWallet()
        await wallet.handleFlowComplete(msg: renewalMessage([["format": "vc+sd-jwt", "credential": makeJwt(exp: now + 3600, iat: now)]]))
        let stored = await store.getAll()
        XCTAssertEqual(stored.count, 1)
        XCTAssertNotEqual(stored.first?.id, 1, "the old credential is gone")
        let tokens = await wallet.exportCredentialRefreshTokens()
        XCTAssertNil(tokens[77], "the old refresh token goes with its batch")
        XCTAssertEqual(tokens.values.first?.refreshToken, "new-rt")
        XCTAssertTrue(listener.errors.isEmpty)
    }

    /// A completion whose credentials are all rejected (here: expired) stores nothing, so no refresh token is
    /// attached to a batch that does not exist, and the old batch is untouched.
    func testNoRefreshTokenIsKeptForABatchThatStoredNothing() async {
        let now = Int64(Date().timeIntervalSince1970)
        let (wallet, store, _) = await renewalWallet()
        await wallet.handleFlowComplete(msg: renewalMessage([["format": "vc+sd-jwt", "credential": makeJwt(exp: now - 3600, iat: now - 7200)]]))
        let stored = await store.getAll()
        XCTAssertEqual(stored.map(\.id), [1])
        let tokens = await wallet.exportCredentialRefreshTokens()
        XCTAssertEqual(tokens.keys.sorted(), [77])
    }

    /// WMP: a plain completion that names a credential entry without its value is an error, never a success.
    func testAWmpCompletionWithAnUnreadableEntryIsRefused() async {
        let store = InMemoryCredentialStore()
        let wallet = makeWallet(store: store)
        let listener = FlowListener()
        wallet.eventListener = listener
        await wallet.handleWmpFlowComplete(flowId: "w1", result: .object_(["credentials": .array([.object_(["format": .string("vc+sd-jwt")])])]))
        XCTAssertEqual(listener.errors.count, 1)
        XCTAssertTrue(listener.completed.isEmpty)
        await wallet.handleWmpFlowComplete(flowId: "w2", result: .object_(["credentials": .array([.object_(["format": .string("vc+sd-jwt"), "credential": .string("a.b.c")])])]))
        XCTAssertEqual(listener.completed, ["w2"], "a readable completion still completes")
    }
}

#endif
