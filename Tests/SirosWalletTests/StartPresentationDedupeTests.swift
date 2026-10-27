// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosTransport
import SirosAuth
import SirosKeystore
import SirosCredentials
@testable import SirosWallet

/// `SirosWallet.startPresentation`'s dedup of a redelivered identical link (siros-sdk-kotlin #333's bug, ported:
/// an issuer's own web page can re-fire the same OpenID4VP request after it was already answered). The connect and
/// send steps are replaced by test hooks (same pattern as `resumeAuthorization`'s own hooks), so this needs no live
/// engine connection.
final class StartPresentationDedupeTests: XCTestCase {
    private struct NotImplemented: Error {}

    private final class NoopAuthProvider: AuthProvider {
        func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
    }

    private final class StubKeystoreManager: KeystoreManager, @unchecked Sendable {
        var isUnlocked: Bool { true }
        func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
        func lock() {}
        func generateKey(algorithm: String) async throws -> String { "key" }
        func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
        func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "proof" }
        func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
        func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
        func exportEncryptedContainer() async throws -> Data { Data() }
        func listKeys() -> [KeyInfo] { [] }
        func saveCredential(id: Int64, json: String) async throws {}
        func getCredential(id: Int64) async throws -> String? { nil }
        func getAllCredentials() async throws -> [Int64: String] { [:] }
        func deleteCredential(id: Int64) async throws {}
        func clearCredentials() async throws {}
        func savePresentationRecord(id: Int64, json: String) async throws {}
        func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
        func clearPresentationRecords() async throws {}
        func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    }

    private struct SendFailed: Error {}

    private func wallet() -> SirosWallet {
        let w = SirosWallet(
            config: WalletConfig(backendUrl: "https://wallet.example.invalid", credentialStore: InMemoryCredentialStore()),
            authProvider: NoopAuthProvider(), keystore: StubKeystoreManager(), accountRegistry: .inMemory()
        )
        XCTAssertNotNil(w)
        w!.engineSession = WalletEngineSession(baseUrl: "https://wallet.example.invalid", tenantId: "t")
        return w!
    }

    func testARedeliveredIdenticalLinkStartsNoSecondFlow() async throws {
        let w = wallet()
        w.startPresentationConnectHook = { _ in }
        var sent: [String] = []
        w.startPresentationSendHook = { sent.append($0); return true }
        let link = "openid4vp://?client_id=x&nonce=1"

        let first = try await w.startPresentation(requestUri: link)
        let second = try await w.startPresentation(requestUri: link)

        XCTAssertTrue(first, "the first delivery starts a flow")
        XCTAssertFalse(second, "the redelivered identical link starts none")
        XCTAssertEqual(sent, [link], "the engine was asked exactly once")
    }

    func testADifferentLinkStillStartsItsOwnFlow() async throws {
        let w = wallet()
        w.startPresentationConnectHook = { _ in }
        var sent: [String] = []
        w.startPresentationSendHook = { sent.append($0); return true }

        let first = try await w.startPresentation(requestUri: "openid4vp://?client_id=x")
        let second = try await w.startPresentation(requestUri: "openid4vp://?client_id=y")
        XCTAssertTrue(first)
        XCTAssertTrue(second)
        XCTAssertEqual(sent, ["openid4vp://?client_id=x", "openid4vp://?client_id=y"])
    }

    /// A start that fails (here: the connect step) forgets the link, so a retry of the SAME link goes through at
    /// once rather than being treated as a redelivered duplicate.
    func testAFailedStartForgetsTheLinkSoARetryGoesThrough() async throws {
        let w = wallet()
        let link = "openid4vp://?client_id=x"
        w.startPresentationConnectHook = { _ in throw SendFailed() }
        do {
            _ = try await w.startPresentation(requestUri: link)
            XCTFail("the connect step was made to fail")
        } catch is SendFailed {}

        var sent: [String] = []
        w.startPresentationConnectHook = { _ in }
        w.startPresentationSendHook = { sent.append($0); return true }
        let retried = try await w.startPresentation(requestUri: link)

        XCTAssertTrue(retried, "the failed attempt did not hold the link against the retry")
        XCTAssertEqual(sent, [link])
    }

    /// The engine session being nil (never connected) also throws, and must not leave the link stuck either.
    func testNoEngineSessionAlsoForgetsTheLinkOnFailure() async throws {
        let w = SirosWallet(
            config: WalletConfig(backendUrl: "https://wallet.example.invalid", credentialStore: InMemoryCredentialStore()),
            authProvider: NoopAuthProvider(), keystore: StubKeystoreManager(), accountRegistry: .inMemory()
        )!
        let link = "openid4vp://?client_id=x"
        do {
            _ = try await w.startPresentation(requestUri: link)
            XCTFail("no engine session is configured")
        } catch {}
        w.engineSession = WalletEngineSession(baseUrl: "https://wallet.example.invalid", tenantId: "t")
        w.startPresentationConnectHook = { _ in }
        var sent: [String] = []
        w.startPresentationSendHook = { sent.append($0); return true }
        let started = try await w.startPresentation(requestUri: link)
        XCTAssertTrue(started)
        XCTAssertEqual(sent, [link])
    }

    /// Cancelling a presentation releases ITS ledger entry: an immediate retry of the SAME request must not be held
    /// against the window for the rest of the minute, unlike a presentation that reaches its own completion/error.
    func testCancellingAPresentationReleasesItsLinkSoAnImmediateRetryGoesThrough() async throws {
        let w = wallet()
        w.startPresentationConnectHook = { _ in }
        var sent: [String] = []
        w.startPresentationSendHook = { sent.append($0); return true }
        let link = "openid4vp://?client_id=x"

        let first = try await w.startPresentation(requestUri: link)
        XCTAssertTrue(first)
        w.cancelCurrentFlow()
        let retried = try await w.startPresentation(requestUri: link)

        XCTAssertTrue(retried, "cancelling released the link - the retry is not an ignored duplicate")
        XCTAssertEqual(sent, [link, link])
    }

    /// A presentation that reaches its OWN completion (not a cancel) is still deduped for the rest of the window:
    /// only a cancel releases the entry early.
    func testACompletedPresentationsLinkIsStillDedupedUntilItsWindowExpires() async throws {
        let w = wallet()
        w.startPresentationConnectHook = { _ in }
        var sent: [String] = []
        w.startPresentationSendHook = { sent.append($0); return true }
        let link = "openid4vp://?client_id=x"

        let first = try await w.startPresentation(requestUri: link)
        XCTAssertTrue(first)
        let completion = try JSONDecoder().decode(
            FlowCompleteMessage.self, from: Data(#"{"type":"flow_complete","flow_id":"p1"}"#.utf8)
        )
        await w.handleFlowComplete(msg: completion)
        let redelivered = try await w.startPresentation(requestUri: link)

        XCTAssertFalse(redelivered, "the completed presentation's link is still inside its window")
        XCTAssertEqual(sent, [link], "no second send for the redelivered link")
    }

    /// `WalletEngineSession.startPresentation` is nonthrowing: a dispatch that finds no live socket (the connection
    /// dropped in the window after `ensureEngineConnected` succeeded) must not be treated as success, and must
    /// release the link exactly as a thrown failure does.
    func testADispatchThatFindsNoSocketIsNotTreatedAsSuccessAndReleasesTheLink() async throws {
        let w = wallet()
        let link = "openid4vp://?client_id=x"
        w.startPresentationConnectHook = { _ in }
        w.startPresentationSendHook = { _ in false }       // mirrors WalletEngineSession.startPresentation finding no socket

        do {
            _ = try await w.startPresentation(requestUri: link)
            XCTFail("a dispatch that found no socket must throw, not return true")
        } catch {}

        var sent: [String] = []
        w.startPresentationSendHook = { sent.append($0); return true }
        let retried = try await w.startPresentation(requestUri: link)

        XCTAssertTrue(retried, "the undelivered dispatch did not hold the link against a retry")
        XCTAssertEqual(sent, [link])
    }
}
