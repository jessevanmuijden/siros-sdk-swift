// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
@testable import SirosWallet

/// `handleSignRequest`'s `sign_presentation` defense-in-depth check (go-wallet-backend#502): the engine's
/// `disclosed_claims` for a credential must not be trusted as given - it is checked against what THIS wallet
/// recorded as consented (`recordConsent`) when it answered `credential_selection`/`match_request`.
final class SignPresentationConsentEnforcementTests: XCTestCase {
    private struct NotImplemented: Error {}

    private final class NoopAuthProvider: AuthProvider {
        func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
    }

    private final class RecordingKeystoreManager: KeystoreManager, @unchecked Sendable {
        var isUnlocked: Bool { true }
        private(set) var signVpTokenCalls: [[String]?] = []
        func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
        func lock() {}
        func generateKey(algorithm: String) async throws -> String { "key" }
        func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
        func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "" }
        func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
        func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String {
            signVpTokenCalls.append(disclosedClaims)
            return "vp-token"
        }
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

    private final class RecordingSender: SignResponseSender, @unchecked Sendable {
        private(set) var sent: [SignResponseMessage] = []
        func sendSignResponse(_ message: SignResponseMessage) { sent.append(message) }
    }

    private func wallet(keystore: RecordingKeystoreManager) async -> SirosWallet {
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(id: 7, format: "dc+sd-jwt", raw: "a.b.c", batchId: 1, instanceId: 0))
        let w = SirosWallet(
            config: WalletConfig(backendUrl: "https://example.invalid", credentialStore: store),
            authProvider: NoopAuthProvider(), keystore: keystore, accountRegistry: .inMemory()
        )
        XCTAssertNotNil(w)
        return w!
    }

    private func signPresentationMessage(flowId: String, disclosedClaims: [String]?) throws -> SignRequestMessage {
        let claims = disclosedClaims.map { "[\($0.map { "\"\($0)\"" }.joined(separator: ","))]" } ?? "null"
        let json = #"""
        {"type":"sign_request","flow_id":"\#(flowId)","message_id":"m1","action":"sign_presentation",
         "params":{"audience":"https://verifier.example.invalid","nonce":"n",
         "credentials_to_include":[{"credential_id":"7","credential_query_id":"q1","disclosed_claims":\#(claims)}]}}
        """#
        return try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
    }

    func testSignPresentationRefusesWithNoRecordedConsentAtAll() async throws {
        let keystore = RecordingKeystoreManager()
        let w = await wallet(keystore: keystore)
        let sender = RecordingSender()

        await w.handleSignRequest(engine: sender, msg: try signPresentationMessage(flowId: "f1", disclosedClaims: ["given_name"]))

        XCTAssertEqual(sender.sent.count, 1)
        XCTAssertNotNil(sender.sent.first?.error, "no consent was ever recorded for this flow - must refuse")
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertTrue(keystore.signVpTokenCalls.isEmpty, "nothing was signed")
    }

    func testSignPresentationRefusesWhenTheEngineListsAClaimBeyondWhatWasConsented() async throws {
        let keystore = RecordingKeystoreManager()
        let w = await wallet(keystore: keystore)
        w.recordConsent(
            flowId: "f2",
            matchResults: [CredentialMatcher.MatchResult(queryId: "q1", format: "dc+sd-jwt", candidates: [await w.credentialStore.getAll()[0]], requestedClaims: [["given_name"]])],
            selectedIds: [7]
        )
        let sender = RecordingSender()

        await w.handleSignRequest(engine: sender, msg: try signPresentationMessage(flowId: "f2", disclosedClaims: ["given_name", "ssn"]))

        XCTAssertNotNil(sender.sent.first?.error, "ssn was never consented to")
        XCTAssertTrue(keystore.signVpTokenCalls.isEmpty)
    }

    func testSignPresentationSignsWhenDisclosedClaimsIsASubsetOfRecordedConsent() async throws {
        let keystore = RecordingKeystoreManager()
        let w = await wallet(keystore: keystore)
        w.recordConsent(
            flowId: "f3",
            matchResults: [CredentialMatcher.MatchResult(queryId: "q1", format: "dc+sd-jwt", candidates: [await w.credentialStore.getAll()[0]], requestedClaims: [["given_name"], ["family_name"]])],
            selectedIds: [7]
        )
        let sender = RecordingSender()

        await w.handleSignRequest(engine: sender, msg: try signPresentationMessage(flowId: "f3", disclosedClaims: ["given_name"]))

        XCTAssertNil(sender.sent.first?.error)
        XCTAssertEqual(sender.sent.first?.vpToken, "vp-token")
        XCTAssertEqual(keystore.signVpTokenCalls, [["given_name"]])
    }

    /// A nil `disclosed_claims` (the worst case: a modified engine omitting it entirely) is replaced by the
    /// recorded consent, never passed through as "disclose everything".
    func testSignPresentationReplacesANilDisclosedClaimsWithTheRecordedConsent() async throws {
        let keystore = RecordingKeystoreManager()
        let w = await wallet(keystore: keystore)
        w.recordConsent(
            flowId: "f4",
            matchResults: [CredentialMatcher.MatchResult(queryId: "q1", format: "dc+sd-jwt", candidates: [await w.credentialStore.getAll()[0]], requestedClaims: [["given_name"]])],
            selectedIds: [7]
        )
        let sender = RecordingSender()

        await w.handleSignRequest(engine: sender, msg: try signPresentationMessage(flowId: "f4", disclosedClaims: nil))

        XCTAssertNil(sender.sent.first?.error)
        XCTAssertEqual(keystore.signVpTokenCalls, [["given_name"]])
    }
}
