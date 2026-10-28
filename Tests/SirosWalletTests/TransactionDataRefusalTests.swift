// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosKeystore
import SirosTransport
@testable import SirosWallet

#if canImport(CryptoKit)

private final class NoAuth: AuthProvider, @unchecked Sendable {
    struct E: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw E() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw E() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw E() }
}

/// Records every signing call; answers fixed tokens.
private final class RecordingKeystore: KeystoreManager, @unchecked Sendable {
    struct NotImplemented: Error {}
    private(set) var calls: [String] = []
    var isUnlocked: Bool { false }
    func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
    func lock() {}
    func generateKey(algorithm: String) async throws -> String { throw NotImplemented() }
    func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { throw NotImplemented() }
    func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { throw NotImplemented() }
    func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String {
        calls.append("signPresentation"); return "legacy-token"
    }
    func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String {
        calls.append("signVpToken"); return "sd-jwt-token"
    }
    func signMdocPresentationForDCAPI(credentialBytes: Data, disclosedClaims: [String]?, nonce: String, origin: String,
                                      encryptionPublicJwkThumbprint: String?, kid: String?) async throws -> Data { throw NotImplemented() }
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
    func generateKeyProof(keyId: String, typ: String, issuer: String, audience: String, extraClaims: [String: String]) async throws -> String { throw NotImplemented() }
}

private final class Sender: SignResponseSender, @unchecked Sendable {
    private(set) var sent: [SignResponseMessage] = []
    func sendSignResponse(_ message: SignResponseMessage) { sent.append(message) }
}

private final class Listener: WalletEventListener, @unchecked Sendable {
    private(set) var errors: [String] = []
    func onCredentialSelectionRequired(request: PresentationRequest) async -> [Int64] { [] }
    func onFlowError(flowId: String, errorMessage: String, redirectUri: String?) { errors.append(errorMessage) }
}

/// A backend that still forwards `transaction_data` to every client must not
/// get a presentation signed without the hashes and without the user seeing
/// the transaction, on ANY transport.
final class TransactionDataRefusalTests: XCTestCase {
    private func makeWallet() async throws -> (SirosWallet, RecordingKeystore, Listener) {
        let store = InMemoryCredentialStore()
        await store.save(StoredCredential(id: 1, format: "dc+sd-jwt", raw: "a.b.c~", metadata: CredentialMetadata(name: "Card", vct: "urn:x", doctype: nil), batchId: 1, instanceId: 0))
        let keystore = RecordingKeystore()
        let wallet = try XCTUnwrap(SirosWallet(config: WalletConfig(backendUrl: "https://example.invalid", credentialStore: store), authProvider: NoAuth(), keystore: keystore))
        let listener = Listener()
        wallet.setEventListener(listener)
        return (wallet, keystore, listener)
    }

    private let td = #"[{"type":"urn:eudi:sca:payment:1","raw":"e30","credential_ids":["q"]}]"#

    private func engineMessage(transactionData: String?) throws -> SignRequestMessage {
        let tdMember = transactionData.map { #","transaction_data":\#($0)"# } ?? ""
        let json = #"{"type":"sign_request","flow_id":"f1","message_id":"m1","action":"sign_presentation","params":{"audience":"aud","nonce":"n","credentials_to_include":[{"credential_query_id":"q","credential_id":"1"}]\#(tdMember)}}"#
        return try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
    }

    private func wmpParams(transactionData: String?) throws -> SignSubFlowParams {
        let tdMember = transactionData.map { #","transaction_data":\#($0)"# } ?? ""
        return try JSONDecoder().decode(SignSubFlowParams.self, from: Data(#"{"action":"sign_presentation","nonce":"n","audience":"aud"\#(tdMember)}"#.utf8))
    }

    // MARK: legacy engine

    func testEngineRefusesTransactionDataAndSignsNothing() async throws {
        let (wallet, keystore, listener) = try await makeWallet()
        let sender = Sender()
        await wallet.handleSignRequest(engine: sender, msg: try engineMessage(transactionData: td))
        XCTAssertTrue(keystore.calls.isEmpty, "nothing is signed")
        XCTAssertEqual(sender.sent.count, 1, "the engine is answered at once, with an empty response")
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertEqual(sender.sent.first?.messageId, "m1", "correlated to the request")
        XCTAssertEqual(listener.errors.count, 1)
        XCTAssertTrue(listener.errors[0].hasPrefix("invalid_transaction_data"), listener.errors[0])
    }

    func testEngineRefusesAnExplicitNullMember() async throws {
        let (wallet, keystore, listener) = try await makeWallet()
        let sender = Sender()
        await wallet.handleSignRequest(engine: sender, msg: try engineMessage(transactionData: "null"))
        XCTAssertTrue(keystore.calls.isEmpty)
        XCTAssertNil(sender.sent.first?.vpToken)
        XCTAssertTrue(listener.errors.first?.hasPrefix("invalid_transaction_data") ?? false)
    }

    func testWmpRefusesAnExplicitNullMember() async throws {
        let (wallet, keystore, _) = try await makeWallet()
        do { _ = try await wallet.handleWmpSignRequest(flowId: "f1", params: try wmpParams(transactionData: "null")); XCTFail() }
        catch let error as WmpErrorCodeProviding { XCTAssertEqual(error.wmpErrorCode, "invalid_transaction_data") }
        XCTAssertTrue(keystore.calls.isEmpty)
    }

    /// A malformed member would otherwise fail to decode and be dropped without any answer.
    func testMalformedMembersAreRefusedOnBothTransports() async throws {
        for bad in ["5", "[{}]", #"{"a":1}"#, #"[{"raw":"x"}]"#] {
            let (wallet, keystore, listener) = try await makeWallet()
            let sender = Sender()
            await wallet.handleSignRequest(engine: sender, msg: try engineMessage(transactionData: bad))
            XCTAssertTrue(keystore.calls.isEmpty, bad)
            XCTAssertEqual(sender.sent.count, 1, "answered at once: \(bad)")
            XCTAssertNil(sender.sent.first?.vpToken, bad)
            XCTAssertTrue(listener.errors.first?.hasPrefix("invalid_transaction_data") ?? false, bad)
            do { _ = try await wallet.handleWmpSignRequest(flowId: "f1", params: try wmpParams(transactionData: bad)); XCTFail(bad) }
            catch let error as WmpErrorCodeProviding { XCTAssertEqual(error.wmpErrorCode, "invalid_transaction_data", bad) }
        }
    }

    func testEngineAnswersAsBeforeWithoutTransactionData() async throws {
        for member in [nil, "[]"] {
            let (wallet, keystore, listener) = try await makeWallet()
            // go-wallet-backend#502 defense in depth: this file is about transaction_data validation, not
            // consent-enforcement (covered by SignPresentationConsentEnforcementTests) - grant what a real
            // credential_selection would have for the one credential this fixture always uses.
            wallet.recordConsent(flowId: "f1", matchResults: [], selectedIds: [1])
            let sender = Sender()
            await wallet.handleSignRequest(engine: sender, msg: try engineMessage(transactionData: member))
            XCTAssertEqual(keystore.calls, ["signVpToken"], "\(member ?? "absent")")
            XCTAssertEqual(sender.sent.first?.vpToken, "sd-jwt-token")
            XCTAssertTrue(listener.errors.isEmpty)
        }
    }

    // MARK: WMP

    func testWmpRefusesTransactionDataWithTheVerifierCodeAndSignsNothing() async throws {
        let (wallet, keystore, _) = try await makeWallet()
        do {
            _ = try await wallet.handleWmpSignRequest(flowId: "f1", params: try wmpParams(transactionData: td))
            XCTFail("must refuse")
        } catch let error as WmpErrorCodeProviding {
            XCTAssertEqual(error.wmpErrorCode, "invalid_transaction_data")
        }
        XCTAssertTrue(keystore.calls.isEmpty)
    }

    func testWmpAnswersAsBeforeWithoutTransactionData() async throws {
        for member in [nil, "[]"] {
            let (wallet, keystore, _) = try await makeWallet()
            let result = try await wallet.handleWmpSignRequest(flowId: "f1", params: try wmpParams(transactionData: member))
            XCTAssertEqual(result.vpToken, "legacy-token")
            XCTAssertEqual(keystore.calls, ["signPresentation"])
        }
    }
}
#endif
