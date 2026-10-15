// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosKeystore
@testable import SirosWallet

final class TransactionDataFlagTests: XCTestCase {

    func testConfigDefaultIsOff() {
        XCTAssertFalse(WalletConfig(backendUrl: "https://w.example").transactionDataEnabled)
        XCTAssertTrue(WalletConfig(backendUrl: "https://w.example", transactionDataEnabled: true).transactionDataEnabled)
    }

    // MARK: - DC API parsing (no CryptoKit needed for the unsigned variant)

    private func unsigned(_ extra: [String: Any]) -> String {
        var data: [String: Any] = ["nonce": "n", "response_mode": "dc_api"]
        data.merge(extra) { $1 }
        let obj: [String: Any] = ["requests": [["protocol": "openid4vp-v1-unsigned", "data": data]]]
        return String(decoding: try! JSONSerialization.data(withJSONObject: obj), as: UTF8.self)
    }

    func testParserReportsTransactionDataPresence() throws {
        XCTAssertFalse(try DCAPIRequestParser.parse(unsigned([:])).hasTransactionData)
        let r = try DCAPIRequestParser.parse(unsigned(["transaction_data": ["abc", "def"]]))
        XCTAssertTrue(r.hasTransactionData)
        XCTAssertEqual(r.transactionData, ["abc", "def"])
    }

    func testMalformedTransactionDataStillCountsAsPresent() throws {
        for value in [["not-a-string": 1] as Any, 5 as Any, NSNull(), [1, 2] as Any] {
            let r = try DCAPIRequestParser.parse(unsigned(["transaction_data": value]))
            XCTAssertTrue(r.hasTransactionData, "\(value)")
            XCTAssertNil(r.transactionData, "\(value)")
        }
    }
}

#if canImport(CryptoKit)
import CryptoKit
import SirosCredentials

/// Needs a wallet, which on Apple platforms defaults to the CryptoKit keystore.
final class TransactionDataWalletFlagTests: XCTestCase {
    private final class NoAuth: AuthProvider, @unchecked Sendable {
        struct E: Error {}
        func register(options: RegisterOptions) async throws -> RegisterResult { throw E() }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw E() }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw E() }
    }

    private final class StubHandler: TransactionConsentHandler, @unchecked Sendable {
        func confirm(_ request: TransactionConsentRequest) async throws -> Bool { false }
    }

    private func makeWallet(enabled: Bool = false) -> SirosWallet {
        SirosWallet(
            config: WalletConfig(backendUrl: "https://w.example.invalid", credentialStore: InMemoryCredentialStore(), transactionDataEnabled: enabled),
            authProvider: NoAuth(),
            accountRegistry: AccountRegistry.inMemory()
        )!
    }

    func testDefaultDeclaresNothing() {
        let w = makeWallet()
        XCTAssertFalse(w.transactionDataEnabled)
        XCTAssertNil(w.transactionDataEngineFeatures)
        XCTAssertNil(w.transactionDataWmpCapabilities)
    }

    func testFlagWithoutConsentHandlerDeclaresNothing() {
        let w = makeWallet(enabled: true)
        XCTAssertTrue(w.transactionDataEnabled)
        XCTAssertFalse(w.transactionDataEffectivelyEnabled)
        XCTAssertNil(w.transactionDataEngineFeatures)
        XCTAssertNil(w.transactionDataWmpCapabilities)
    }

    func testFlagAndHandlerDeclareBothTransports() {
        let w = makeWallet(enabled: true)
        w.transactionConsentHandler = StubHandler()
        XCTAssertEqual(w.transactionDataEngineFeatures, ["transaction_data.v1"])
        XCTAssertNotNil(w.transactionDataWmpCapabilities?["transaction_data"])
        w.transactionDataEnabled = false
        XCTAssertNil(w.transactionDataEngineFeatures, "a runtime flip applies to the next flow")
    }

    func testDCAPIRefusesTransactionDataInsteadOfIgnoringIt() async throws {
        let wallet = makeWallet()
        let obj: [String: Any] = ["requests": [["protocol": "openid4vp-v1-unsigned", "data": [
            "nonce": "n", "response_mode": "dc_api", "transaction_data": ["abc"],
            "dcql_query": ["credentials": [["id": "q", "format": "dc+sd-jwt"]]],
        ]]]]
        let json = String(decoding: try JSONSerialization.data(withJSONObject: obj), as: UTF8.self)
        do {
            _ = try await wallet.handleDCAPIRequest(rawRequestJson: json, origin: "https://rp.example")
            XCTFail("must refuse")
        } catch SirosError.transactionData(let e) {
            XCTAssertEqual(e.verifierErrorCode, "invalid_transaction_data")
        }
    }
}
#endif
