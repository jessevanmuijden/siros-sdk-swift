// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore
import SirosCredentials

#if canImport(CryptoKit)
import CryptoKit

/// A `Signer` that records how often it signed, so a refusal can be shown to
/// happen BEFORE any signature is produced.
private final class CountingSigner: Signer, @unchecked Sendable {
    private let lock = NSLock()
    private var _signCount = 0
    var signCount: Int { lock.lock(); defer { lock.unlock() }; return _signCount }
    var amr: [String] = ["hwk", "pop", "pin"]
    private let realKey = P256.Signing.PrivateKey()

    func generateKey(algorithm: String) async throws -> String { "k1" }
    func sign(keyId: String, data: Data) async throws -> Data {
        lock.lock(); _signCount += 1; lock.unlock()
        return Data(repeating: 1, count: 64)
    }
    func listKeys() async throws -> [SignerKeyInfo] { [SignerKeyInfo(keyId: "k1", algorithm: "ES256")] }
    func deleteKey(keyId: String) async throws {}
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func exportPublicKey(keyId: String) async throws -> Data {
        try JSONSerialization.data(withJSONObject: JwtHelpers.publicKeyJwk(realKey))
    }
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        SignerSecurityProperties(keyStorage: ["hardware"], userAuthentication: ["pin"], amr: amr)
    }
}

final class WscdKeystoreAdapterTransactionDataTests: XCTestCase {
    private let credential = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ4In0.c2ln~"
    /// Raw strings and sha-256/384 values from the wmp golden vectors
    /// (`keys_in_spec_order`, `pretty_printed`).
    private let raws = [
        "eyJ0eXBlIjoidXJuOmV1ZGk6c2NhOnBheW1lbnQ6MSIsImNyZWRlbnRpYWxfaWRzIjpbInBheSJdLCJwYXlsb2FkIjp7InRyYW5zYWN0aW9uX2lkIjoidHgtMDAwMSIsInBheWVlIjp7Im5hbWUiOiJTaG9wIEFCIiwiaWQiOiJTRTEyMzQ1Njc4OTAifSwiYW1vdW50IjoiNDkuOTkiLCJjdXJyZW5jeSI6IkVVUiIsImV4ZWN1dGlvbl9kYXRlIjoiMjAyNi0xMC0wNiJ9fQ",
        "eyJ0eXBlIjoidXJuOmV1ZGk6c2NhOnBheW1lbnQ6MSIsImNyZWRlbnRpYWxfaWRzIjpbInBheSJdLCJwYXlsb2FkIjp7InRyYW5zYWN0aW9uX2lkIjoidHgtMDAwMiIsInBheWVlIjp7Im5hbWUiOiJcdTAwYzVrZXNzb24gXC8gU29uIiwiaWQiOiJTRTEifSwiYW1vdW50IjoiMTAuMDAiLCJjdXJyZW5jeSI6IlNFSyJ9fQ",
    ]
    private let sha256 = ["d4up91CnefFMyilR37pBM743RezMNKvBr5-Cc9F_GzY", "WoIXcj6LDcvVcXpugPs57WSBd6W7ZYLq_5lg3o89QTk"]
    private let sha384 = [
        "y6OQtBXxf4i_U1g5uy3JKxuqy6RZUlyLrUKhyh8Aj1dUHz_ttS5QHh2Q-Chz7c8V",
        "ICddVCtQK_UXazO5cu-vGshtyRJQ6QxIussKYx8QDGD3CSZeMD5XhNhcXlZTQarn",
    ]
    private let twoFactors = [AuthenticationFactor(.knowledge, "other"), AuthenticationFactor(.possession, "key_in_local_native_wscd")]

    private func adapter(_ signer: CountingSigner) async throws -> WscdKeystoreAdapter {
        let a = WscdKeystoreAdapter(signer: signer)
        try await a.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())
        return a
    }

    private func kbClaims(_ presentation: String) throws -> [String: Any] {
        let kb = try XCTUnwrap(presentation.split(separator: "~", omittingEmptySubsequences: false).last.map(String.init))
        let payload = try XCTUnwrap(kb.split(separator: ".").dropFirst().first.map(String.init))
        var b64 = payload.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        b64 += String(repeating: "=", count: (4 - b64.count % 4) % 4)
        let data = try XCTUnwrap(Data(base64Encoded: b64))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    func testScaKbJwtMeetsTheVerifierContract() async throws {
        let signer = CountingSigner()
        let a = try await adapter(signer)
        let binding = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-256", responseMode: "direct_post.jwt", factors: twoFactors)
        let vp = try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n1", audience: "aud1", transactionData: binding, kid: nil)
        let c = try kbClaims(vp)
        XCTAssertEqual(c["transaction_data_hashes"] as? [String], sha256, "hashes over the raw strings, verifier order")
        XCTAssertEqual(c["transaction_data_hashes_alg"] as? String, "sha-256")
        XCTAssertEqual(c["response_mode"] as? String, "direct_post.jwt")
        XCTAssertEqual(c["amr"] as? [[String: String]], [["knowledge": "other"], ["possession": "key_in_local_native_wscd"]],
                       "TS12 object-form amr replaces the signer's RFC 8176 strings")
        XCTAssertFalse((c["jti"] as? String ?? "").isEmpty)
        XCTAssertEqual(c["aud"] as? String, "aud1")
        XCTAssertEqual(c["nonce"] as? String, "n1")
        XCTAssertNotNil(c["iat"])
        XCTAssertNotNil(c["sd_hash"])
        let again = try kbClaims(try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n1", audience: "aud1", transactionData: binding, kid: nil))
        XCTAssertNotEqual(c["jti"] as? String, again["jti"] as? String, "jti is fresh per presentation")
    }

    /// The pre-TS12 overload still compiles: items are refused, none/empty signs a plain presentation.
    @available(*, deprecated)
    func testTheDeprecatedItemOverloadRefusesItemsAndSignsPlainWithout() async throws {
        let signer = CountingSigner()
        let a = try await adapter(signer)
        let items = [TransactionDataItem(type: "payment", rawJson: "{}")]
        do {
            _ = try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: items, kid: nil)
            XCTFail("expected a refusal")
        } catch is KeystoreError {}
        let plain = try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: [TransactionDataItem](), kid: nil)
        XCTAssertNil(try kbClaims(plain)["transaction_data_hashes"])
    }

    func testScaWithSha384() async throws {
        let a = try await adapter(CountingSigner())
        let binding = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-384", responseMode: "dc_api", factors: twoFactors)
        let c = try kbClaims(try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: binding, kid: nil))
        XCTAssertEqual(c["transaction_data_hashes"] as? [String], sha384)
        XCTAssertEqual(c["transaction_data_hashes_alg"] as? String, "sha-384")
    }

    func testInsufficientFactorsRefuseBeforeAnythingIsSigned() async throws {
        let signer = CountingSigner()
        let a = try await adapter(signer)
        let one = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-256", responseMode: "dc_api",
                                         factors: [AuthenticationFactor(.possession, "key_in_remote_wscd")])
        do {
            _ = try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: one, kid: nil)
            XCTFail("must refuse")
        } catch let e as TransactionDataError {
            XCTAssertEqual(e.reason, .insufficientAuthenticationFactors)
        }
        XCTAssertEqual(signer.signCount, 0, "nothing may be signed when the claims cannot be produced")
    }

    /// Presentations without transaction data are byte-for-byte unchanged:
    /// the claim set is exactly the pre-existing one, RFC 8176 amr included.
    func testNonScaClaimSetIsUnchanged() async throws {
        let signer = CountingSigner()
        let a = try await adapter(signer)
        let plain = try kbClaims(try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", kid: nil))
        XCTAssertEqual(Set(plain.keys), ["aud", "iat", "nonce", "sd_hash", "amr"])
        XCTAssertEqual(plain["amr"] as? [String], ["hwk", "pop", "pin"])
        let viaNil = try kbClaims(try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: nil, kid: nil))
        XCTAssertEqual(Set(viaNil.keys), Set(plain.keys))
        XCTAssertEqual(viaNil["amr"] as? [String], plain["amr"] as? [String])
        signer.amr = []
        let noAmr = try kbClaims(try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", kid: nil))
        XCTAssertEqual(Set(noAmr.keys), ["aud", "iat", "nonce", "sd_hash"])
    }

    /// A keystore that was not written to produce TS12 claims must refuse an
    /// SCA request rather than answer with a presentation lacking them.
    func testKeystoreWithoutScaSupportRefuses() async throws {
        let keystore: KeystoreManager = JweKeystore()
        let binding = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-256", responseMode: "dc_api", factors: twoFactors)
        do {
            _ = try await keystore.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: binding, kid: nil)
            XCTFail("must refuse")
        } catch let e as TransactionDataError {
            XCTAssertEqual(e.reason, .insufficientAuthenticationFactors)
        }
    }
}
#endif
