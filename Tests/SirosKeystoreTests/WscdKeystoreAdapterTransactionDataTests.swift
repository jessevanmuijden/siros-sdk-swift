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
    /// What the scripted SCA sign reports having applied, and what the plugin is.
    var pluginId: String? = "r2ps"
    var pin = Data("123456".utf8)
    var applied = [AuthenticationFactor(.possession, "key_in_remote_wscd"), AuthenticationFactor(.knowledge, "pin_6_or_more_digits")]
    var capability = SignerFactorCapability(canReachTwoCategories: true)
    private var _pinPrompts = 0
    var pinPrompts: Int { lock.lock(); defer { lock.unlock() }; return _pinPrompts }
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
    func authenticationCapability(keyId: String) async throws -> SignerFactorCapability { capability }
    func signForSca(keyId: String, payload: @escaping ([AuthenticationFactor]) throws -> Data) async throws -> SignerScaOutcome {
        try ScaSignFlow.run(
            pluginId: pluginId, capability: capability,
            promptPin: { lock.lock(); _pinPrompts += 1; lock.unlock(); return SecureBytes(pin) },
            payload: payload,
            sign: { _, _ in
                lock.lock(); _signCount += 1; lock.unlock()
                return ScaSignReport(
                    signature: Data(repeating: 2, count: 64), factors: applied,
                    satisfiesTwoCategories: Set(applied.map(\.category)).count >= 2, shortfall: nil
                )
            }
        )
    }
}

/// A signer that knows nothing about TS12 factors: only the protocol defaults.
private final class PlainSigner: Signer, @unchecked Sendable {
    private let realKey = P256.Signing.PrivateKey()
    func generateKey(algorithm: String) async throws -> String { "k1" }
    func sign(keyId: String, data: Data) async throws -> Data { Data(repeating: 1, count: 64) }
    func listKeys() async throws -> [SignerKeyInfo] { [SignerKeyInfo(keyId: "k1", algorithm: "ES256")] }
    func deleteKey(keyId: String) async throws {}
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func exportPublicKey(keyId: String) async throws -> Data { try JSONSerialization.data(withJSONObject: JwtHelpers.publicKeyJwk(realKey)) }
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties { SignerSecurityProperties(keyStorage: ["hardware"]) }
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
        let binding = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-256", responseMode: "direct_post.jwt")
        let vp = try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n1", audience: "aud1", transactionData: binding, kid: "k1")
        let c = try kbClaims(vp)
        XCTAssertEqual(c["transaction_data_hashes"] as? [String], sha256, "hashes over the raw strings, verifier order")
        XCTAssertEqual(c["transaction_data_hashes_alg"] as? String, "sha-256")
        XCTAssertEqual(c["response_mode"] as? String, "direct_post.jwt")
        XCTAssertEqual(c["amr"] as? [[String: String]], [["possession": "key_in_remote_wscd"], ["knowledge": "pin_6_or_more_digits"]],
                       "TS12 object-form amr, from the sign's own factors, replaces the signer's RFC 8176 strings")
        XCTAssertEqual(signer.pinPrompts, 1, "one fresh authentication for the sign")
        XCTAssertFalse((c["jti"] as? String ?? "").isEmpty)
        XCTAssertEqual(c["aud"] as? String, "aud1")
        XCTAssertEqual(c["nonce"] as? String, "n1")
        XCTAssertNotNil(c["iat"])
        XCTAssertNotNil(c["sd_hash"])
        let again = try kbClaims(try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n1", audience: "aud1", transactionData: binding, kid: "k1"))
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

    /// Factors were established for one key; if the credential's binding selects another, nothing is signed.
    func testAKeyMismatchBetweenFactorsAndSigningRefusesBeforeSigning() async throws {
        let signer = CountingSigner()
        let a = try await adapter(signer)
        let binding = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-256", responseMode: "dc_api")
        do {
            _ = try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: binding, kid: "k2")
            XCTFail("expected a refusal")
        } catch is KeystoreError {}
        XCTAssertEqual(signer.signCount, 0)
        do {
            _ = try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: binding, kid: nil)
            XCTFail("expected a refusal without a named key")
        } catch is KeystoreError {}
    }

    func testScaWithSha384() async throws {
        let a = try await adapter(CountingSigner())
        let binding = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-384", responseMode: "dc_api")
        let c = try kbClaims(try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: binding, kid: "k1"))
        XCTAssertEqual(c["transaction_data_hashes"] as? [String], sha384)
        XCTAssertEqual(c["transaction_data_hashes_alg"] as? String, "sha-384")
    }

    private func expectScaRefusal(_ signer: CountingSigner, file: StaticString = #filePath, line: UInt = #line) async throws {
        let a = try await adapter(signer)
        let binding = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-256", responseMode: "dc_api")
        do {
            _ = try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: binding, kid: "k1")
            XCTFail("must refuse", file: file, line: line)
        } catch let e as TransactionDataError {
            XCTAssertEqual(e.reason, .insufficientAuthenticationFactors, file: file, line: line)
        }
    }

    /// A key whose plugin cannot reach two categories is refused before the user is asked for anything.
    func testACapabilityShortfallRefusesBeforeAnyPromptOrSignature() async throws {
        let signer = CountingSigner()
        signer.capability = .cannot("softkey has no second factor")
        try await expectScaRefusal(signer)
        XCTAssertEqual(signer.pinPrompts, 0)
        XCTAssertEqual(signer.signCount, 0)
    }

    /// A plugin the manager does not honour a fresh PIN authentication for (softkey, anything unknown) never signs for SCA.
    func testAPluginWithoutFreshPinAuthenticationNeverSignsForSca() async throws {
        for plugin in ["softkey", "", "other-wscd"] {
            let signer = CountingSigner()
            signer.pluginId = plugin
            try await expectScaRefusal(signer)
            XCTAssertEqual(signer.signCount, 0, plugin)
        }
    }

    /// The token claims what the sign reports: if the sign applied something else, the signature is discarded.
    func testAFactorMismatchBetweenClaimAndSignDiscardsThePresentation() async throws {
        let signer = CountingSigner()
        // The PIN typed is 6 digits (claimed pin_6_or_more_digits) but the sign reports a shorter class.
        signer.applied = [AuthenticationFactor(.possession, "key_in_remote_wscd"), AuthenticationFactor(.knowledge, "pin_less_than_6_digits")]
        try await expectScaRefusal(signer)
        XCTAssertEqual(signer.signCount, 1, "the sign happened; its result must not leave the keystore")
    }

    func testASignThatAppliedOnlyOneCategoryIsRefused() async throws {
        let signer = CountingSigner()
        signer.applied = [AuthenticationFactor(.possession, "key_in_remote_wscd")]
        try await expectScaRefusal(signer)
    }

    /// A signer that cannot report factors (the protocol default) refuses rather than sign a claim it cannot back.
    func testASignerThatCannotReportFactorsRefuses() async throws {
        let a = WscdKeystoreAdapter(signer: PlainSigner())
        try await a.unlock(prfOutput: Data(), encryptedContainer: Data(), hkdfSalt: Data(), hkdfInfo: Data())
        let binding = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-256", responseMode: "dc_api")
        do {
            _ = try await a.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: binding, kid: "k1")
            XCTFail("must refuse")
        } catch let e as TransactionDataError {
            XCTAssertEqual(e.reason, .insufficientAuthenticationFactors)
        }
        let capability = await a.scaAuthenticationCapability(keyId: "k1")
        XCTAssertFalse(capability.canReachTwoCategories)
    }

    func testTheKeystoreCapabilityFailsClosed() async throws {
        let signer = CountingSigner()
        let a = try await adapter(signer)
        let ok = await a.scaAuthenticationCapability(keyId: "k1")
        XCTAssertTrue(ok.canReachTwoCategories)
        // A factor only the host could supply cannot be used: a fresh authentication cannot be combined with it.
        signer.capability = SignerFactorCapability(canReachTwoCategories: true, requiresHostVerifiedFactor: true)
        let host = await a.scaAuthenticationCapability(keyId: "k1")
        XCTAssertFalse(host.canReachTwoCategories)
        signer.capability = .cannot("no")
        let no = await a.scaAuthenticationCapability(keyId: "k1")
        XCTAssertFalse(no.canReachTwoCategories)
    }

    /// The manager may answer positively for a key it does not hold: an unknown key is refused before consent.
    func testAnUnknownKeyHasNoScaCapability() async throws {
        let a = try await adapter(CountingSigner())   // reports a positive capability for any key id
        let unknown = await a.scaAuthenticationCapability(keyId: "not-a-key")
        XCTAssertFalse(unknown.canReachTwoCategories)
        let empty = await a.scaAuthenticationCapability(keyId: "")
        XCTAssertFalse(empty.canReachTwoCategories)
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
        let binding = TransactionDataBinding(rawEntries: raws, hashAlgorithm: "sha-256", responseMode: "dc_api")
        do {
            _ = try await keystore.signVpToken(credential: credential, disclosedClaims: nil, nonce: "n", audience: "a", transactionData: binding, kid: "k1")
            XCTFail("must refuse")
        } catch let e as TransactionDataError {
            XCTAssertEqual(e.reason, .insufficientAuthenticationFactors)
        }
    }
}
#endif
