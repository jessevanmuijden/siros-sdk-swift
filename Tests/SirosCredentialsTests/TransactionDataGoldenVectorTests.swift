// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

/// Golden hash vectors, computed with Python hashlib independently of any
/// wallet: `Resources/transaction-data-hashes.json` is a verbatim copy of
/// `vectors/openid4x/transaction-data-hashes.json` in leifj/wmp (origin/main
/// 21074e4cd09c87cccbcd62afde7862b4dcb34258, 2026-10-06).
final class TransactionDataGoldenVectorTests: XCTestCase {
    struct Vector: Decodable {
        let name: String
        let json: String
        let raw: String
        let noncanonical: Bool
        let hashes: [String: String]
    }
    struct File: Decodable { let vectors: [Vector] }

    private func vectors() throws -> [Vector] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "transaction-data-hashes", withExtension: "json"))
        return try JSONDecoder().decode(File.self, from: Data(contentsOf: url)).vectors
    }

    func testEveryVectorHashIsReproducedFromRaw() throws {
        let all = try vectors()
        XCTAssertGreaterThanOrEqual(all.count, 7)
        for v in all {
            for alg in ["sha-256", "sha-384", "sha-512"] {
                XCTAssertEqual(TransactionDataHashing.hash(raw: v.raw, algorithm: alg), v.hashes[alg], "\(v.name) \(alg)")
            }
        }
    }

    func testRawDecodesToTheStatedJson() throws {
        for v in try vectors() {
            let decoded = try XCTUnwrap(TransactionDataHashing.base64UrlDecode(v.raw), v.name)
            XCTAssertEqual(String(decoding: decoded, as: UTF8.self), v.json, v.name)
        }
    }

    /// The point of hashing `raw`: for non-canonical entries, hashing the
    /// decoded text, or a re-serialisation of it, gives a different value.
    func testHashingDecodedContentGivesTheWrongValueForNonCanonicalVectors() throws {
        var checked = 0
        for v in try vectors() where v.noncanonical {
            XCTAssertNotEqual(TransactionDataHashing.hash(raw: v.json, algorithm: "sha-256"), v.hashes["sha-256"], v.name)
            checked += 1
        }
        XCTAssertGreaterThanOrEqual(checked, 5)
    }

    func testKbJwtClaimsCarryTheVectorHashesInVerifierOrder() throws {
        let all = try vectors()
        let binding = TransactionDataBinding(
            rawEntries: all.map(\.raw),
            hashAlgorithm: "sha-384",
            responseMode: "dc_api",
            factors: [AuthenticationFactor(.knowledge, "other"), AuthenticationFactor(.possession, "key_in_local_native_wscd")]
        )
        let claims = try binding.kbJwtClaims(jti: "j")
        XCTAssertEqual(claims["transaction_data_hashes"] as? [String], all.map { $0.hashes["sha-384"]! })
    }

    func testUnsupportedAlgorithmYieldsNoHash() {
        XCTAssertNil(TransactionDataHashing.hash(raw: "abc", algorithm: "sha-1"))
        XCTAssertNil(TransactionDataHashing.hash(raw: "abc", algorithm: "SHA-256"))
    }

    func testBase64UrlDecodeIsStrict() {
        XCTAssertNotNil(TransactionDataHashing.base64UrlDecode("e30"))
        XCTAssertNotNil(TransactionDataHashing.base64UrlDecode("e30="))
        XCTAssertNil(TransactionDataHashing.base64UrlDecode("e+0"), "standard alphabet is not base64url")
        XCTAssertNil(TransactionDataHashing.base64UrlDecode("e30 "))
        XCTAssertNil(TransactionDataHashing.base64UrlDecode("e"), "a single character is not a valid base64 length")
        XCTAssertNil(TransactionDataHashing.base64UrlDecode("e30==="), "at most two padding characters")
    }
}
