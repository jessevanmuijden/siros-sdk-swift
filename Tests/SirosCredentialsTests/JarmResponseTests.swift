// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class JarmResponseTests: XCTestCase {

    private let verifier = P256.KeyAgreement.PrivateKey()

    private func jwk(kid: String? = "verifier-key-1", extra: [String: String] = [:]) -> [String: String] {
        let point = verifier.publicKey.x963Representation
        var jwk = [
            "kty": "EC", "crv": "P-256",
            "x": CredentialResponseJwe.encode(point.subdata(in: 1..<33)),
            "y": CredentialResponseJwe.encode(point.subdata(in: 33..<65)),
        ]
        if let kid { jwk["kid"] = kid }
        for (k, v) in extra { jwk[k] = v }
        return jwk
    }

    private func header(of jwe: String) throws -> [String: Any] {
        let segment = try XCTUnwrap(jwe.split(separator: ".", omittingEmptySubsequences: false).first.map(String.init))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(CredentialResponseJwe.decode(segment))) as? [String: Any])
    }

    private func claims(_ jwe: String, enc: String = "A128GCM") throws -> [String: Any] {
        let plaintext = try CredentialResponseJwe.decrypt(
            jwe, recipient: verifier, expected: CredentialResponseEncryptionParams(alg: "ECDH-ES", enc: enc)
        )
        return try XCTUnwrap(JSONSerialization.jsonObject(with: plaintext) as? [String: Any])
    }

    func testTheResponseIsAJweWithExactlyTheRequestedHeaderAndTheVerifiersKid() throws {
        for enc in ["A128GCM", "A256GCM"] {
            let jwe = try JarmResponse.encrypt(
                vpToken: .string("tok"), state: "s", audience: "x509_san_dns:verifier.example",
                recipientJwk: jwk(), alg: "ECDH-ES", enc: enc
            )
            let parts = jwe.split(separator: ".", omittingEmptySubsequences: false)
            XCTAssertEqual(parts.count, 5)
            XCTAssertTrue(parts[1].isEmpty, "direct key agreement has no encrypted key")
            XCTAssertTrue([2, 3, 4].allSatisfy { !parts[$0].isEmpty })
            let h = try header(of: jwe)
            XCTAssertEqual(h["alg"] as? String, "ECDH-ES")
            XCTAssertEqual(h["enc"] as? String, enc)
            XCTAssertEqual(h["kid"] as? String, "verifier-key-1")
            XCTAssertNil(h["cty"], "the claims are plain JSON: no content type is set")
            XCTAssertEqual((h["epk"] as? [String: Any])?["crv"] as? String, "P-256")
            XCTAssertNil((h["epk"] as? [String: Any])?["d"])
            XCTAssertEqual(try claims(jwe, enc: enc)["vp_token"] as? String, "tok")
        }
    }

    func testNoKidInTheKeyMeansNoKidInTheHeader() throws {
        let jwe = try JarmResponse.encrypt(vpToken: .string("t"), state: nil, audience: "a", recipientJwk: jwk(kid: nil), alg: "ECDH-ES", enc: "A128GCM")
        XCTAssertNil(try header(of: jwe)["kid"])
    }

    func testTheClaimsAreTheJarmClaims() throws {
        let issued = Date(timeIntervalSince1970: 1_760_000_000)
        let jwe = try JarmResponse.encrypt(
            vpToken: .string("tok"), state: "state-1", audience: "client-1", recipientJwk: jwk(), alg: "ECDH-ES", enc: "A128GCM", issuedAt: issued
        )
        let c = try claims(jwe)
        XCTAssertEqual(c["iss"] as? String, "https://self-issued.me/v2")
        XCTAssertEqual(c["aud"] as? String, "client-1")
        XCTAssertEqual(c["iat"] as? Int, 1_760_000_000)
        XCTAssertEqual(c["exp"] as? Int, 1_760_000_300)
        XCTAssertEqual(c["state"] as? String, "state-1")
        XCTAssertEqual(Set(c.keys), ["iss", "aud", "iat", "exp", "vp_token", "state"])
        let stateless = try claims(try JarmResponse.encrypt(vpToken: .string("t"), state: nil, audience: "a", recipientJwk: jwk(), alg: "ECDH-ES", enc: "A128GCM"))
        XCTAssertNil(stateless["state"], "state only when the request had one")
    }

    func testDcqlTokensAreGroupedByQueryIdInOrder() throws {
        let value = VpTokenValue.from(parts: [("pid", "t1"), ("mdl", "t2"), ("pid", "t3")])
        XCTAssertEqual(value, .dcql([("pid", ["t1", "t3"]), ("mdl", ["t2"])]))
        let jwe = try JarmResponse.encrypt(vpToken: value, state: nil, audience: "a", recipientJwk: jwk(), alg: "ECDH-ES", enc: "A128GCM")
        let token = try XCTUnwrap(try claims(jwe)["vp_token"] as? [String: [String]])
        XCTAssertEqual(token, ["pid": ["t1", "t3"], "mdl": ["t2"]])
    }

    /// The enum case is public: a repeated query id is merged in order, not a trap.
    func testRepeatedQueryIdsPassedDirectlyAreMerged() throws {
        let jwe = try JarmResponse.encrypt(
            vpToken: .dcql([("pid", ["t1"]), ("mdl", ["m1"]), ("pid", ["t2"])]), state: nil, audience: "a",
            recipientJwk: jwk(), alg: "ECDH-ES", enc: "A128GCM"
        )
        XCTAssertEqual(try claims(jwe)["vp_token"] as? [String: [String]], ["pid": ["t1", "t2"], "mdl": ["m1"]])
    }

    func testWithoutQueryIdsTheTokenIsAString() {
        XCTAssertEqual(VpTokenValue.from(parts: [(nil, "a"), (nil, "b")]), .string("a\nb"))
        XCTAssertEqual(VpTokenValue.from(parts: [("q", "a"), (nil, "b")]), .string("a\nb"), "a part without a query makes it non-DCQL")
        XCTAssertEqual(VpTokenValue.from(parts: [("", "a")]), .string("a"))
        XCTAssertEqual(VpTokenValue.from(parts: []), .string(""))
    }

    func testTheAudienceComesFromTheValidatedClientIdOrNothingIsBuilt() {
        for audience in [nil, ""] as [String?] {
            XCTAssertThrowsError(try JarmResponse.encrypt(vpToken: .string("t"), state: nil, audience: audience, recipientJwk: jwk(), alg: "ECDH-ES", enc: "A128GCM")) {
                XCTAssertEqual($0 as? JarmResponseError, .missingAudience)
            }
        }
    }

    func testAnUnusableKeyOrParameterIsRefused() {
        func encrypt(_ key: [String: String], alg: String = "ECDH-ES", enc: String = "A128GCM") throws {
            _ = try JarmResponse.encrypt(vpToken: .string("t"), state: nil, audience: "a", recipientJwk: key, alg: alg, enc: enc)
        }
        XCTAssertThrowsError(try encrypt(jwk(extra: ["d": "AAAA"])), "a private key is never a target")
        XCTAssertThrowsError(try encrypt(jwk(extra: ["use": "sig"])))
        XCTAssertThrowsError(try encrypt(jwk(extra: ["crv": "P-384"])))
        XCTAssertThrowsError(try encrypt(jwk(extra: ["kty": "OKP"])))
        XCTAssertThrowsError(try encrypt(jwk(extra: ["x": "AA"])))
        XCTAssertNoThrow(try encrypt(jwk(extra: ["use": "enc"])))
        XCTAssertThrowsError(try encrypt(jwk(), alg: "ECDH-ES+A256KW")) { XCTAssertEqual($0 as? JarmResponseError, .unsupportedAlgorithm("ECDH-ES+A256KW")) }
        XCTAssertThrowsError(try encrypt(jwk(), enc: "A128CBC-HS256")) { XCTAssertEqual($0 as? JarmResponseError, .unsupportedEncryption("A128CBC-HS256")) }
    }

    func testTheSelfCheckRefusesWhatTheEngineWouldRefuse() {
        func check(_ jwe: String, kid: String? = nil) throws { try JarmResponse.selfCheck(jwe, alg: "ECDH-ES", enc: "A128GCM", kid: kid) }
        let header = CredentialResponseJwe.encode(Data(#"{"alg":"ECDH-ES","enc":"A128GCM"}"#.utf8))
        XCTAssertNoThrow(try check("\(header)..a.b.c"))
        XCTAssertThrowsError(try check("\(header).x.a.b.c"), "direct ECDH-ES has no encrypted key")
        XCTAssertThrowsError(try check("\(header)..a.b"), "four segments")
        XCTAssertThrowsError(try check("\(header)..a..c"), "an empty segment")
        XCTAssertThrowsError(try check("\(header)..a.b.c", kid: "k1"), "the kid must be the JWK's")
        XCTAssertThrowsError(try JarmResponse.selfCheck("\(header)..a.b.c", alg: "ECDH-ES", enc: "A256GCM", kid: nil), "the enc must be the request's")
        XCTAssertThrowsError(try check("\(header)..a.b.\(String(repeating: "c", count: JarmResponse.maxResponseBytes))"), "over 4 MiB")
    }

    func testAnotherKeyCannotOpenIt() throws {
        let jwe = try JarmResponse.encrypt(vpToken: .string("secret"), state: nil, audience: "a", recipientJwk: jwk(), alg: "ECDH-ES", enc: "A128GCM")
        XCTAssertThrowsError(try CredentialResponseJwe.decrypt(jwe, recipient: P256.KeyAgreement.PrivateKey()))
    }

    /// RFC 7638: SHA-256 over {"crv","kty","x","y"}; the expected value was computed independently (Python hashlib).
    func testAnEcJwkThumbprintMatchesAnIndependentComputation() {
        let jwk = ["kty": "EC", "crv": "P-256", "kid": "ignored",
                   "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU", "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"]
        XCTAssertEqual(JwkThumbprint.ec(jwk), "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U")
        XCTAssertNil(JwkThumbprint.ec(["kty": "EC", "crv": "P-256", "x": "x"]), "an incomplete key has no thumbprint")
        XCTAssertNil(JwkThumbprint.ec(["kty": "RSA", "crv": "P-256", "x": "x", "y": "y"]))
    }
}
