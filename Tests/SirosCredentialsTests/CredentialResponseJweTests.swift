// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class CredentialResponseJweTests: XCTestCase {

    // MARK: - Fixtures

    private struct Vectors {
        let recipient: P256.KeyAgreement.PrivateKey
        let plaintext: String
        let cases: [String: String]
    }

    private func vectors() throws -> Vectors {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "credential-response-jwe-vectors", withExtension: "json"))
        let raw = try Data(contentsOf: url)
        // Pinned: the file is generated, never edited (see its PROVENANCE).
        XCTAssertEqual(sha256Hex(raw), "51da911d44f3644e5f3b96dd81042c35eae0aa7f0fbb31ccece94c2cba61c104")
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: raw) as? [String: Any])
        let d = try XCTUnwrap((json["recipient_d"] as? String).flatMap(CredentialResponseJwe.decode))
        return Vectors(
            recipient: try P256.KeyAgreement.PrivateKey(rawRepresentation: d),
            plaintext: try XCTUnwrap(json["plaintext"] as? String),
            cases: try XCTUnwrap(json["cases"] as? [String: String])
        )
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - go-jose vectors

    func testEveryAlgAndEncCombinationOpensToThePlaintext() throws {
        let v = try vectors()
        XCTAssertEqual(v.cases.count, 16)
        for (name, jwe) in v.cases {
            let parts = name.split(separator: "|").map(String.init)
            let plaintext = try CredentialResponseJwe.decrypt(
                jwe, recipient: v.recipient, expected: CredentialResponseEncryptionParams(alg: parts[0], enc: parts[1])
            )
            XCTAssertEqual(String(decoding: plaintext, as: UTF8.self), v.plaintext, name)
        }
    }

    /// ECDH-ES+A192KW: a 24-byte key-encryption key from the Concat KDF, then RFC 3394 unwrap; go-jose vectors.
    func testEcdhEsA192KwOpensWithEveryContentEncryption() throws {
        let v = try vectors()
        for enc in CredentialResponseEncryptionParams.supportedEncs {
            let jwe = try XCTUnwrap(v.cases["ECDH-ES+A192KW|\(enc)"], enc)
            let plaintext = try CredentialResponseJwe.decrypt(
                jwe, recipient: v.recipient, expected: CredentialResponseEncryptionParams(alg: "ECDH-ES+A192KW", enc: enc)
            )
            XCTAssertEqual(String(decoding: plaintext, as: UTF8.self), v.plaintext, enc)
        }
    }

    /// The one that occurs in practice: gdc only advertises ECDH-ES+A256KW.
    func testTheGdcPairEcdhEsA256KwWithA256GcmOpens() throws {
        let v = try vectors()
        let jwe = try XCTUnwrap(v.cases["ECDH-ES+A256KW|A256GCM"])
        let plaintext = try CredentialResponseJwe.decrypt(jwe, recipient: v.recipient)
        XCTAssertEqual(String(decoding: plaintext, as: UTF8.self), v.plaintext)
    }

    func testAnotherRecipientKeyCannotOpenIt() throws {
        let v = try vectors()
        let other = P256.KeyAgreement.PrivateKey()
        for (name, jwe) in v.cases {
            XCTAssertThrowsError(try CredentialResponseJwe.decrypt(jwe, recipient: other), name) { error in
                XCTAssertEqual(error as? CredentialResponseJweError, .authenticationFailed, name)
            }
        }
    }

    func testAJweOtherThanTheNegotiatedPairIsRefusedBeforeItIsOpened() throws {
        let v = try vectors()
        let jwe = try XCTUnwrap(v.cases["ECDH-ES|A256GCM"])
        for wrong in [
            CredentialResponseEncryptionParams(alg: "ECDH-ES+A256KW", enc: "A256GCM"),
            CredentialResponseEncryptionParams(alg: "ECDH-ES", enc: "A128GCM"),
        ] {
            XCTAssertThrowsError(try CredentialResponseJwe.decrypt(jwe, recipient: v.recipient, expected: wrong)) { error in
                guard case CredentialResponseJweError.notNegotiated = error else { return XCTFail("\(error)") }
            }
        }
    }

    /// A flipped bit in any part must fail authentication, not yield wrong plaintext.
    func testTamperingWithAnyPartIsDetected() throws {
        let v = try vectors()
        for name in ["ECDH-ES|A256GCM", "ECDH-ES+A256KW|A256GCM", "ECDH-ES|A128CBC-HS256", "ECDH-ES+A128KW|A256CBC-HS512"] {
            let jwe = try XCTUnwrap(v.cases[name])
            var parts = jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
            for index in 1..<5 where !parts[index].isEmpty {
                var bytes = try XCTUnwrap(CredentialResponseJwe.decode(parts[index]))
                bytes[bytes.count / 2] ^= 0x01
                let original = parts[index]
                parts[index] = CredentialResponseJwe.encode(bytes)
                XCTAssertThrowsError(try CredentialResponseJwe.decrypt(parts.joined(separator: "."), recipient: v.recipient), "\(name) part \(index)")
                parts[index] = original
            }
        }
    }

    func testMalformedInputsAreRefusedNotCrashed() throws {
        let v = try vectors()
        for bad in ["", "a.b.c", "a.b.c.d.e.f", "!!.!!.!!.!!.!!", "e30.e30.e30.e30.e30"] {
            XCTAssertThrowsError(try CredentialResponseJwe.decrypt(bad, recipient: v.recipient), bad)
        }
    }

    func testUnsupportedAlgorithmsAndEncryptionsAreNamed() throws {
        let v = try vectors()
        func compact(_ header: String) -> String {
            "\(CredentialResponseJwe.encode(Data(header.utf8))).AA.AA.AA.AA"
        }
        XCTAssertThrowsError(try CredentialResponseJwe.decrypt(compact(#"{"alg":"RSA-OAEP","enc":"A256GCM"}"#), recipient: v.recipient)) {
            XCTAssertEqual($0 as? CredentialResponseJweError, .unsupportedAlgorithm("RSA-OAEP"))
        }
        XCTAssertThrowsError(try CredentialResponseJwe.decrypt(compact(#"{"alg":"ECDH-ES","enc":"A192GCM"}"#), recipient: v.recipient)) {
            XCTAssertEqual($0 as? CredentialResponseJweError, .unsupportedEncryption("A192GCM"))
        }
        XCTAssertThrowsError(try CredentialResponseJwe.decrypt(compact(#"{"alg":"ECDH-ES","enc":"A256GCM","zip":"DEF"}"#), recipient: v.recipient))
        XCTAssertThrowsError(try CredentialResponseJwe.decrypt(
            compact(#"{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}}"#), recipient: v.recipient
        )) { XCTAssertEqual($0 as? CredentialResponseJweError, .unsupportedCurve) }
    }

    /// RFC 7518 section 4.6.1.1: the ephemeral key is public. A header whose `epk` carries `d` exposes its private half to
    /// the relay, so the response is refused before any key agreement.
    func testAnEphemeralKeyWithAPrivateMemberIsRefused() throws {
        let v = try vectors()
        let jwe = try XCTUnwrap(v.cases["ECDH-ES|A256GCM"])
        var parts = jwe.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        var header = try XCTUnwrap(JSONSerialization.jsonObject(with: try XCTUnwrap(CredentialResponseJwe.decode(parts[0]))) as? [String: Any])
        var epk = try XCTUnwrap(header["epk"] as? [String: Any])
        epk["d"] = "VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"
        header["epk"] = epk
        parts[0] = CredentialResponseJwe.encode(try JSONSerialization.data(withJSONObject: header))
        XCTAssertThrowsError(try CredentialResponseJwe.decrypt(parts.joined(separator: "."), recipient: v.recipient)) {
            guard case .malformed(let why)? = $0 as? CredentialResponseJweError else { return XCTFail("\($0)") }
            XCTAssertTrue(why.contains("private"), why)
        }
    }

    // MARK: - RFC vectors for the primitives

    /// RFC 7518 Appendix C: Concat KDF over an ECDH-ES agreement, A128GCM, apu "Alice", apv "Bob".
    func testRfc7518AppendixCKeyDerivation() throws {
        func key(_ d: String) throws -> P256.KeyAgreement.PrivateKey {
            try P256.KeyAgreement.PrivateKey(rawRepresentation: try XCTUnwrap(CredentialResponseJwe.decode(d)))
        }
        func point(_ x: String, _ y: String) throws -> P256.KeyAgreement.PublicKey {
            try P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + (try XCTUnwrap(CredentialResponseJwe.decode(x))) + (try XCTUnwrap(CredentialResponseJwe.decode(y))))
        }
        let bob = try key("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw")
        let alice = try point("gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0", "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps")
        let z = try bob.sharedSecretFromKeyAgreement(with: alice).withUnsafeBytes { Array($0) }
        let derived = CredentialResponseJwe.concatKdf(z: z, algorithmId: "A128GCM", apu: Data("Alice".utf8), apv: Data("Bob".utf8), keyBits: 128)
        XCTAssertEqual(CredentialResponseJwe.encode(Data(derived)), "VqqN6vgjbSBcIijNcacQGg")
    }

    /// RFC 3394 section 4.1 and 4.6 (128-bit and 256-bit KEKs).
    func testRfc3394KeyUnwrap() throws {
        func hex(_ s: String) -> [UInt8] { stride(from: 0, to: s.count, by: 2).map { UInt8(s[s.index(s.startIndex, offsetBy: $0)..<s.index(s.startIndex, offsetBy: $0 + 2)], radix: 16)! } }
        XCTAssertEqual(
            try AesBlock.keyUnwrap(kek: hex("000102030405060708090A0B0C0D0E0F"), wrapped: hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")),
            hex("00112233445566778899AABBCCDDEEFF")
        )
        XCTAssertEqual(
            try AesBlock.keyUnwrap(
                kek: hex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
                wrapped: hex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
            ),
            hex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F")
        )
        // A wrong key fails the integrity check rather than yielding a key.
        XCTAssertThrowsError(try AesBlock.keyUnwrap(kek: hex("000102030405060708090A0B0C0D0E0E"), wrapped: hex("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")))
    }

    /// RFC 7516 Appendix A.3: A128KW with A128CBC-HS256, a symmetric key. Exercises AES-CBC-HMAC and
    /// the key wrap with an independent, published JWE.
    func testRfc7516AppendixA3CbcHmacContent() throws {
        let kek = [UInt8](try XCTUnwrap(CredentialResponseJwe.decode("GawgguFyGrWKav7AX4VKUg")))
        let encryptedKey = [UInt8](try XCTUnwrap(CredentialResponseJwe.decode("6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ")))
        let cek = try AesBlock.keyUnwrap(kek: kek, wrapped: encryptedKey)
        XCTAssertEqual(cek.count, 32)
        let iv = [UInt8](try XCTUnwrap(CredentialResponseJwe.decode("AxY8DCtDaGlsbGljb3RoZQ")))
        let ciphertext = [UInt8](try XCTUnwrap(CredentialResponseJwe.decode("KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY")))
        let plain = try AesBlock.cbcDecryptPkcs7(key: Array(cek[16...]), iv: iv, ciphertext: ciphertext)
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "Live long and prosper.")
    }

    /// FIPS 197 Appendix C.1 to C.3: the reference AES (used where there is no CommonCrypto) and
    /// CommonCrypto must both give the standard answer.
    func testAesBlockMatchesFips197() throws {
        #if canImport(CommonCrypto)
        throw XCTSkip("the FIPS 197 block cipher is exercised through the key wrap and CBC vectors here; the reference is not compiled on Apple platforms")
        #else
        func hex(_ s: String) -> [UInt8] { stride(from: 0, to: s.count, by: 2).map { UInt8(s[s.index(s.startIndex, offsetBy: $0)..<s.index(s.startIndex, offsetBy: $0 + 2)], radix: 16)! } }
        let plain = hex("00112233445566778899aabbccddeeff")
        XCTAssertEqual(try AesBlock.referenceDecryptBlocks(key: hex("000102030405060708090a0b0c0d0e0f"), data: hex("69c4e0d86a7b0430d8cdb78070b4c55a")), plain)
        XCTAssertEqual(try AesBlock.referenceDecryptBlocks(key: hex("000102030405060708090a0b0c0d0e0f1011121314151617"), data: hex("dda97ca4864cdfe06eaf70a0ec0d7191")), plain)
        XCTAssertEqual(try AesBlock.referenceDecryptBlocks(key: hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), data: hex("8ea2b7ca516745bfeafc49904b496089")), plain)
        #endif
    }

    // MARK: - Credential Response parsing

    func testParseKeepsCredentialsMetadataAndControlFields() throws {
        let plaintext = try vectors().plaintext
        let response = try DecryptedCredentialResponse.parse(Data(plaintext.utf8))
        XCTAssertEqual(response.credentials, ["eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ1cm46ZXVkaTpwaWQ6MSJ9.c2ln~disclosure~"])
        XCTAssertEqual(response.notificationId, "3fwe98js")
        XCTAssertNil(response.transactionId)
        XCTAssertEqual(response.credentialMetadata?["org.siros.secret_seed"]?["org.siros.nym_auth"]?.stringValue, "00112233445566778899aabbccddeeff")
    }

    func testParseDeferredAndObjectCredentials() throws {
        let deferred = try DecryptedCredentialResponse.parse(Data(#"{"transaction_id":"tx","interval":5}"#.utf8))
        XCTAssertEqual(deferred.transactionId, "tx")
        XCTAssertEqual(deferred.interval, 5)
        XCTAssertTrue(deferred.credentials.isEmpty)
        let object = try DecryptedCredentialResponse.parse(Data(#"{"credentials":[{"credential":{"b":1,"a":"x"}}]}"#.utf8))
        XCTAssertEqual(object.credentials, [#"{"a":"x","b":1}"#])
        XCTAssertNil(object.credentialMetadata)
        // `credential_metadata` of any type is kept as received: what it means is the consumer's call.
        let odd = try DecryptedCredentialResponse.parse(Data(#"{"credentials":[{"credential":"c"}],"credential_metadata":[1]}"#.utf8))
        XCTAssertEqual(odd.credentialMetadata, .array([.int(1)]))
    }

    /// The inner `credential` value is what is stored, not the entry that wraps it.
    func testTheInnerCredentialValueIsStored() throws {
        let response = try DecryptedCredentialResponse.parse(Data(#"{"credentials":[{"credential":"one","extra":"x"},{"credential":"two"}]}"#.utf8))
        XCTAssertEqual(response.credentials, ["one", "two"])
    }

    /// Numbers inside an object-valued credential are written as the validated token, not rounded or re-typed.
    func testObjectCredentialsKeepNumbersExactly() throws {
        let plaintext = #"{"credentials":[{"credential":{"big":1e200,"precise":0.1234567890123456789012345678901234567890,"n":-0,"s":"a/b\n\u00e9","l":[1,2.50]}}]}"#
        let response = try DecryptedCredentialResponse.parse(Data(plaintext.utf8))
        let stored = try XCTUnwrap(response.credentials.first)
        XCTAssertTrue(stored.contains("\"big\":1e200"), stored)
        XCTAssertTrue(stored.contains("0.1234567890123456789012345678901234567890"), stored)
        XCTAssertTrue(stored.contains("2.50"), stored)
        XCTAssertTrue(stored.contains("a/b"), "slashes are not escaped")
        // And it is the same document: parsing the stored text gives the original value.
        let original = try StrictJSON.parse(Data(plaintext.utf8))["credentials"]?.arrayValue?.first?["credential"]
        XCTAssertEqual(try StrictJSON.parse(stored), original)
    }

    func testParseRefusesWhatIsNotACredentialResponse() {
        for bad in [
            // Each credentials[] entry must be an object with a `credential` member, never a bare value.
            #"{"credentials":["c"]}"#, #"{"credentials":[null]}"#, #"{"credentials":[["c"]]}"#, #"{"credentials":[{"cred":"c"}]}"#,
            "[]", "not json", "{}", #"{"credentials":[]}"#, #"{"credentials":"x"}"#, #"{"credentials":[{}]}"#,
            #"{"credentials":[{"credential":""}]}"#, #"{"credentials":[{"credential":1}]}"#,
            #"{"credentials":[{"credential":[]}],"notification_id":"n"}"#, #"{"credential":[1]}"#, #"{"transaction_id":1}"#,
            #"{"transaction_id":"t","interval":-1}"#, #"{"credentials":[{"credential":"c"}],"notification_id":7}"#,
            // A duplicate member is ambiguous, so it is refused rather than resolved by order.
            #"{"credentials":[{"credential":"a"}],"credentials":[{"credential":"b"}]}"#,
        ] {
            XCTAssertThrowsError(try DecryptedCredentialResponse.parse(Data(bad.utf8)), bad)
        }
    }
}
