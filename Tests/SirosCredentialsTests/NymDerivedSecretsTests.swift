// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@preconcurrency import SwiftCBOR
@testable import SirosCredentials

private func hex(_ text: String) -> [UInt8] {
    let chars = Array(text.utf8)
    func nibble(_ c: UInt8) -> UInt8 { c <= 0x39 ? c - 0x30 : c - 0x61 + 10 }
    return stride(from: 0, to: chars.count, by: 2).map { (nibble(chars[$0]) << 4) | nibble(chars[$0 + 1]) }
}

private func toHex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

/// A shared vector file: parsed, and (where CryptoKit is available) checked to be the verbatim copy.
private func vectorFile(_ name: String, hash: String, file: StaticString = #filePath, line: UInt = #line) throws -> [String: JSONValue] {
    let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json"), file: file, line: line)
    let data = try Data(contentsOf: url)
    XCTAssertEqual(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(), hash,
                   "re-copy \(name).json from siros-sdk-kotlin spec/ and update PROVENANCE", file: file, line: line)
    return try XCTUnwrap(StrictJSON.parse(data).objectValue, file: file, line: line)
}

final class NymPseudonymTests: XCTestCase {
    private func vectors() throws -> [String: JSONValue] {
        try vectorFile("nym-pseudonym-vectors", hash: "006bc11a79b2bf43dbf2abbdd6d4b1fae5baba94089f5e41c22526ae9649906e")
    }

    func testEveryVector() throws {
        let all = try XCTUnwrap(vectors()["vectors"]?.arrayValue)
        XCTAssertEqual(all.count, 23)
        // The archive reference value (zk-cred-vega pseudonym.json) for the PREFIXED verifier id is among them.
        XCTAssertTrue(all.contains { $0.objectValue?["expected_hex"]?.stringValue?.hasPrefix("155f433796d1f282") == true })
        for item in all {
            let v = try XCTUnwrap(item.objectValue)
            let name = v["name"]?.stringValue ?? "?"
            // A `verifier_id_type` in the vectors is informational: the derivation never sees it.
            let derived = try NymPseudonym.derive(
                config: try XCTUnwrap(v["config"]?.stringValue),
                seed: hex(try XCTUnwrap(v["seed_hex"]?.stringValue)),
                proverInput: v["prover_input_hex"]?.stringValue.map(hex),
                verifierId: v["verifier_id"]?.stringValue,
                verifierContext: v["verifier_context"]?.stringValue)
            XCTAssertEqual(toHex(derived), v["expected_hex"]?.stringValue, name)
        }
    }

    func testEveryRejection() throws {
        let all = try XCTUnwrap(vectors()["rejections"]?.arrayValue)
        XCTAssertEqual(all.count, 16)
        for item in all {
            let v = try XCTUnwrap(item.objectValue)
            let name = v["name"]?.stringValue ?? "?"
            do {
                _ = try NymPseudonym.derive(
                    config: try XCTUnwrap(v["config"]?.stringValue),
                    seed: hex(try XCTUnwrap(v["seed_hex"]?.stringValue)),
                    proverInput: v["prover_input_hex"]?.stringValue.map(hex),
                    verifierId: v["verifier_id"]?.stringValue,
                    verifierContext: v["verifier_context"]?.stringValue)
                XCTFail("\(name): must be refused")
            } catch let error as NymPseudonymError {
                let kind: String
                switch error {
                case .unknownConfig: kind = "UNKNOWN_CONFIG"
                case .missingInput: kind = "MISSING_INPUT"
                case .unusedInput: kind = "UNUSED_INPUT"
                case .wrongSeedLength: kind = "WRONG_SEED_LENGTH"
                }
                XCTAssertEqual(kind, v["error"]?.stringValue, name)
            }
        }
    }

    func testDescribeAndTable() {
        XCTAssertEqual(
            NymPseudonym.configIds,
            ["known-offender-matching-ssc", "known-offender-matching-psc", "account-recovery-ssc", "user-managed-pseudonym-xsite-ssc"])
        XCTAssertEqual(
            NymPseudonym.describe(config: "account-recovery-ssc"),
            NymConfigInfo(seedKind: .secret, userValue: false, verifierId: true, verifierContext: true))
        XCTAssertEqual(NymPseudonym.describe(config: "known-offender-matching-psc")?.seedKind, .private)
        XCTAssertNil(NymPseudonym.describe(config: "nope"))
    }

    func testErrorsNeverCarrySeedMaterial() {
        let seed = hex("00112233445566778899aabbccddeeff")
        do { _ = try NymPseudonym.derive(config: "nope", seed: seed) } catch {
            XCTAssertFalse("\(error)".contains("00112233"))
        }
    }
}

final class PrivateSeedTests: XCTestCase {
    private static let derivedHash = "fdcdb5f01be080adaed1dc7a9f7c4bc9c9080322a92f764bc6a4b0a961209d2c"

    private func file() throws -> [String: JSONValue] {
        try vectorFile("derived-secrets", hash: Self.derivedHash)
    }

    private func field(_ v: [String: JSONValue], _ name: String) -> String {
        if case .int(let n)? = v["\(name)_fill"] { return String(repeating: "a", count: Int(n)) }
        return v[name]?.stringValue ?? ""
    }

    private func seeds(_ v: [String: JSONValue]) -> PrivateSeed {
        PrivateSeed(root: FixedRootSecret(key: hex(v["root_hex"]?.stringValue ?? "")))
    }

    func testEveryVectorGivesItsSeedAndPsc() throws {
        let all = try XCTUnwrap(file()["vectors"]?.arrayValue)
        XCTAssertEqual(all.count, 11)
        for item in all {
            let v = try XCTUnwrap(item.objectValue)
            let name = v["name"]?.stringValue ?? "?"
            let type = field(v, "credential_type"), issuer = field(v, "issuer")
            XCTAssertEqual(toHex(try seeds(v).derive(credentialType: type, issuer: issuer)), v["seed_hex"]?.stringValue, name)
            XCTAssertEqual(toHex(try seeds(v).psc(credentialType: type, issuer: issuer)), v["psc_hex"]?.stringValue, name)
            XCTAssertTrue(try seeds(v).matchesCommitment(
                credentialType: type, issuer: issuer, psc: hex(try XCTUnwrap(v["psc_hex"]?.stringValue))), name)
        }
    }

    func testRefusedInputsDeriveNothing() throws {
        let all = try XCTUnwrap(file()["refused"]?.arrayValue)
        XCTAssertEqual(all.count, 4)
        for item in all {
            let v = try XCTUnwrap(item.objectValue)
            XCTAssertThrowsError(try seeds(v).derive(credentialType: field(v, "credential_type"), issuer: field(v, "issuer")), v["name"]?.stringValue ?? "?")
            XCTAssertThrowsError(try seeds(v).psc(credentialType: field(v, "credential_type"), issuer: field(v, "issuer")))
        }
    }

    func testMustDifferPairsGiveDifferentSeeds() throws {
        let f = try file()
        var byName: [String: [String: JSONValue]] = [:]
        for item in try XCTUnwrap(f["vectors"]?.arrayValue) {
            if let o = item.objectValue, let name = o["name"]?.stringValue { byName[name] = o }
        }
        let pairs = try XCTUnwrap(f["must_differ"]?.arrayValue)
        XCTAssertEqual(pairs.count, 5)
        for pair in pairs {
            let names = try XCTUnwrap(pair.arrayValue).compactMap { $0.stringValue }
            XCTAssertEqual(names.count, 2)
            let a = try XCTUnwrap(byName[names[0]]), b = try XCTUnwrap(byName[names[1]])
            XCTAssertNotEqual(a["seed_hex"], b["seed_hex"], "\(names)")
        }
    }

    func testBoundaryAndEncoding() throws {
        let seeds = PrivateSeed(root: FixedRootSecret(key: (0..<32).map { UInt8($0) }))
        XCTAssertNoThrow(try seeds.derive(credentialType: String(repeating: "a", count: 65535), issuer: "i"))
        XCTAssertThrowsError(try seeds.derive(credentialType: String(repeating: "a", count: 65536), issuer: "i")) {
            XCTAssertEqual($0 as? PrivateSeedError, .fieldTooLong)
        }
        XCTAssertThrowsError(try seeds.derive(credentialType: "", issuer: "i")) { XCTAssertEqual($0 as? PrivateSeedError, .emptyField) }
        // lp(): 2-byte big-endian length, so "ab"+"c" and "a"+"bc" differ.
        XCTAssertEqual(
            try PrivateSeed.info(credentialType: "ab", issuer: "c"),
            Array("org.siros.private_seed/v2".utf8) + [0, 2, 0x61, 0x62, 0, 1, 0x63])
        // A multi-byte type counts BYTES, not characters.
        XCTAssertEqual(try PrivateSeed.info(credentialType: "\u{e9}", issuer: "i").dropFirst(25).prefix(4), [0, 2, 0xC3, 0xA9])
    }

    func testMatchesCommitmentFailsClosed() throws {
        let seeds = PrivateSeed(root: FixedRootSecret(key: (0..<32).map { UInt8($0) }))
        let psc = try seeds.psc(credentialType: "t", issuer: "i")
        XCTAssertTrue(try seeds.matchesCommitment(credentialType: "t", issuer: "i", psc: psc))
        XCTAssertFalse(try seeds.matchesCommitment(credentialType: "u", issuer: "i", psc: psc))
        XCTAssertFalse(try seeds.matchesCommitment(credentialType: "t", issuer: "j", psc: psc))
        XCTAssertFalse(try seeds.matchesCommitment(credentialType: "t", issuer: "i", psc: Array(psc.dropLast())))
        XCTAssertFalse(try seeds.matchesCommitment(credentialType: "t", issuer: "i", psc: []))
        var flipped = psc
        flipped[0] ^= 1
        XCTAssertFalse(try seeds.matchesCommitment(credentialType: "t", issuer: "i", psc: flipped))
    }

    func testWipeZeroesAndConstantTimeEqual() {
        var bytes: [UInt8] = [1, 2, 3]
        SecretBytes.wipe(&bytes)
        XCTAssertEqual(bytes, [0, 0, 0])
        XCTAssertTrue(SecretBytes.constantTimeEqual([1, 2], [1, 2]))
        XCTAssertFalse(SecretBytes.constantTimeEqual([1, 2], [1, 3]))
        XCTAssertFalse(SecretBytes.constantTimeEqual([1, 2], [1]))
    }
}

final class SecretSeedCommitmentTests: XCTestCase {
    func testEveryVectorOpens() throws {
        let file = try vectorFile("secret-seed-commitment-vectors", hash: "1b03550a7f6767a446a59f20f0a38f19e54bfde6e5c0ce52566b7d0bfe8ab5dd")
        for item in try XCTUnwrap(file["vectors"]?.arrayValue) {
            let v = try XCTUnwrap(item.objectValue)
            XCTAssertTrue(
                SecretSeedCommitment.opens(seed: hex(v["seed_hex"]?.stringValue ?? ""), ssc: hex(v["ssc_hex"]?.stringValue ?? "")),
                v["name"]?.stringValue ?? "?")
        }
        let rejections = try XCTUnwrap(file["rejections"]?.arrayValue)
        XCTAssertEqual(rejections.count, 14)
        for item in rejections {
            let v = try XCTUnwrap(item.objectValue)
            XCTAssertFalse(
                SecretSeedCommitment.opens(seed: hex(v["seed_hex"]?.stringValue ?? ""), ssc: hex(v["ssc_hex"]?.stringValue ?? "")),
                v["name"]?.stringValue ?? "?")
        }
    }

    func testSeedFromHexIsStrict() {
        XCTAssertEqual(SecretSeedCommitment.seed(fromHex: "00112233445566778899aabbccddeeff"), hex("00112233445566778899aabbccddeeff"))
        for bad in ["00112233445566778899AABBCCDDEEFF", "0011223344556677", "00112233445566778899aabbccddeeff00",
                    "0x112233445566778899aabbccddeeff", " 0112233445566778899aabbccddeeff", "", "0011223344556677889gaabbccddeeff"] {
            XCTAssertNil(SecretSeedCommitment.seed(fromHex: bad), bad)
        }
    }

    // MARK: ssc from credentials

    private let sscBytes = hex("a8faed6abbf35c12a4b26e40f6feb19d736d90045c83b9f9a31f638d323e6811")

    private func item(_ name: String, _ value: CBOR) -> NamespaceItem {
        NamespaceItem(item: IssuerSignedItem(digestId: 1, random: [], elementIdentifier: name, elementValue: value), original: .null)
    }

    private func document(_ namespaces: [String: [NamespaceItem]]) -> DocumentMdoc {
        DocumentMdoc(docType: "eu.europa.ec.eudi.nym_auth.1", issuerSigned: IssuerSignedMdoc(nameSpaces: namespaces, issuerAuth: .null))
    }

    func testMdocSscIsReadOnlyFromTheDoctypeNamespaceAndOnlyWhenWellFormed() {
        let docType = "eu.europa.ec.eudi.nym_auth.1"
        XCTAssertEqual(SecretSeedCommitment.ssc(of: document([docType: [item("ssc", .byteString(sscBytes))]])), sscBytes)
        // another namespace is never consulted
        XCTAssertNil(SecretSeedCommitment.ssc(of: document(["other": [item("ssc", .byteString(sscBytes))]])))
        // duplicated, wrong type, wrong length
        XCTAssertNil(SecretSeedCommitment.ssc(of: document([docType: [item("ssc", .byteString(sscBytes)), item("ssc", .byteString(sscBytes))]])))
        XCTAssertNil(SecretSeedCommitment.ssc(of: document([docType: [item("ssc", .utf8String("x"))]])))
        XCTAssertNil(SecretSeedCommitment.ssc(of: document([docType: [item("ssc", .byteString(Array(sscBytes.dropLast())))]])))
        XCTAssertNil(SecretSeedCommitment.ssc(of: document([docType: []])))
    }

    private func b64url(_ text: String) -> String {
        Data(text.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    /// A compact SD-JWT whose payload references `disclosures` by digest (or not).
    private func sdJwt(disclosures: [String], referenced: [String]? = nil, payloadExtra: String = "") -> String {
        let digests = (referenced ?? disclosures).map { SecretSeedCommitment.disclosureDigest($0) }
        let payload = "{\"_sd\":[\(digests.map { "\"\($0)\"" }.joined(separator: ","))]\(payloadExtra)}"
        return ([b64url("{\"alg\":\"ES256\"}") + "." + b64url(payload) + ".sig"] + disclosures).joined(separator: "~") + "~"
    }

    private func sscDisclosure(_ value: String) -> String { b64url("[\"salt\",\"ssc\",\"\(value)\"]") }

    func testSdJwtSscIsBoundToTheSignedPayloadAndStrict() {
        let hexValue = "a8faed6abbf35c12a4b26e40f6feb19d736d90045c83b9f9a31f638d323e6811"
        let good = sscDisclosure(hexValue)
        XCTAssertEqual(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [good])), sscBytes)
        // not referenced from the signed _sd
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [good], referenced: [])))
        // also present in the clear
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [good], payloadExtra: ",\"ssc\":\"\(hexValue)\"")))
        // duplicated
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [good, sscDisclosure(hexValue.replacingOccurrences(of: "a", with: "b"))])))
        // not 64 lowercase hex
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [sscDisclosure(hexValue.uppercased())])))
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [sscDisclosure(String(hexValue.dropLast(2)))])))
        // a same-named claim inside a nested object is a different claim: only the top-level one counts
        let nested = sscDisclosure(String(repeating: "c", count: 64))
        let nestedPayload = "{\"_sd\":[\"\(SecretSeedCommitment.disclosureDigest(good))\"],\"profile\":{\"_sd\":[\"\(SecretSeedCommitment.disclosureDigest(nested))\"]}}"
        let withNested = ([b64url("{\"alg\":\"ES256\"}") + "." + b64url(nestedPayload) + ".sig", good, nested]).joined(separator: "~") + "~"
        XCTAssertEqual(SecretSeedCommitment.sscOfSdJwt(withNested), sscBytes)
        // the digest algorithm: absent or sha-256 only; anything else fails closed
        XCTAssertEqual(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [good], payloadExtra: ",\"_sd_alg\":\"sha-256\"")), sscBytes)
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [good], payloadExtra: ",\"_sd_alg\":\"sha-512\"")))
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [good], payloadExtra: ",\"_sd_alg\":5")))
        // a repeated payload member is ambiguous and refused, in either order (a lenient parser keeps the last one)
        let good2 = SecretSeedCommitment.disclosureDigest(good)
        func raw(_ payload: String) -> String { ([b64url("{\"alg\":\"ES256\"}") + "." + b64url(payload) + ".sig", good]).joined(separator: "~") + "~" }
        XCTAssertEqual(SecretSeedCommitment.sscOfSdJwt(raw("{\"_sd\":[\"\(good2)\"]}")), sscBytes, "the single-member form still works")
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(raw("{\"_sd\":[\"\(good2)\"],\"_sd\":[]}")), "conflicting _sd, referencing first")
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(raw("{\"_sd\":[],\"_sd\":[\"\(good2)\"]}")), "conflicting _sd, referencing last")
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(raw("{\"_sd\":[\"\(good2)\"],\"_sd_alg\":\"sha-512\",\"_sd_alg\":\"sha-256\"}")))
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(raw("{\"_sd\":[\"\(good2)\"],\"_sd_alg\":\"sha-256\",\"_sd_alg\":\"sha-512\"}")))
        // none
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt(sdJwt(disclosures: [])))
        XCTAssertNil(SecretSeedCommitment.sscOfSdJwt("garbage"))
    }
}
