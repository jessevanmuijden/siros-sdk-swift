// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import SirosCredentials

/// The shared `zkp_req` conformance vectors of siros-dc-matcher (squash commit
/// 93047bc7b8a22117fbc9b4c8cd59ce7cd742e8d3, PR 50), copied verbatim into Tests/SirosCredentialsTests/ZkpReqVectors
/// and pinned by the matcher's own vector-set digest.
final class ZkpReqVectorsTests: XCTestCase {
    private static let setDigest = "9f482d7a3fb87cb1381d0dfb7a2fc396b6cd3c1eba07c5d76f44e47142b751ac"
    private static let directories = ["zkp_req", "zkp_req_response", "zkp_req_unsat", "proof_time"]

    private func root() throws -> URL {
        try XCTUnwrap(Bundle.module.resourceURL).appendingPathComponent("ZkpReqVectors")
    }

    private func files(_ directory: String) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: try root().appendingPathComponent(directory), includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "json" }
            .sorted { $0.lastPathComponent.utf8.lexicographicallyPrecedes($1.lastPathComponent.utf8) }
    }

    private func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    private func load(_ url: URL) throws -> RawJSON {
        try XCTUnwrap(RawJSON.parse(String(decoding: try Data(contentsOf: url), as: UTF8.self)), url.lastPathComponent)
    }

    /// scripts/vectors_digest.sh: the sha256 of the sha256sum manifest of every `*.json`, `LC_ALL=C` sorted by path.
    func testTheVectorSetIsTheMatchersOwnDigest() throws {
        var lines: [(String, String)] = []
        for directory in Self.directories {
            for file in try files(directory) { lines.append(("\(directory)/\(file.lastPathComponent)", sha256(try Data(contentsOf: file)))) }
        }
        lines.sort { $0.0.utf8.lexicographicallyPrecedes($1.0.utf8) }
        let manifest = lines.map { "\($0.1)  \($0.0)\n" }.joined()
        XCTAssertEqual(sha256(Data(manifest.utf8)), Self.setDigest, "re-copy from siros-dc-matcher and update PROVENANCE")
        XCTAssertEqual(lines.count, 54 + 143 + 43 + 1)
    }

    private func text(_ vector: RawJSON, _ name: String) -> String? {
        if case .string(let t)? = vector.member(name) { return t }
        return nil
    }

    private func queryText(_ vector: RawJSON) -> String { text(vector, "query_text") ?? vector.member("query")?.serialized() ?? "" }
    private func metadataText(_ vector: RawJSON) -> String? { text(vector, "client_metadata_text") ?? vector.member("client_metadata")?.serialized() }

    private func expectedCode(_ vector: RawJSON) -> String? { text(vector.member("expect") ?? .null, "error") }

    private func planJSON(_ plan: ZkpReqPlan) -> JSONValue {
        var filter: [String: JSONValue] = [:]
        if let systems = plan.proofSystems { filter["proof_systems"] = .array(systems.map(JSONValue.string)) }
        if let ids = plan.systemIds { filter["system_ids"] = .array(ids.map(JSONValue.string)) }
        return .object([
            "functions": .array(plan.functions.map { .object(["function_id": .string($0.functionId), "handle": .string($0.handle), "params": .object($0.params)]) }),
            "system_filter": .object(filter), "source_format": .string(plan.sourceFormat),
            "meta_doctype": plan.metaDoctype.map(JSONValue.string) ?? .null, "meta_schema_id": plan.metaSchemaId.map(JSONValue.string) ?? .null,
        ])
    }

    func testEveryPlannerVector() throws {
        var ok = 0, err = 0
        for file in try files("zkp_req") {
            let name = file.lastPathComponent
            let vector = try load(file)
            do {
                let plan = try ZkpReqPlanner.plan(credentialQuery: queryText(vector), clientMetadata: metadataText(vector))
                let expected = try XCTUnwrap(vector.member("expect")?.member("plan"), "\(name): planned but expected an error")
                XCTAssertEqual(planJSON(plan), try StrictJSON.parse(expected.serialized()), name)
                if let query = vector.member("query") { XCTAssertEqual(plan.raw, try StrictJSON.parse(query.serialized()), "\(name): raw is the query unchanged") }
                ok += 1
            } catch let error as ZkpReqInvalidRequest {
                XCTAssertEqual(error.code, expectedCode(vector), name)
                err += 1
            }
        }
        XCTAssertEqual(ok, 13)
        XCTAssertEqual(err, 41)
    }

    func testEveryUnsatisfiableVector() throws {
        var ok = 0, err = 0
        for file in try files("zkp_req_unsat") {
            let name = file.lastPathComponent
            let vector = try load(file)
            let plan = try ZkpReqPlanner.plan(credentialQuery: queryText(vector), clientMetadata: metadataText(vector))
            if let rule = ZkpReqUnsatisfiable.check(plan) {
                XCTAssertEqual(rule.code, expectedCode(vector), name)
                err += 1
            } else {
                XCTAssertEqual(vector.member("expect")?.member("satisfiable").map { if case .bool(true) = $0 { return true } else { return false } }, true, name)
                ok += 1
            }
        }
        XCTAssertEqual(ok, 10)
        XCTAssertEqual(err, 33)
    }

    func testEveryResponseVector() throws {
        var ok = 0, err = 0
        var codes = Set<String>()
        for file in try files("zkp_req_response") {
            let name = file.lastPathComponent
            let vector = try load(file)
            let plan = try ZkpReqPlanner.plan(credentialQuery: queryText(vector), clientMetadata: metadataText(vector))
            let token = text(vector, "vp_token_text") ?? vector.member("vp_token")?.serialized() ?? ""
            do {
                try ZkpReqResponseValidator.validate(plan, vpToken: token)
                if case .bool(true)? = vector.member("expect")?.member("valid") { ok += 1 } else { XCTFail("\(name): accepted but expected \(String(describing: vector.member("expect")))") }
            } catch let error as ZkpReqResponseError {
                XCTAssertEqual(error.code, expectedCode(vector), name)
                codes.insert(error.code)
                err += 1
            }
        }
        XCTAssertEqual(ok + err, 143)
        XCTAssertGreaterThanOrEqual(ok, 10)
        XCTAssertGreaterThanOrEqual(codes.count, 30, "\(codes.sorted())")
    }

    func testProofTimeVectors() throws {
        let vector = try load(try root().appendingPathComponent("proof_time/proof_time.json"))
        func list(_ name: String) -> [RawJSON] { if case .array(let items)? = vector.member(name) { return items } else { return [] } }
        func int(_ value: RawJSON?) -> Int64 { if case .number(let t)? = value { return Int64(t) ?? .min } else { return .min } }
        for item in list("render") { XCTAssertEqual(try ZkpReqProofTime.render(seconds: int(item.member("secs"))), text(item, "text")) }
        for item in list("render_errors") {
            XCTAssertThrowsError(try ZkpReqProofTime.render(seconds: int(item.member("secs")))) { XCTAssertEqual(($0 as? ZkpReqProofTime.Invalid)?.code, self.text(item, "error")) }
        }
        for item in list("parse_ok") { XCTAssertEqual(try ZkpReqProofTime.parse(text(item, "text") ?? ""), int(item.member("secs"))) }
        for item in list("parse_errors") {
            XCTAssertThrowsError(try ZkpReqProofTime.parse(text(item, "text") ?? ""), text(item, "text") ?? "") {
                XCTAssertEqual(($0 as? ZkpReqProofTime.Invalid)?.code, self.text(item, "error"), self.text(item, "text") ?? "")
            }
        }
        XCTAssertEqual(list("render").count, 29)
        XCTAssertEqual(list("parse_errors").count, 22)
        for item in list("tolerance") {
            let now = int(item.member("now_secs")), skew = int(item.member("skew_secs")), maxAge = int(item.member("max_age_secs"))
            let result = Result { try ZkpReqProofTime.checkTolerance(self.text(item, "proof_time") ?? "", now: now, skew: skew, maxAge: maxAge) }
            let expect = text(item, "expect") ?? ""
            if expect == "ok" { XCTAssertNoThrow(try result.get(), self.text(item, "name") ?? "") } else {
                XCTAssertThrowsError(try result.get(), text(item, "name") ?? "") { XCTAssertEqual(($0 as? ZkpReqProofTime.Invalid)?.code, expect, self.text(item, "name") ?? "") }
            }
        }
        XCTAssertEqual(list("tolerance").count, 12)
    }

    func testThePrefixedVerifierId() {
        XCTAssertEqual(ZkpReqVerifierId.x509SanDns("verifier.example"), "x509_san_dns:verifier.example")
        XCTAssertEqual(ZkpReqVerifierId.x509SanDns("x509_san_dns:verifier.example"), "x509_san_dns:verifier.example")
        XCTAssertEqual(ZkpReqVerifierId.semantic("EU:1"), "semantic_id:EU:1")
        // verifier_input is SHA-256 of the PREFIXED string, never of the bare name.
        let prefixed = ZkpReqVerifierId.verifierInput("x509_san_dns:verifier.example").map { String(format: "%02x", $0) }.joined()
        let bare = ZkpReqVerifierId.verifierInput("verifier.example").map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(prefixed, "6eae85a0b2dfcd7d8b716291e54a004da798f93a26a248c265becd33a04a6bab")
        XCTAssertNotEqual(prefixed, bare)
    }

    // MARK: building

    private func normativePlan() throws -> ZkpReqPlan {
        let query = """
        {"id":"nym_attestation","format":"zkp_req","meta":{"source_format":"mso_mdoc","doctype_value":"eu.europa.ec.eudi.nym_auth.1"},
         "_req":[{"fn_id":"pseudonym","return":"nym","params":{"config":"known-offender-matching-ssc","ver":1,"prf":"sha-256"}},
                 {"fn_id":"age_check","return":"age","params":{"ge":"2008-10-10","le":"2013-10-09"}}]}
        """
        let metadata = #"{"vp_formats_supported":{"zkp_req":{"system_id_values":["urn:circuits:longfellow:nym_auth:v1"]}}}"#
        return try ZkpReqPlanner.plan(credentialQuery: query, clientMetadata: metadata)
    }

    private func build(proofTime: String? = "2026-10-20T12:00:00Z", keys: [[UInt8]] = [[1, 2, 3]], pseudonym: [UInt8] = Array(repeating: 7, count: 32)) throws -> String {
        let plan = try normativePlan()
        let presentation = ZkpReqPresentationBuilder.encode(
            systemId: "urn:circuits:longfellow:nym_auth:v1", proof: [9, 9], issuerKeySet: keys, proofTime: proofTime,
            results: [("nym", .pseudonym(pseudonym)), ("age", .predicateSatisfied)])
        return try ZkpReqPresentationBuilder.vpToken(for: plan, presentations: [presentation])
    }

    func testABuiltPresentationPassesTheValidatorAndRoundTrips() throws {
        let token = try build()
        let parsed = try ZkpReqResponseValidator.parse(try normativePlan(), vpToken: token)
        XCTAssertEqual(parsed.count, 1)
        XCTAssertEqual(parsed[0].proofTime, "2026-10-20T12:00:00Z")
        XCTAssertEqual(parsed[0].proofTime?.utf8.count, 20)
        XCTAssertEqual(parsed[0].issuerKeySet, [[1, 2, 3]])
        XCTAssertEqual(parsed[0].results.map(\.handle), ["nym", "age"])
        XCTAssertFalse("\(parsed[0])".contains("007"), "description is redacted")
    }

    func testLargeProofsUseTheFourByteLengthHeader() throws {
        let plan = try normativePlan()
        let proof = [UInt8](repeating: 0xAB, count: 70_000)
        let presentation = ZkpReqPresentationBuilder.encode(
            systemId: "urn:circuits:longfellow:nym_auth:v1", proof: proof, issuerKeySet: [[1]], proofTime: "2026-10-20T12:00:00Z",
            results: [("nym", .pseudonym(Array(repeating: 7, count: 32))), ("age", .predicateSatisfied)])
        let parsed = try ZkpReqResponseValidator.parse(plan, vpToken: try ZkpReqPresentationBuilder.vpToken(for: plan, presentations: [presentation]))
        XCTAssertEqual(parsed[0].proof.count, 70_000)
    }

    func testAnInvalidPresentationIsNeverReturned() throws {
        func code(_ body: () throws -> String) -> String? {
            do { _ = try body(); return nil } catch let e as ZkpReqPresentationBuilder.Refusal { if case .invalid(let c) = e { return c.code } else { return nil } } catch { return "other" }
        }
        XCTAssertEqual(code { try self.build(proofTime: nil) }, "proof_time_missing", "mso_mdoc requires proof_time")
        XCTAssertEqual(code { try self.build(proofTime: "2026-10-20T12:00:00.000Z") }, "proof_time_form")
        XCTAssertEqual(code { try self.build(keys: []) }, "issuer_key_set_empty")
        XCTAssertEqual(code { try self.build(keys: Array(repeating: [1], count: 9)) }, "issuer_key_set_too_many")
        XCTAssertEqual(code { try self.build(keys: [[UInt8](repeating: 1, count: 4097)]) }, "issuer_key_too_large")
        XCTAssertEqual(code { try self.build(pseudonym: [1]) }, "pseudonym_wrong_length")
        XCTAssertNotNil(try? self.build(keys: Array(repeating: [UInt8](repeating: 1, count: 4096), count: 8)), "limits are inclusive")
    }
}
