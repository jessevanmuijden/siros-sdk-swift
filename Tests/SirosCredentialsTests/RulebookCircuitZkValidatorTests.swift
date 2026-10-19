// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
#if canImport(CryptoKit)
import CryptoKit
#endif
@testable import SirosCredentials

/// The shared validator vectors (siros-sdk-kotlin spec/circuit-zk-validator-vectors.json, copied
/// byte-for-byte, see circuit-zk-validator-vectors.PROVENANCE.txt) against this SDK's validator.
final class RulebookCircuitZkValidatorTests: XCTestCase {

    private static let vectorsHash = "c75b6e57e70147a0a5184cb35ffaeb32e48bb39989be1b87ce81b6c9d64cda67"

    private struct Fixed: CircuitZkCircuitSource {
        let list: [CircuitZkCircuit]
        func circuits() -> [CircuitZkCircuit] { list }
    }

    private func cases() throws -> [[String: JSONValue]] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "circuit-zk-validator-vectors", withExtension: "json"))
        let data = try Data(contentsOf: url)
        #if canImport(CryptoKit)
        XCTAssertEqual(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(), Self.vectorsHash)
        #endif
        let root = try XCTUnwrap(StrictJSON.parse(data).objectValue)
        return try XCTUnwrap(root["cases"]?.arrayValue).compactMap { $0.objectValue }
    }

    private func plan(_ json: [String: JSONValue]) throws -> CircuitZkPlan {
        let functions = try XCTUnwrap(json["functions"]?.arrayValue).map { item -> CircuitZkFunction in
            let object = item.objectValue ?? [:]
            return CircuitZkFunction(
                id: object["id"]?.stringValue ?? "", handle: object["handle"]?.stringValue ?? "",
                params: object["params"]?.objectValue ?? [:])
        }
        var filter: CircuitZkCircuitFilter?
        if let pairs = json["circuit_filter"]?.arrayValue?.compactMap({ $0.objectValue }) {
            // The vectors list the pairs; the plan keeps the two lists they are made of.
            var systems: [String] = []
            var ids: [String] = []
            for pair in pairs {
                if let system = pair["system"]?.stringValue, !systems.contains(system) { systems.append(system) }
                if let id = pair["circuit_id"]?.stringValue, !ids.contains(id) { ids.append(id) }
            }
            filter = CircuitZkCircuitFilter(proofSystems: systems.isEmpty ? nil : systems, circuitIds: ids)
        }
        return CircuitZkPlan(functions: functions, circuitFilter: filter, raw: json["query"]?.objectValue ?? [:])
    }

    private func validator(_ options: [String: JSONValue]?) -> RulebookCircuitZkValidator {
        let circuits = options?["circuits"]?.arrayValue?.compactMap { $0.objectValue }.map { object in
            CircuitZkCircuit(
                system: object["system"]?.stringValue ?? "", circuitId: object["circuit_id"]?.stringValue ?? "",
                docTypes: Set((object["doc_types"]?.arrayValue ?? []).compactMap { $0.stringValue }),
                functions: object["functions"]?.arrayValue.map { Set($0.compactMap { $0.stringValue }) })
        }
        return RulebookCircuitZkValidator(circuits: circuits.map { Fixed(list: $0) })
    }

    func testEveryVectorGivesItsVerdict() throws {
        let all = try cases()
        XCTAssertGreaterThanOrEqual(all.count, 60)
        for testCase in all {
            let name = testCase["name"]?.stringValue ?? "?"
            let verdict = validator(testCase["options"]?.objectValue).validate(try plan(try XCTUnwrap(testCase["plan"]?.objectValue)))
            let expected = try XCTUnwrap(testCase["verdict"]?.objectValue)
            if expected["ok"] == .bool(true) {
                XCTAssertEqual(verdict, .ok, name)
            } else {
                XCTAssertEqual(verdict, .accessDenied(ruleId: expected["access_denied"]?.stringValue ?? "?"), name)
            }
        }
    }

    func testEveryRuleIdHasAFailingVectorAndTheFileHasPassingOnes() throws {
        let all = try cases()
        let failing = Set(all.compactMap { $0["verdict"]?.objectValue?["access_denied"]?.stringValue })
        let expected: Set<String> = [
            "meta-vct-values-reserved", "holder-binding-false", "function-not-declared", "unknown-function",
            "pseudonym-count", "age-check-count", "pseudonym-config-unsupported", "verifier-context-required",
            "verifier-context-forbidden", "verifier-context-length", "age-check-no-bounds",
            "age-check-bad-date", "age-check-le-before-ge", "age-check-span-short",
        ]
        XCTAssertEqual(failing, expected)
        XCTAssertTrue(all.contains { $0["verdict"]?.objectValue?["ok"] != nil })
    }

    func testALegacyVerifierIdTypeIsAcceptedAndIgnoredWhateverItHolds() {
        let rules = RulebookCircuitZkValidator()
        let legacy: [JSONValue] = [.string("semantic"), .string("x509_hash"), .int(1), .null]
        for value in legacy {
            for config in ["known-offender-matching-ssc", "user-managed-pseudonym-xsite-ssc"] {
                let function = CircuitZkFunction(
                    id: CircuitZkRuleSet.pseudonym, handle: "n",
                    params: ["config": .string(config), "verifier_id_type": value])
                XCTAssertEqual(rules.validate(CircuitZkPlan(functions: [function])), .ok, "\(config) \(value)")
            }
        }
    }

    func testTheRuleSetIsData() {
        let base = CircuitZkRuleSet.rulebookV03()
        let extended = base.withFunction("my_fn", CircuitZkFunctionRules(maxItems: 1, countRuleId: "my-fn-count", rules: [
            CircuitZkFunctionRule(id: "my-fn-needs-x") { function, _ in function.params["x"] != nil },
        ]))
        let validator = RulebookCircuitZkValidator(rules: extended)
        XCTAssertEqual(validator.validate(CircuitZkPlan(functions: [CircuitZkFunction(id: "my_fn", handle: "h", params: ["x": .int(1)])])), .ok)
        XCTAssertEqual(validator.validate(CircuitZkPlan(functions: [CircuitZkFunction(id: "my_fn", handle: "h")])), .accessDenied(ruleId: "my-fn-needs-x"))
        XCTAssertEqual(
            RulebookCircuitZkValidator().validate(CircuitZkPlan(functions: [CircuitZkFunction(id: "my_fn", handle: "h")])),
            .accessDenied(ruleId: "unknown-function"))

        let onlyXsite = CircuitZkRuleSet.rulebookV03(
            pseudonymConfigs: CircuitZkRuleSet.rulebookPseudonymConfigs.filter { $0.id.hasPrefix("user-managed") })
        let ssc = CircuitZkFunction(id: CircuitZkRuleSet.pseudonym, handle: "n", params: ["config": .string("known-offender-matching-ssc")])
        XCTAssertEqual(RulebookCircuitZkValidator(rules: onlyXsite).validate(CircuitZkPlan(functions: [ssc])), .accessDenied(ruleId: "pseudonym-config-unsupported"))
    }

    func testAnEmptyPlanWithNoQueryMembersIsSatisfiable() {
        XCTAssertEqual(RulebookCircuitZkValidator().validate(CircuitZkPlan(functions: [])), .ok)
    }

    func testAMatcherConstrainedCircuitIsNotSubjectToTheLegacyFunctionsCheck() {
        let rules = CircuitZkRuleSet(
            planRules: CircuitZkRuleSet.rulebookV03().planRules,
            functions: ["my_fn": CircuitZkFunctionRules(maxItems: 1, countRuleId: "my-fn-count", rules: [])])
        let plan = CircuitZkPlan(
            functions: [CircuitZkFunction(id: "my_fn", handle: "h")],
            raw: ["meta": .object(["doctype_value": .string("d.1")])])
        func verdict(_ circuit: CircuitZkCircuit) -> CircuitZkVerdict {
            RulebookCircuitZkValidator(rules: rules, circuits: Fixed(list: [circuit])).validate(plan)
        }
        let stale: Set<String> = ["other_fn"]
        XCTAssertEqual(verdict(CircuitZkCircuit(system: "s", circuitId: "c", docTypes: ["d.1"], functions: stale, capabilities: "{}")), .ok)
        XCTAssertEqual(verdict(CircuitZkCircuit(system: "s", circuitId: "c", docTypes: ["d.1"], functions: stale, credentialType: "t")), .ok)
        XCTAssertEqual(verdict(CircuitZkCircuit(system: "s", circuitId: "c", docTypes: ["d.1"], functions: stale)), .accessDenied(ruleId: "function-not-declared"))
        XCTAssertEqual(verdict(CircuitZkCircuit(system: "s", circuitId: "c", docTypes: ["d.1"], functions: ["my_fn"])), .ok)
    }

    func testTheDefaultConfigsAreTheFourRulebookOnes() {
        XCTAssertEqual(
            Set(CircuitZkRuleSet.rulebookPseudonymConfigs.map(\.id)),
            ["known-offender-matching-ssc", "known-offender-matching-psc", "account-recovery-ssc", "user-managed-pseudonym-xsite-ssc"])
    }
}
