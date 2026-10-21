// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
#if canImport(CryptoKit)
import CryptoKit
#endif
@testable import SirosCredentials

/// The shared circuit_zk consent vectors (siros-sdk-kotlin spec/circuit-zk-consent-vectors.json,
/// copied byte-for-byte, see circuit-zk-consent-vectors.PROVENANCE.txt): the consent builder, the
/// registry-driven local pre-check and the cross-query merge, against this SDK.
final class PresentationConsentTests: XCTestCase {

    private static let vectorsHash = "9693823c5cdd57750f58f9d9124c1c19f45280ca7a2d0973a4d52c53960a2fcf"

    private func vectors() throws -> [String: JSONValue] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "circuit-zk-consent-vectors", withExtension: "json"))
        let data = try Data(contentsOf: url)
        #if canImport(CryptoKit)
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        XCTAssertEqual(digest, Self.vectorsHash, "re-copy from siros-sdk-kotlin spec/ and update PROVENANCE")
        #endif
        return try XCTUnwrap(StrictJSON.parse(data).objectValue)
    }

    /// The registry is DATA in the vector file: nothing here hard-codes a function.
    private func registry(_ v: [String: JSONValue]) throws -> PredicateFunctions {
        PredicateFunctions(try XCTUnwrap(v["function_registry"]?.arrayValue).map { item in
            let o = item.objectValue ?? [:]
            let claim = o["claim"]?.objectValue ?? [:]
            let source: PredicateFunction.ClaimSource = claim["param"] != nil
                ? .param : .fixed((claim["path"]?.arrayValue ?? []).compactMap { $0.stringValue })
            let comparisons = (o["comparisons"]?.objectValue ?? [:]).map { ($0.key, $0.value.stringValue ?? "") }
            return PredicateFunction(
                id: o["id"]?.stringValue ?? "", claim: source,
                valueType: PredicateValueType(rawValue: o["value_type"]?.stringValue ?? "") ?? .string,
                comparisons: Self.ordered(comparisons, in: o["comparisons"]),
                minSpan: o["min_span"].flatMap { if case .int(let n) = $0 { return Int(n) } else { return nil } },
                ageSpecialisation: o["age_specialisation"] == .bool(true))
        })
    }

    /// Comparison order is the file's order (display order); a dictionary lost it, so read the keys in order.
    private static func ordered(_ pairs: [(String, String)], in raw: JSONValue?) -> [PredicateFunction.Comparison] {
        let order = Self.keyOrder[raw?.objectValue?.keys.sorted().joined(separator: ",") ?? ""] ?? pairs.map(\.0).sorted()
        return order.compactMap { key in
            pairs.first { $0.0 == key }.flatMap { PredicateOp(rawValue: $0.1) }.map { PredicateFunction.Comparison(param: key, op: $0) }
        }
    }

    /// The registry's declared order for each comparison-key set (JSON objects are unordered once parsed).
    private static let keyOrder: [String: [String]] = [
        "ge,le": ["ge", "le"],
        "eq,ge,gt,in,le,lt,ne": ["eq", "ne", "lt", "le", "gt", "ge", "in"],
        "gt,lt": ["gt", "lt"],
        "eq,in,ne": ["eq", "ne", "in"],
        "eq,ge,le": ["ge", "le", "eq"],
        "eq": ["eq"],
    ]

    func testEveryConsentCase() throws {
        let v = try vectors()
        let registry = try registry(v)
        let cases = try XCTUnwrap(v["cases"]?.arrayValue)
        XCTAssertGreaterThanOrEqual(cases.count, 72)
        for item in cases {
            let testCase = try XCTUnwrap(item.objectValue)
            let name = testCase["name"]?.stringValue ?? "?"
            let input = try XCTUnwrap(testCase["input"]?.objectValue, name)
            let built = try Self.build(input: input, today: try XCTUnwrap(testCase["today"]?.stringValue), registry: registry)
            let expected = try XCTUnwrap(testCase["expected"]?.objectValue, name)
            if expected["refused"] == .bool(true) {
                XCTAssertNil(built, "\(name): must be refused")
            } else {
                XCTAssertEqual(built, try Self.expectedRequest(try XCTUnwrap(expected["request"]?.objectValue)), name)
            }
        }
    }

    func testVerifierIdShortening() throws {
        let cases = try XCTUnwrap(vectors()["verifier_id_shortening"]?.arrayValue)
        XCTAssertEqual(cases.count, 5)
        for item in cases {
            let o = try XCTUnwrap(item.objectValue)
            XCTAssertEqual(PresentationConsentRequest.shortened(verifierId: o["id"]?.stringValue ?? ""), o["display"]?.stringValue)
        }
    }

    func testCombinedPredicateBounds() throws {
        let v = try vectors()
        let registry = try registry(v)
        let cases = try XCTUnwrap(v["combined_predicate_bounds"]?.arrayValue)
        XCTAssertEqual(cases.count, 18)
        for item in cases {
            let o = try XCTUnwrap(item.objectValue)
            let plans = try XCTUnwrap(o["plans"]?.arrayValue).map { try Self.plan($0) }
            XCTAssertEqual(registry.combinedBoundsOk(plans: plans), o["expected_ok"] == .bool(true), o["name"]?.stringValue ?? "?")
        }
    }

    func testPrecheck() throws {
        let v = try vectors()
        let registry = try registry(v)
        let cases = try XCTUnwrap(v["precheck"]?.arrayValue)
        XCTAssertEqual(cases.count, 22)
        for item in cases {
            let o = try XCTUnwrap(item.objectValue)
            let functions = try Self.plan(try XCTUnwrap(o["functions"]))
            let lookups = try XCTUnwrap(o["claims"]?.arrayValue).map { value -> PredicateClaimLookup in
                let c = value.objectValue ?? [:]
                switch c["lookup"]?.stringValue {
                case "absent": return .absent
                case "unsupported": return .unsupported
                default:
                    return .found(type: PredicateValueType(rawValue: c["type"]?.stringValue ?? "") ?? .string, text: c["text"]?.stringValue ?? "")
                }
            }
            XCTAssertEqual(registry.precheck(functions: functions, lookups: lookups), o["expected"] == .bool(true), o["name"]?.stringValue ?? "?")
        }
    }

    /// The shared precheck vectors do not pin the strict ordering operators at their boundary.
    func testPrecheckStrictOrderingAtTheBoundary() {
        let registry = PredicateFunctions([
            PredicateFunction(id: "n", claim: .param, valueType: .number,
                              comparisons: [.init(param: "gt", op: .gt), .init(param: "lt", op: .lt)]),
            PredicateFunction(id: "d", claim: .param, valueType: .date, comparisons: [.init(param: "lt", op: .lt), .init(param: "gt", op: .gt)]),
        ])
        func holds(_ id: String, _ params: [String: JSONValue], _ type: PredicateValueType, _ text: String) -> Bool {
            registry.precheck(functions: [CircuitZkFunction(id: id, handle: "h", params: params.merging(["claim": .string("c")]) { a, _ in a })],
                              lookups: [.found(type: type, text: text)])
        }
        XCTAssertFalse(holds("n", ["lt": .int(10)], .number, "10"))
        XCTAssertTrue(holds("n", ["lt": .int(10)], .number, "9.99"))
        XCTAssertFalse(holds("n", ["gt": .int(10)], .number, "10"))
        XCTAssertFalse(holds("d", ["lt": .string("2024-03-01")], .date, "2024-03-01"))
        XCTAssertTrue(holds("d", ["lt": .string("2024-03-01")], .date, "2024-02-29"))
        XCTAssertFalse(holds("d", ["gt": .string("2024-03-01")], .date, "2024-03-01"))
    }

    // Copilot review: numeric exactness and the lookup count.
    private let numbers = PredicateFunctions([
        PredicateFunction(id: "n", claim: .param, valueType: .number,
                          comparisons: [.init(param: "in", op: .in), .init(param: "ge", op: .ge), .init(param: "le", op: .le)], minSpan: 10),
    ])

    private func n(_ params: [String: JSONValue]) -> CircuitZkFunction {
        CircuitZkFunction(id: "n", handle: "h", params: params.merging(["claim": .string("c")]) { a, _ in a })
    }

    private func parse(_ text: String) throws -> JSONValue { try StrictJSON.parse(text) }

    func testNumericInMembersAreDeduplicatedByValueNotSpelling() throws {
        let fn = numbers["n"]!
        XCTAssertNil(fn.parse(n(["in": try parse("[1, 1.0, 1e0]")])), "the same number three ways is a duplicate")
        XCTAssertNil(fn.parse(n(["in": try parse("[10, 1e1]")])))
        XCTAssertNotNil(fn.parse(n(["in": try parse("[1, 2.5, 3e0]")])))
    }

    func testNumbersThatCannotBeRepresentedExactlyAreRefusedNotRounded() throws {
        let fn = numbers["n"]!
        let long = "12345678901234567890123456789012345678901"      // 41 digits
        XCTAssertNil(fn.parse(n(["ge": try parse(long)])), "a bound Decimal would round")
        XCTAssertNil(fn.parse(n(["in": try parse("[\(long)]")])))
        // Two distinct 40-digit lookups must not compare equal in the precheck.
        let a = "1234567890123456789012345678901234567890", b = "1234567890123456789012345678901234567891"
        let f = n(["ge": try parse(a)])
        XCTAssertNil(fn.parse(f), "40 digits exceeds Decimal's exact range, so it is refused up front")
        XCTAssertFalse(numbers.precheck(functions: [f], lookups: [.found(type: .number, text: b)]), "and never judged by a rounded compare")
    }

    func testTheMergeSpanIsRefusedWhenItCannotBeComputedExactly() throws {
        // Exact width 10 - 1e-100 is below 10, but Decimal would round it to 10 and accept.
        let plans = [[n(["ge": try parse("1e-100")])], [n(["le": .int(10)])]]
        XCTAssertFalse(numbers.combinedBoundsOk(plans: plans))
        // Exact widths that a worst-case digit estimate would wrongly refuse (Copilot review).
        let big = "10000000000000000000000000000000000000"          // 10^37, 38 digits
        let bigPlus10 = "10000000000000000000000000000000000010"
        XCTAssertTrue(numbers.combinedBoundsOk(plans: [[n(["ge": try parse(big)])], [n(["le": try parse(bigPlus10)])]]), "width exactly 10")
        let bigPlus9 = "10000000000000000000000000000000000009"
        XCTAssertFalse(numbers.combinedBoundsOk(plans: [[n(["ge": try parse(big)])], [n(["le": try parse(bigPlus9)])]]), "width 9 is below the minimum")
        XCTAssertTrue(numbers.combinedBoundsOk(plans: [[n(["ge": .int(0)])], [n(["le": try parse("1e100")])]]), "exactly representable huge width")
        XCTAssertTrue(numbers.combinedBoundsOk(plans: [[n(["ge": try parse("-5")])], [n(["le": .int(5)])]]), "negative lower bound: width 10")
        XCTAssertFalse(numbers.combinedBoundsOk(plans: [[n(["ge": try parse("-4")])], [n(["le": .int(5)])]]), "width 9")
        XCTAssertFalse(numbers.combinedBoundsOk(plans: [[n(["ge": .int(11)])], [n(["le": .int(0)])]]), "upper below lower")
        // Bounds whose scales differ by more than 4096 digits are refused, not computed (and cannot exhaust memory).
        XCTAssertFalse(numbers.combinedBoundsOk(plans: [[n(["ge": .int(1)])], [n(["le": .decimal("1e999999999")])]]))
        XCTAssertFalse(numbers.combinedBoundsOk(plans: [[n(["ge": .int(1)])], [n(["le": .decimal("1e5000")])]]))
        XCTAssertFalse(numbers.combinedBoundsOk(plans: [[n(["ge": .decimal("-1e999999999")])], [n(["le": .int(1)])]]))
        // A plain wide range still passes.
        XCTAssertTrue(numbers.combinedBoundsOk(plans: [[n(["ge": .int(0)])], [n(["le": .int(10)])]]))
    }

    func testTheExactWidthRefusesBoundsWhoseScalesDifferByMoreThan4096Digits() {
        XCTAssertNil(ExactDecimal.widthAtLeast(upper: "1e999999999", lower: "1", minimum: 10))
        XCTAssertNil(ExactDecimal.widthAtLeast(upper: "1e5000", lower: "1", minimum: 10))
        XCTAssertNil(ExactDecimal.widthAtLeast(upper: "1", lower: "-1e999999999", minimum: 10))
        XCTAssertNil(ExactDecimal.widthAtLeast(upper: "1e9223372036854775807", lower: "1", minimum: 10), "no Int overflow")
        XCTAssertEqual(ExactDecimal.widthAtLeast(upper: "1e4000", lower: "1", minimum: 10), true, "within the limit")
        XCTAssertEqual(ExactDecimal.widthAtLeast(upper: "0e999999999", lower: "-5", minimum: 5), true, "zero has no scale")
        XCTAssertEqual(ExactDecimal.widthAtLeast(upper: "10", lower: "1e-100", minimum: 10), false, "exactly below the minimum")
    }

    func testPrecheckWithMissingLookupsIsNotSatisfied() {
        let f = n(["ge": .int(1)])
        XCTAssertFalse(numbers.precheck(functions: [f], lookups: []), "a missing lookup must not skip the function")
        XCTAssertFalse(numbers.precheck(functions: [f, f], lookups: [.unsupported]))
        XCTAssertTrue(numbers.precheck(functions: [f], lookups: [.unsupported]))
    }

    func testRequestSignedIsCarriedAndAnEmptyQueryListIsRefused() throws {
        let query = CircuitZkConsentQuery(
            plan: [CircuitZkFunction(id: "age_check", handle: "a", params: ["le": .string("2008-10-19")])],
            credential: PresentationConsentCredential(name: nil, issuer: nil))
        func build(_ queries: [CircuitZkConsentQuery], signed: Bool) -> PresentationConsentRequest? {
            PresentationConsentBuilder.build(
                queries: queries, trust: CircuitZkConsentTrust(entityName: "x", framework: nil, identifier: nil),
                verifiedClientIdDisplayName: nil, attestedOrigin: "https://x", verifierId: nil, verifierIdType: nil,
                requestSigned: signed, today: "2026-10-19")
        }
        XCTAssertEqual(build([query], signed: false)?.requestSigned, false)
        XCTAssertEqual(build([query], signed: true)?.requestSigned, true)
        XCTAssertNil(build([], signed: true), "nothing to ask is refused, not an empty consent")
    }

    func testFloatOperandsMustBeFiniteExactNumbers() {
        let fn = numbers["n"]!
        XCTAssertNil(fn.parse(n(["ge": .double(.nan)])))
        XCTAssertNil(fn.parse(n(["ge": .double(.infinity)])))
        XCTAssertNil(fn.parse(n(["ge": .double(1e200)])), "outside Decimal's range: refused, not compared")
        XCTAssertNotNil(fn.parse(n(["ge": .double(2.5)])))
        XCTAssertFalse(numbers.precheck(functions: [n(["ge": .double(.nan)])], lookups: [.unsupported]), "an unsupported lookup must not wave an invalid operand through")
    }

    func testAnAgeFunctionWithAnyOtherComparisonFallsBackToTheGenericWording() throws {
        let registry = PredicateFunctions([
            PredicateFunction(id: "age_plus", claim: .fixed(["birth_date"]), valueType: .date,
                              comparisons: [.init(param: "ge", op: .ge), .init(param: "le", op: .le), .init(param: "eq", op: .eq)],
                              minSpan: 365, ageSpecialisation: true),
        ])
        func predicate(_ params: [String: JSONValue]) throws -> PresentationConsentPredicate {
            let query = CircuitZkConsentQuery(
                plan: [CircuitZkFunction(id: "age_plus", handle: "a", params: params)],
                credential: PresentationConsentCredential(name: nil, issuer: nil))
            let request = try XCTUnwrap(PresentationConsentBuilder.build(
                queries: [query], functions: registry, trust: CircuitZkConsentTrust(entityName: "x", framework: nil, identifier: nil),
                verifiedClientIdDisplayName: nil, attestedOrigin: "https://x", verifierId: nil, verifierIdType: nil,
                requestSigned: true, today: "2026-10-19"))
            guard case .predicate(let p) = request.entries[0].items[0] else { throw XCTSkip("not a predicate") }
            return p
        }
        // An equality reveals the date: no age form, so every comparison is worded.
        let withEq = try predicate(["le": .string("2008-10-19"), "eq": .string("2000-01-01")])
        XCTAssertNil(withEq.ageForm)
        XCTAssertEqual(withEq.conditions.map(\.op), [.le, .eq])
        XCTAssertNil(try predicate(["ge": .string("1990-01-01"), "le": .string("2010-01-01"), "eq": .string("2000-01-01")]).ageForm)
        // Bounds alone keep the age wording.
        XCTAssertNotNil(try predicate(["ge": .string("1990-01-01"), "le": .string("2010-01-01")]).ageForm)
        XCTAssertNotNil(try predicate(["le": .string("2008-10-19")]).ageForm)
    }

    func testTheAgeWordingIsDroppedWhenTheRequestRevealsTheBirthDateElsewhere() throws {
        let registry = PredicateFunctions([
            .ageCheck,
            PredicateFunction(id: "date_compare", claim: .param, valueType: .date, comparisons: [.init(param: "eq", op: .eq)]),
        ])
        func age(_ extra: [CircuitZkFunction]) throws -> PresentationConsentPredicate {
            let ageFn = CircuitZkFunction(id: "age_check", handle: "a", params: ["le": .string("2008-10-19")])
            let query = CircuitZkConsentQuery(plan: [ageFn] + extra, credential: PresentationConsentCredential(name: nil, issuer: nil))
            let request = try XCTUnwrap(PresentationConsentBuilder.build(
                queries: [query], functions: registry, trust: CircuitZkConsentTrust(entityName: "x", framework: nil, identifier: nil),
                verifiedClientIdDisplayName: nil, attestedOrigin: "https://x", verifierId: nil, verifierIdType: nil, requestSigned: true, today: "2026-10-19"))
            guard case .predicate(let p) = request.entries[0].items[0] else { throw XCTSkip("not a predicate") }
            return p
        }
        XCTAssertNotNil(try age([]).ageForm, "alone it is an age")
        // a legacy disclosure of birth_date
        let disclosure = CircuitZkFunction(id: "zk-claim-disclosure-v1", handle: "d", params: ["claims": .array([.string("birth_date")])])
        XCTAssertNil(try age([disclosure]).ageForm)
        // a separate equality on the same claim
        let equality = CircuitZkFunction(id: "date_compare", handle: "e", params: ["claim": .string("birth_date"), "eq": .string("2000-01-01")])
        XCTAssertNil(try age([equality]).ageForm)
        // other claims do not matter
        let other = CircuitZkFunction(id: "zk-claim-disclosure-v1", handle: "d", params: ["claims": .array([.string("family_name")])])
        XCTAssertNotNil(try age([other]).ageForm)
    }

    func testALargeRequestIsBuiltWithoutQuadraticWork() throws {
        // 20,000 single-item entries: the revealed-claims set is built once, not once per entry.
        let entries = (0..<20_000).map { _ in
            CircuitZkConsentQuery(
                plan: [CircuitZkFunction(id: "age_check", handle: "a", params: ["le": .string("2008-10-19")])],
                credential: PresentationConsentCredential(name: nil, issuer: nil))
        }
        let start = Date()
        let request = try XCTUnwrap(PresentationConsentBuilder.build(
            queries: entries, trust: CircuitZkConsentTrust(entityName: "x", framework: nil, identifier: nil),
            verifiedClientIdDisplayName: nil, attestedOrigin: "https://x", verifierId: nil, verifierIdType: nil, requestSigned: true, today: "2026-10-19"))
        XCTAssertEqual(request.entries.count, 20_000)
        XCTAssertLessThan(Date().timeIntervalSince(start), 5)
    }

    func testTheCutoverDateIsNamedAsTheOperandNotNormalised() throws {
        let item = PresentationConsentItem.predicate(PresentationConsentPredicate(
            functionId: "x", claim: PresentationConsentClaimRef(path: ["d"], label: "D"), valueType: .date,
            conditions: [PredicateCondition(op: .eq, values: ["1582-10-10"])], ageForm: nil))
        let request = PresentationConsentRequest(
            verifier: PresentationConsentVerifier(label: "x", trustFramework: nil, trustIdentifier: nil, verifierId: nil, verifierIdType: nil, intermediaryRisk: false),
            entries: [PresentationConsentEntry(credential: PresentationConsentCredential(name: nil, issuer: nil), items: [item])], requestSigned: true)
        let line = try PresentationConsentText(locale: Locale(identifier: "en")).render(request).entries[0].lines[0]
        XCTAssertFalse(line.contains("20"), line)
        XCTAssertTrue(line.contains("10"), line)
        XCTAssertTrue(line.contains("1582"), line)
    }

    func testStringOperandsAreComparedByUtf8BytesNotCanonicalEquivalence() throws {
        let strings = PredicateFunctions([
            PredicateFunction(id: "s", claim: .param, valueType: .string,
                              comparisons: [.init(param: "eq", op: .eq), .init(param: "ne", op: .ne), .init(param: "in", op: .in)]),
        ])
        let composed = "\u{00E9}", decomposed = "e\u{0301}"
        XCTAssertEqual(composed, decomposed, "Swift treats these as equal; the vectors of the other SDKs do not")
        func fn(_ params: [String: JSONValue]) -> CircuitZkFunction {
            CircuitZkFunction(id: "s", handle: "h", params: params.merging(["claim": .string("c")]) { a, _ in a })
        }
        // a set with both spellings is NOT a duplicate
        XCTAssertNotNil(strings["s"]!.parse(fn(["in": .array([.string(composed), .string(decomposed)])])))
        // the same spelling twice is
        XCTAssertNil(strings["s"]!.parse(fn(["in": .array([.string(composed), .string(composed)])])))
        func holds(_ params: [String: JSONValue], _ value: String) -> Bool {
            strings.precheck(functions: [fn(params)], lookups: [.found(type: .string, text: value)])
        }
        XCTAssertTrue(holds(["eq": .string(composed)], composed))
        XCTAssertFalse(holds(["eq": .string(composed)], decomposed))
        XCTAssertTrue(holds(["ne": .string(composed)], decomposed))
        XCTAssertFalse(holds(["ne": .string(composed)], composed))
        XCTAssertTrue(holds(["in": .array([.string(composed)])], composed))
        XCTAssertFalse(holds(["in": .array([.string(composed)])], decomposed))
    }

    func testTheDefaultRegistryKnowsOnlyAgeCheckAndNothingElseIsAssumed() {
        XCTAssertNotNil(PredicateFunctions.default["age_check"])
        XCTAssertNil(PredicateFunctions.default["number_range"])
        let unknown = CircuitZkConsentQuery(
            plan: [CircuitZkFunction(id: "number_range", handle: "p", params: ["claim": .string("score"), "ge": .int(1)])],
            credential: PresentationConsentCredential(name: nil, issuer: nil))
        XCTAssertNil(PresentationConsentBuilder.build(
            queries: [unknown], trust: CircuitZkConsentTrust(entityName: "x", framework: nil, identifier: nil),
            verifiedClientIdDisplayName: nil, attestedOrigin: "https://x", verifierId: nil, verifierIdType: nil, requestSigned: true, today: "2026-10-19"),
            "a function the registry does not declare is refused before consent")
    }

    // MARK: - vector -> model

    private static func plan(_ value: JSONValue) throws -> [CircuitZkFunction] {
        try XCTUnwrap(value.arrayValue).map { item in
            let o = item.objectValue ?? [:]
            return CircuitZkFunction(id: o["id"]?.stringValue ?? "", handle: o["handle"]?.stringValue ?? "", params: o["params"]?.objectValue ?? [:])
        }
    }

    private static func build(input: [String: JSONValue], today: String, registry: PredicateFunctions) throws -> PresentationConsentRequest? {
        let queries = try XCTUnwrap(input["queries"]?.arrayValue).map { value -> CircuitZkConsentQuery in
            let q = value.objectValue ?? [:]
            let cred = q["credential"]?.objectValue ?? [:]
            let claims = (q["claims"]?.arrayValue ?? []).map { c -> PresentationConsentClaimRef in
                let o = c.objectValue ?? [:]
                return PresentationConsentClaimRef(path: (o["path"]?.arrayValue ?? []).compactMap { $0.stringValue }, label: o["label"]?.stringValue)
            }
            return CircuitZkConsentQuery(
                plan: try plan(q["plan"] ?? .array([])),
                credential: PresentationConsentCredential(name: cred["name"]?.stringValue, issuer: cred["issuer"]?.stringValue), claims: claims,
                namespace: q["namespace"]?.stringValue)
        }
        let trust = input["trust"]?.objectValue ?? [:]
        return PresentationConsentBuilder.build(
            queries: queries, functions: registry,
            trust: CircuitZkConsentTrust(
                entityName: trust["entity_name"]?.stringValue, framework: trust["framework"]?.stringValue,
                identifier: trust["identifier"]?.stringValue, intermediaryRisk: trust["intermediary_risk"] == .bool(true)),
            verifiedClientIdDisplayName: input["verified_client_id_display_name"]?.stringValue,
            attestedOrigin: try XCTUnwrap(input["attested_origin"]?.stringValue),
            verifierId: input["verifier_id"]?.stringValue, verifierIdType: input["verifier_id_type"]?.stringValue,
            requestSigned: true, today: today)
    }

    private static func expectedRequest(_ request: [String: JSONValue]) throws -> PresentationConsentRequest {
        let verifier = request["verifier"]?.objectValue ?? [:]
        let entries = try XCTUnwrap(request["entries"]?.arrayValue).map { value -> PresentationConsentEntry in
            let entry = value.objectValue ?? [:]
            let cred = entry["credential"]?.objectValue ?? [:]
            return PresentationConsentEntry(
                credential: PresentationConsentCredential(name: cred["name"]?.stringValue, issuer: cred["issuer"]?.stringValue),
                items: try XCTUnwrap(entry["items"]?.arrayValue).map(expectedItem))
        }
        return PresentationConsentRequest(
            verifier: PresentationConsentVerifier(
                label: verifier["label"]?.stringValue ?? "", trustFramework: verifier["trust_framework"]?.stringValue,
                trustIdentifier: verifier["trust_identifier"]?.stringValue, verifierId: verifier["verifier_id"]?.stringValue,
                verifierIdType: verifier["verifier_id_type"]?.stringValue, intermediaryRisk: verifier["intermediary_risk"] == .bool(true)),
            entries: entries, requestSigned: request["request_signed"] == .bool(true))
    }

    private static func expectedItem(_ value: JSONValue) throws -> PresentationConsentItem {
        let item = try XCTUnwrap(value.objectValue)
        switch item["kind"]?.stringValue {
        case "pseudonym":
            return .pseudonym(
                config: item["config"]?.stringValue ?? "",
                scope: PresentationConsentItem.PseudonymScope(rawValue: item["scope"]?.stringValue ?? "") ?? .perVerifier,
                remappableByIssuer: item["remappable_by_issuer"] == .bool(true), crossSite: item["cross_site"] == .bool(true),
                verifierId: item["verifier_id"]?.stringValue ?? "", verifierContext: item["verifier_context"]?.stringValue)
        case "predicate":
            let claim = item["claim"]?.objectValue ?? [:]
            let conditions = (item["conditions"]?.arrayValue ?? []).map { c -> PredicateCondition in
                let o = c.objectValue ?? [:]
                return PredicateCondition(
                    op: PredicateOp(rawValue: o["op"]?.stringValue ?? "") ?? .eq,
                    values: (o["values"]?.arrayValue ?? []).compactMap { $0.stringValue })
            }
            return .predicate(PresentationConsentPredicate(
                functionId: item["function"]?.stringValue ?? "",
                claim: PresentationConsentClaimRef(
                    path: (claim["path"]?.arrayValue ?? []).compactMap { $0.stringValue }, label: claim["label"]?.stringValue),
                valueType: PredicateValueType(rawValue: item["value_type"]?.stringValue ?? "") ?? .string,
                conditions: conditions, ageForm: try expectedAgeForm(item["age_form"])))
        case "claim": return .claim(name: item["name"]?.stringValue ?? "")
        case "legacy_pseudonym": return .legacyPseudonym(verifierContext: item["verifier_context"]?.stringValue)
        default: throw XCTSkip("unknown item kind")
        }
    }

    private static func expectedAgeForm(_ value: JSONValue?) throws -> PredicateAgeForm? {
        guard let form = value?.objectValue else { return nil }
        func int(_ key: String) -> Int {
            if case .int(let n)? = form[key] { return Int(n) }
            return -1
        }
        switch form["kind"]?.stringValue {
        case "between":
            return .between(from: form["from"]?.stringValue ?? "", to: form["to"]?.stringValue ?? "", minYears: int("min_years"), maxYears: int("max_years"))
        case "at_least": return .atLeast(years: int("years"))
        case "at_most": return .atMost(years: int("years"))
        default: throw XCTSkip("unknown age form")
        }
    }
}

final class CivilDateTests: XCTestCase {
    func testStrictDates() {
        XCTAssertNil(CivilDate("2000-1-1"))
        XCTAssertNil(CivilDate("2000-02-30"))
        XCTAssertNil(CivilDate("1900-02-29"))
        XCTAssertNotNil(CivilDate("2000-02-29"))
        XCTAssertNil(CivilDate("0000-01-01"))
        XCTAssertNil(CivilDate("2000-01-01 "))
    }

    func testDaysSinceEpoch() throws {
        XCTAssertEqual(try XCTUnwrap(CivilDate("1970-01-01")).daysSinceEpoch, 0)
        XCTAssertEqual(try XCTUnwrap(CivilDate("1970-01-02")).daysSinceEpoch, 1)
        XCTAssertEqual(try XCTUnwrap(CivilDate("2000-03-01")).daysSinceEpoch, 11017)
        XCTAssertEqual(try XCTUnwrap(CivilDate("1969-12-31")).daysSinceEpoch, -1)
        // 2024 is a leap year: 366 days between the same date a year apart across Feb 29.
        let a = try XCTUnwrap(CivilDate("2023-03-01")), b = try XCTUnwrap(CivilDate("2024-03-01")), c = try XCTUnwrap(CivilDate("2025-03-01"))
        XCTAssertEqual(b.daysSinceEpoch - a.daysSinceEpoch, 366)
        XCTAssertEqual(c.daysSinceEpoch - b.daysSinceEpoch, 365)
    }
}
