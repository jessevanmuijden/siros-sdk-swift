// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

final class StrictJSONTests: XCTestCase {
    func testParsesAllValueKinds() throws {
        let v = try StrictJSON.parse(#"{"a":[1,2.5,-3,true,false,null,"xå\n😀"],"b":{}}"#)
        XCTAssertEqual(v["a"]?.arrayValue?[0], .int(1))
        XCTAssertEqual(v["a"]?.arrayValue?[1], .decimal("2.5"))
        XCTAssertEqual(v["a"]?.arrayValue?[2], .int(-3))
        XCTAssertEqual(v["a"]?.arrayValue?[6], .string("x\u{e5}\n\u{1F600}"))
    }

    /// Numbers are compared exactly, never through binary floating point.
    func testNumberComparisonIsExact() throws {
        let a = try StrictJSON.parse("9007199254740992")
        let b = try StrictJSON.parse("9007199254740993")
        XCTAssertFalse(a.jsonEquals(b), "distinct integers above 2^53 stay distinct")
        XCTAssertFalse(try StrictJSON.parse("0.1").jsonEquals(try StrictJSON.parse("0.10000000000000001")))
        XCTAssertTrue(try StrictJSON.parse("0.5").jsonEquals(try StrictJSON.parse("0.50")))
        XCTAssertEqual(try StrictJSON.parse("9223372036854775808"), .decimal("9223372036854775808"), "beyond Int64 keeps its text")
        XCTAssertEqual(JSONValue.compareNumbers(a, b), .orderedAscending)
        XCTAssertNil(JSONValue.compareNumbers(.string("1"), .int(1)))
    }

    /// Beyond Decimal's precision there is no exact comparison: fail closed.
    func testNumbersTooLongForExactComparisonAreNotComparable() throws {
        let a = try StrictJSON.parse("1234567890123456789012345678901234567890")
        let b = try StrictJSON.parse("1234567890123456789012345678901234567891")
        XCTAssertNil(JSONValue.compareNumbers(a, b))
        XCTAssertFalse(a.jsonEquals(b), "distinct 40-digit numbers must not compare equal")
        XCTAssertFalse(a.jsonEquals(a), "an uncomparable number is never equal, not even to itself")
        XCTAssertFalse(a.isIntegral)
        XCTAssertNil(JSONValue.decimal("1e999999").exactNumber)
        XCTAssertThrowsError(try StrictJSON.parse("1e999999"))
        XCTAssertEqual(JSONValue.significantDigits("-0.00120e5"), 3)
        // Within precision it is exact.
        XCTAssertTrue(try StrictJSON.parse("12345678901234567890123456789012345678").jsonEquals(try StrictJSON.parse("12345678901234567890123456789012345678")))
    }

    func testRefusesAmbiguousOrMalformedDocuments() {
        let bad = [
            #"{"a":1,"a":2}"#,         // duplicate key
            #"{"a":1} x"#,             // trailing content
            #"{"a":01}"#,              // leading zero
            #"{"a":"\ud800"}"#,        // lone surrogate
            #"{"a":1,}"#,              // trailing comma
            "{\"a\":\"line\nbreak\"}", // raw control character
            #"{'a':1}"#,
            "",
            String(repeating: "[", count: 40) + String(repeating: "]", count: 40), // too deep
        ]
        for text in bad { XCTAssertThrowsError(try StrictJSON.parse(text), text) }
    }

    func testNumbersKeepTheirKind() throws {
        XCTAssertEqual(try StrictJSON.parse("1"), .int(1))
        XCTAssertEqual(try StrictJSON.parse("1.0"), .decimal("1.0"), "kept as written")
        XCTAssertTrue(JSONValue.int(1).jsonEquals(.decimal("1.0")))
        XCTAssertTrue(JSONValue.int(100).jsonEquals(try StrictJSON.parse("1e2")))
        XCTAssertTrue(JSONValue.int(1).jsonEquals(.double(1)))
        XCTAssertFalse(JSONValue.bool(true).jsonEquals(.int(1)))
    }
}

final class JSONSchemaValidatorTests: XCTestCase {
    private func check(_ instance: String, _ schema: String) throws -> JSONSchemaValidator.Outcome {
        JSONSchemaValidator().validate(try StrictJSON.parse(instance), against: try StrictJSON.parse(schema))
    }

    func testTypeRequiredAndAdditionalProperties() throws {
        let schema = #"{"type":"object","properties":{"a":{"type":"string"},"n":{"type":"integer"}},"required":["a"],"additionalProperties":false}"#
        XCTAssertEqual(try check(#"{"a":"x","n":2}"#, schema), .valid)
        XCTAssertEqual(try check(#"{"a":"x","n":2.0}"#, schema), .valid, "2.0 is an integer")
        guard case .invalid = try check(#"{"n":2}"#, schema) else { return XCTFail("missing required") }
        guard case .invalid = try check(#"{"a":"x","extra":1}"#, schema) else { return XCTFail("additional") }
        guard case .invalid = try check(#"{"a":1}"#, schema) else { return XCTFail("type") }
        guard case .invalid = try check(#"{"a":"x","n":2.5}"#, schema) else { return XCTFail("integer") }
        guard case .invalid = try check(#"{"a":"x","n":true}"#, schema) else { return XCTFail("bool is not a number") }
    }

    func testStringAndNumberConstraints() throws {
        XCTAssertEqual(try check(#""ab""#, #"{"minLength":2,"maxLength":3,"pattern":"^[a-z]+$"}"#), .valid)
        guard case .invalid = try check(#""a""#, #"{"minLength":2}"#) else { return XCTFail() }
        guard case .invalid = try check(#""abcd""#, #"{"maxLength":3}"#) else { return XCTFail() }
        guard case .invalid = try check(#""AB""#, #"{"pattern":"^[a-z]+$"}"#) else { return XCTFail() }
        // length counts code points, not UTF-16 units
        XCTAssertEqual(try check(#""😀""#, #"{"maxLength":1}"#), .valid)
        guard case .invalid = try check("5", #"{"maximum":4}"#) else { return XCTFail() }
        guard case .invalid = try check("4", #"{"exclusiveMaximum":4}"#) else { return XCTFail() }
    }

    func testIntegerAndBoundChecksAreExact() throws {
        XCTAssertEqual(try check("2.0", #"{"type":"integer"}"#), .valid)
        XCTAssertEqual(try check("1e2", #"{"type":"integer"}"#), .valid)
        guard case .invalid = try check("2.5", #"{"type":"integer"}"#) else { return XCTFail() }
        XCTAssertEqual(try check("0.1", #"{"type":"number","minimum":0.1}"#), .valid)
        guard case .invalid = try check("9007199254740993", #"{"maximum":9007199254740992}"#) else { return XCTFail("exact bound") }
        guard case .invalid = try check("9007199254740993", #"{"const":9007199254740992}"#) else { return XCTFail("exact const") }
        guard case .invalid = try check("9007199254740993", #"{"enum":[9007199254740992]}"#) else { return XCTFail("exact enum") }
    }

    /// RFC 6901: a `~` not followed by 0 or 1 is a malformed pointer, unsupported even under `not`.
    func testMalformedJsonPointerTokensAreUnsupported() throws {
        // The $defs keys are the literal malformed tokens, so a lenient resolver WOULD find them.
        for token in ["a~", "a~2b", "~x"] {
            for schema in [##"{"$defs":{"\##(token)":{"type":"string"}},"$ref":"#/$defs/\##(token)"}"##,
                           ##"{"$defs":{"\##(token)":{"type":"string"}},"not":{"$ref":"#/$defs/\##(token)"}}"##] {
                guard case .unsupported = try check(#""text""#, schema) else { return XCTFail("\(schema)") }
            }
        }
        let ok = ##"{"$defs":{"a/b":{"type":"string"},"a~b":{"type":"string"}},"properties":{"x":{"$ref":"#/$defs/a~1b"},"y":{"$ref":"#/$defs/a~0b"}}}"##
        XCTAssertEqual(try check(#"{"x":"s","y":"t"}"#, ok), .valid)
    }

    /// An undecidable integer/bound check is refused, and a `not` cannot turn it into acceptance.
    func testUndecidableNumberChecksAreUnsupportedNotInvalid() throws {
        let big = "1234567890123456789012345678901234567890"
        for schema in [#"{"type":"integer"}"#, #"{"not":{"type":"integer"}}"#, #"{"not":{"maximum":1234567890123456789012345678901234567891}}"#, #"{"maximum":1234567890123456789012345678901234567891}"#] {
            guard case .unsupported = try check(big, schema) else { return XCTFail("\(schema) must be unsupported") }
        }
    }

    func testEnumConstAndCombinators() throws {
        XCTAssertEqual(try check(#""A""#, #"{"enum":["A","B"]}"#), .valid)
        guard case .invalid = try check(#""C""#, #"{"enum":["A","B"]}"#) else { return XCTFail() }
        guard case .invalid = try check("1", #"{"const":2}"#) else { return XCTFail() }
        XCTAssertEqual(try check("1", #"{"anyOf":[{"type":"string"},{"type":"integer"}]}"#), .valid)
        guard case .invalid = try check("1.5", #"{"anyOf":[{"type":"string"},{"type":"integer"}]}"#) else { return XCTFail() }
        guard case .invalid = try check("1", #"{"not":{"type":"integer"}}"#) else { return XCTFail() }
    }

    /// A schema keyword the validator cannot evaluate must never be treated as satisfied.
    func testUnsupportedKeywordFailsClosed() throws {
        for keyword in [#"{"patternProperties":{"^a":{"type":"string"}}}"#, #"{"unevaluatedProperties":false}"#,
                        #"{"dependentRequired":{"a":["b"]}}"#, #"{"if":{"type":"string"}}"#, ##"{"$dynamicRef":"#x"}"##] {
            guard case .unsupported = try check(#"{"a":1}"#, keyword) else { return XCTFail(keyword) }
        }
        // ... including when nested.
        guard case .unsupported = try check(#"{"a":1}"#, #"{"properties":{"a":{"multipleOf":2}}}"#) else { return XCTFail() }
    }

    func testRefsResolveOnlyLocallyOrThroughTheResolver() throws {
        let local = ##"{"$defs":{"s":{"type":"string"}},"properties":{"a":{"$ref":"#/$defs/s"}}}"##
        XCTAssertEqual(try check(#"{"a":"x"}"#, local), .valid)
        guard case .invalid = try check(#"{"a":1}"#, local) else { return XCTFail() }
        guard case .unsupported = try check(#"{"a":1}"#, #"{"properties":{"a":{"$ref":"https://evil.example/s.json"}}}"#) else { return XCTFail("never fetches") }
        guard case .unsupported = try check(#"{"a":1}"#, #"{"properties":{"a":{"$ref":"other.json"}}}"#) else { return XCTFail("unresolvable") }
    }

    /// Even a resolver willing to answer must not be asked for a network URL.
    func testNetworkReferencesAreNeverPassedToTheResolver() throws {
        let validator = JSONSchemaValidator(resolveRef: { _ in .bool(true) })
        let schema = try StrictJSON.parse(#"{"properties":{"a":{"$ref":"https://evil.example/s.json"}}}"#)
        guard case .unsupported = validator.validate(try StrictJSON.parse(#"{"a":1}"#), against: schema) else { return XCTFail() }
        // Anything with a scheme, a host or a path is never passed on.
        for ref in ["//evil.example/s.json", "file:///etc/passwd", "urn:x:y", "mailto:a@b", "a/b.json", "../s.json", "/abs.json", "s.json?x=1", "s.json#frag"] {
            let schema = try StrictJSON.parse(#"{"properties":{"a":{"$ref":"\#(ref)"}}}"#)
            guard case .unsupported = validator.validate(try StrictJSON.parse(#"{"a":1}"#), against: schema) else { return XCTFail(ref) }
        }
        let local = try StrictJSON.parse(#"{"properties":{"a":{"$ref":"file.json"}}}"#)
        XCTAssertEqual(validator.validate(try StrictJSON.parse(#"{"a":1}"#), against: local), .valid)
    }

    /// Branching recursion must not do exponential work inside the depth limit.
    func testBranchingRecursiveSchemaIsStoppedByTheBudget() throws {
        let started = Date()
        guard case .unsupported = try check(#"{"a":1}"#, ##"{"anyOf":[{"$ref":"#"},{"$ref":"#"}]}"##) else { return XCTFail("must not be accepted") }
        guard case .unsupported = try check(#"{"a":1}"#, ##"{"oneOf":[{"$ref":"#"},{"$ref":"#"}]}"##) else { return XCTFail() }
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }

    func testSelfReferenceTerminates() throws {
        guard case .unsupported = try check(#"{"a":1}"#, ##"{"$ref":"#"}"##) else { return XCTFail() }
    }
}

final class BuiltInSchemaTests: XCTestCase {
    private func sha256Hex(_ text: String) -> String {
        SHA256.hash(data: Data(text.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    /// Pins the embedded schemas to the spec's files (fetched 2026-10-06): a
    /// change here must be a deliberate, reviewed update, not an edit.
    func testEmbeddedSchemasAreTheSpecFilesVerbatim() throws {
        // SHA-256 of each file's text (trailing newline stripped), fetched from
        // eudi-doc-standards-and-technical-specifications main on 2026-10-06.
        let expected: [String: String] = [
            "urn:eudi:sca:payment:1": "d0c42d120f5120b41d215fe2fffcafb414b084ac6506b31ef52289d4423e6fed",
            "urn:eudi:sca:login_risk_transaction:1": "5bed693b2dad50e47015006d86e4be1c737a31297241e09ede4ad257e898aed8",
            "urn:eudi:sca:account_access:1": "0b4bf3efd3a51a528b459393f33dcbf703e1e4eab2acdf9ea352482c6eeca912",
            "urn:eudi:sca:emandate:1": "e9fe430436470f4ba97c66185619879358c2eb1fa40b9238f3b42b310acc7e89",
        ]
        XCTAssertEqual(Set(TransactionDataBuiltIns.sources.keys), Set(expected.keys))
        for (type, text) in TransactionDataBuiltIns.sources {
            XCTAssertNotNil(TransactionDataBuiltIns.schema(forType: type), type)
            XCTAssertEqual(sha256Hex(text), expected[type], type)
        }
    }

    private func outcome(_ type: String, _ payload: String) throws -> JSONSchemaValidator.Outcome {
        JSONSchemaValidator(resolveRef: { TransactionDataBuiltIns.schema(forReference: $0) })
            .validate(try StrictJSON.parse(payload), against: try XCTUnwrap(TransactionDataBuiltIns.schema(forType: type)))
    }

    func testPaymentSchema() throws {
        let ok = #"{"transaction_id":"tx-1","payee":{"name":"Shop","id":"SE1"},"currency":"EUR","amount":49.99}"#
        XCTAssertEqual(try outcome("urn:eudi:sca:payment:1", ok), .valid)
        XCTAssertEqual(try outcome("urn:eudi:sca:payment:1", #"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1,"recurrence":{"frequency":"MNTH","number":3}}"#), .valid)
        for bad in [
            #"{"transaction_id":"tx-1","payee":{"name":"Shop","id":"SE1"},"currency":"EUR","amount":"49.99"}"#,   // amount is a number
            #"{"transaction_id":"tx-1","payee":{"name":"Shop"},"currency":"EUR","amount":1}"#,                    // payee.id required
            #"{"transaction_id":"tx-1","payee":{"name":"S","id":"1"},"currency":"eur","amount":1}"#,              // pattern
            #"{"transaction_id":"","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1}"#,                  // minLength
            #"{"transaction_id":"tx-1","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1,"x":1}"#,        // additional
            #"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1,"recurrence":{"frequency":"HOURLY"}}"#,
        ] {
            guard case .invalid = try outcome("urn:eudi:sca:payment:1", bad) else { return XCTFail(bad) }
        }
    }

    func testOtherBuiltInSchemas() throws {
        XCTAssertEqual(try outcome("urn:eudi:sca:login_risk_transaction:1", #"{"transaction_id":"t","action":"Log in"}"#), .valid)
        guard case .invalid = try outcome("urn:eudi:sca:login_risk_transaction:1", #"{"transaction_id":"t"}"#) else { return XCTFail() }
        XCTAssertEqual(try outcome("urn:eudi:sca:account_access:1", #"{"transaction_id":"t","aisp":{"legal_name":"L","brand_name":"B","domain_name":"d.example"}}"#), .valid)
        guard case .invalid = try outcome("urn:eudi:sca:account_access:1", #"{"transaction_id":"t","aisp":{"legal_name":"L"}}"#) else { return XCTFail() }
    }

    /// The e-mandate schema `$ref`s the payment schema by file name; the
    /// nested payload must be validated against it, not skipped.
    func testEmandateValidatesTheReferencedPaymentSchema() throws {
        let good = #"{"transaction_id":"t","purpose":"p","payment_payload":{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1}}"#
        XCTAssertEqual(try outcome("urn:eudi:sca:emandate:1", good), .valid)
        let bad = #"{"transaction_id":"t","payment_payload":{"transaction_id":"t","currency":"EUR","amount":1}}"#
        guard case .invalid(let path, _) = try outcome("urn:eudi:sca:emandate:1", bad) else { return XCTFail("nested violation missed") }
        XCTAssertTrue(path.hasPrefix(".payment_payload"), path)
    }
}
