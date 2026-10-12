// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

private final class Source: TransactionMetadataSource, @unchecked Sendable {
    var documents: [String: String] = [:]
    func typeMetadataDocument(vct: String, expectedIntegrity: String?, maxBytes: Int) async -> String? { documents[vct] }
    func fetchResource(uri: String, maxBytes: Int) async -> Data? { nil }
}

/// Malformed input never crashes or escapes as a raw error; schema work is bounded;
/// integrity claims fail closed; the unpinned-metadata warning is generic and single.
final class TransactionDataHardeningTests: XCTestCase {
    // The vct, payee, id and amount are DISTINCTIVE so a leak into a log line is detectable.
    private let vct = "https://secret-bank.example/cards/platinum-black"
    private let payload = #"{"transaction_id":"TX-9f3c-UNIQUE","payee":{"name":"Zebra Holdings GmbH","id":"DE-UNIQUE-77"},"currency":"EUR","amount":98765.43}"#

    private func raw(_ json: String) -> String {
        Data(json.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    private func entry(_ payload: String? = nil) -> String {
        raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":\#(payload ?? self.payload)}"#)
    }
    private var metadata: String {
        #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{"urn:eudi:sca:payment:1":{"schema":"urn:eudi:sca:payment:1"}}}"#
    }
    private func request(_ entries: [String], pins: [String: String] = [:]) -> TransactionDataRequest {
        TransactionDataRequest(
            entries: entries.map { TransactionDataEntryInput(raw: $0) }, responseMode: "dc_api",
            credentials: [TransactionDataCredential(queryId: "pay", format: "dc+sd-jwt", vct: vct, integrityClaims: pins)]
        )
    }
    private func source() -> Source { let s = Source(); s.documents[vct] = metadata; return s }

    private func expectRefusal(_ req: TransactionDataRequest, _ reason: TransactionDataError.Reason? = nil, line: UInt = #line) async {
        do { _ = try await TransactionDataPipeline(source: source()).validate(req); XCTFail("expected a refusal", line: line) }
        catch let e as TransactionDataError { if let reason { XCTAssertEqual(e.reason, reason, line: line) } }
        catch { XCTFail("raw error escaped: \(error)", line: line) }
    }

    // MARK: every failure is a TransactionDataError

    func testMalformedRawInputsAreRefusedWithAReasonNeverAnEscapedError() async {
        let cases: [(String, String)] = [
            ("bad \\u escape", raw(#"{"type":"t","payload":{"a":"\uZZZZ"}}"#)),
            ("lone surrogate", raw(#"{"type":"t","payload":{"a":"\ud800"}}"#)),
            ("invalid UTF-8", Data([0x7b, 0x22, 0xff, 0xfe, 0x22, 0x3a, 0x31, 0x7d]).base64EncodedString().replacingOccurrences(of: "=", with: "")),
            ("deep nesting", raw(String(repeating: "[", count: 5000) + String(repeating: "]", count: 5000))),
            ("huge number", raw(#"{"type":"t","payload":{"a":1e99999}}"#)),
            ("not base64url", "@@@@"),
            ("empty", ""),
            ("huge", String(repeating: "A", count: 200_000)),
        ]
        for (name, value) in cases {
            do { _ = try await TransactionDataPipeline(source: source()).validate(request([value])); XCTFail(name) }
            catch let e as TransactionDataError { XCTAssertEqual(e.reason, .invalidEntry, name) }
            catch { XCTFail("\(name): raw error escaped: \(error)") }
        }
    }

    /// An issuer schema's bare file-name `$ref` never resolves to a bundled document of the same name.
    func testACustomSchemaCannotReferenceABundledSchemaByFileName() async {
        let s = Source()
        let types = #"{"https://x.example/t":{"schema":{"$ref":"ts12-urn-eudi-sca-payment-1-data-model.json"}}}"#
        s.documents[vct] = #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":\#(types)}"#
        let e = raw(#"{"type":"https://x.example/t","credential_ids":["pay"],"payload":{"transaction_id":"tx-1","payee":{"name":"Shop AB","id":"SE1"},"currency":"EUR","amount":49.99}}"#)
        do { _ = try await TransactionDataPipeline(source: s).validate(request([e])); XCTFail("must refuse") }
        catch let err as TransactionDataError { XCTAssertEqual(err.reason, .schemaViolation) }
        catch { XCTFail("\(error)") }
    }

    func testSchemaOutcomesSurfaceAsSchemaViolation() async {
        let s = Source()
        let types = #"{"https://x.example/t":{"schema":{"type":"object","properties":{"a":{"pattern":"(a+)+$"}}}}}"#
        s.documents[vct] = #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":\#(types)}"#
        let e = raw(#"{"type":"https://x.example/t","credential_ids":["pay"],"payload":{"a":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}}"#)
        do { _ = try await TransactionDataPipeline(source: s).validate(request([e])); XCTFail() }
        catch let err as TransactionDataError { XCTAssertEqual(err.reason, .schemaViolation) }
        catch { XCTFail("\(error)") }
    }

    // MARK: schema bounds

    func testCatastrophicPatternsAreRefusedNotRun() throws {
        let started = Date()
        let evil = ["(a+)+$", "(a|aa)+$", "(a*)*$", "(.*a){12}x", "^(([a-z])+.)+[A-Z]([a-z])+$", #"(a)\1+"#, "(?=a)a", String(repeating: "a", count: 300),
                    "^" + String(repeating: "(aa|aaaa)", count: 24) + "$", "^(ab|cd)$", "^(a)(b)(c)(d)(e)(f)(g)(h)(i)$",
                    "^(a?){30}a{30}$", "a*a*a*b", "a?a?a?a?a?a?a?aaaaaaa", "^(abc)?x$", "(a){2,}(b)+",
                    "^a{0,64}a{0,64}a{0,64}a{0,64}a{0,64}a{0,64}b$", "^a{0,9}a{0,9}a{0,9}b$"]
        for pattern in evil {
            let schema = try StrictJSON.parse(#"{"pattern":"\#(pattern.replacingOccurrences(of: "\\", with: "\\\\"))"}"#)
            let outcome = JSONSchemaValidator().validate(.string(String(repeating: "a", count: 40) + "!"), against: schema)
            guard case .unsupported = outcome else { return XCTFail("\(pattern): \(outcome)") }
        }
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
        for fine in ["^[A-Z]{3}$", "^[a-z0-9._-]+$", "^\\d{4}-\\d{2}$", "^(?:abc)x$", "^[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}$"] {
            let schema = try StrictJSON.parse(#"{"pattern":"\#(fine.replacingOccurrences(of: "\\", with: "\\\\"))"}"#)
            if case .unsupported = JSONSchemaValidator().validate(.string("x"), against: schema) { XCTFail("\(fine) should be allowed") }
        }
        // An over-long input is not matched at all.
        let schema = try StrictJSON.parse(#"{"pattern":"^a+$"}"#)
        guard case .unsupported = JSONSchemaValidator().validate(.string(String(repeating: "a", count: 10_000)), against: schema) else { return XCTFail() }
        // ... and a `not` cannot turn that refusal into acceptance.
        let negated = try StrictJSON.parse(#"{"not":{"pattern":"^a+$"}}"#)
        guard case .unsupported = JSONSchemaValidator().validate(.string(String(repeating: "a", count: 10_000)), against: negated) else { return XCTFail("fail-open under not") }
    }

    /// A caller that is cancelled is released at once, whatever the work is doing.
    func testWithDeadlineReleasesACancelledCaller() async {
        let task = Task { () -> Int in
            await withDeadline(30, fallback: 7) { () async -> Int in
                await withCheckedContinuation { (_: CheckedContinuation<Int, Never>) in }
            }
        }
        try? await Task.sleep(nanoseconds: 100_000_000)
        task.cancel()
        let started = Date()
        let value = await task.value
        XCTAssertEqual(value, 7)
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
    }

    // MARK: undecidable results never read as "different"

    func testNotCannotInvertAnUndecidableNumericComparison() throws {
        let big = "1234567890123456789012345678901234567890"
        let schema = try StrictJSON.parse(#"{"not":{"const":\#(big)}}"#)
        guard case .unsupported = JSONSchemaValidator().validate(try StrictJSON.parse(big), against: schema) else { return XCTFail("the forbidden value must not be accepted") }
        let enumSchema = try StrictJSON.parse(#"{"not":{"enum":[\#(big)]}}"#)
        guard case .unsupported = JSONSchemaValidator().validate(try StrictJSON.parse(big), against: enumSchema) else { return XCTFail() }
        // A definite difference is still decided.
        XCTAssertEqual(JSONSchemaValidator().validate(.int(5), against: try StrictJSON.parse(#"{"not":{"const":6}}"#)), .valid)
    }

    func testIdAndMalformedKeywordsFailClosedWhateverTheInstanceType() throws {
        func outcome(_ instance: String, _ schema: String) throws -> JSONSchemaValidator.Outcome {
            JSONSchemaValidator().validate(try StrictJSON.parse(instance), against: try StrictJSON.parse(schema))
        }
        guard case .unsupported = try outcome("1", #"{"$id":"https://evil.example/s","type":"integer"}"#) else { return XCTFail("$id changes reference resolution") }
        XCTAssertEqual(try outcome("1", #"{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"integer"}"#), .valid, "$schema stays an annotation")
        for bad in [#"{"minLength":"x"}"#, #"{"maxItems":-1}"#, #"{"required":"a"}"#, #"{"properties":[1]}"#, #"{"enum":"a"}"#, #"{"minimum":"1"}"#,
                    #"{"type":5}"#, #"{"anyOf":{}}"#, #"{"pattern":5}"#,
                    #"{"allOf":[]}"#, #"{"oneOf":[]}"#, #"{"anyOf":[5]}"#, #"{"additionalProperties":5}"#, #"{"items":5}"#, #"{"not":5}"#,
                    #"{"properties":{"a":5}}"#, #"{"$ref":5}"#, #"{"items":[{}]}"#,
                    #"{"enum":[]}"#, #"{"not":{"enum":[]}}"#, #"{"type":[]}"#, #"{"not":{"type":[]}}"#] {
            guard case .unsupported = try outcome("1", bad) else { return XCTFail("\(bad) must be refused even for a number") }
            guard case .unsupported = try outcome(#""text""#, bad) else { return XCTFail(bad) }
        }
    }

    // MARK: IPv6 classification

    func testOnlyGlobalUnicastIPv6IsPublic() {
        let denied = ["64:ff9b:1::1", "100::1", "2001:2::1", "2001::1", "2001:10::1", "2001:20::1", "2001:db8::1", "3fff::1", "fc00::1", "fe80::1", "fec0::1",
                      "ff02::1", "::", "::1", "4000::1", "5f00::1", "2620:4f:8000::1", "1::1"]
        for text in denied { XCTAssertFalse(PublicHostPolicy.parseAddress(text).map(PublicHostPolicy.isPublic) ?? true, text) }
        for text in ["2606:4700::1111", "2a00:1450:4001::1", "2001:4860:4860::8888", "2400:cb00::1", "2002:0808:0808::1", "64:ff9b::808:808"] {
            XCTAssertTrue(PublicHostPolicy.parseAddress(text).map(PublicHostPolicy.isPublic) ?? false, text)
        }
        XCTAssertFalse(PublicHostPolicy.parseAddress("2002:7f00:1::1").map(PublicHostPolicy.isPublic) ?? true, "6to4 of 127.0.0.1")
    }

    // MARK: malformed integrity claims

    private func sdJwt(_ payload: String) -> String { "e30.\(raw(payload)).c2ln~" }

    func testIntegrityClaimsAreReadAndMalformedOnesRefuse() throws {
        let ok = try TransactionDataCredential.integrityClaims(ofSdJwt: sdJwt(#"{"vct":"x","vct#integrity":"sha256-AAAA","other":1}"#))
        XCTAssertEqual(ok, ["vct#integrity": "sha256-AAAA"])
        XCTAssertEqual(try TransactionDataCredential.integrityClaims(ofSdJwt: sdJwt(#"{"vct":"x"}"#)), [:])
        for bad in [#"{"vct#integrity":null}"#, #"{"vct#integrity":{"a":1}}"#, #"{"vct#integrity":["sha256-A"]}"#, #"{"vct#integrity":5}"#,
                    #"{"vct#integrity":""}"#, #"{"transaction_data_types['u'].schema_uri#integrity":false}"#] {
            XCTAssertThrowsError(try TransactionDataCredential.integrityClaims(ofSdJwt: sdJwt(bad)), bad) {
                XCTAssertEqual(($0 as? TransactionDataError)?.reason, .metadataUnavailable)
            }
        }
        for unreadable in ["", "notajwt", "a.b~", "a.@@@.c~"] {
            XCTAssertThrowsError(try TransactionDataCredential.integrityClaims(ofSdJwt: unreadable), unreadable)
        }
    }

    // MARK: the unpinned-metadata warning

    private func captureWarnings(_ body: () async throws -> Void) async rethrows -> [String] {
        final class Box: @unchecked Sendable { let lock = NSLock(); var lines: [String] = [] }
        let box = Box()
        let previous = TransactionDataDiagnostics.sink
        TransactionDataDiagnostics.sink = { box.lock.lock(); box.lines.append($0); box.lock.unlock() }
        defer { TransactionDataDiagnostics.sink = previous }
        try await body()
        return box.lines
    }

    func testUnpinnedMetadataWarnsExactlyOncePerValidationEvenWithSeveralEntries() async throws {
        let lines = try await captureWarnings {
            _ = try await TransactionDataPipeline(source: source()).validate(request([entry(), entry(), entry()]))
        }
        XCTAssertEqual(lines.count, 1)
        XCTAssertEqual(lines.first, TransactionDataDiagnostics.unpinnedMessage)
    }

    func testAPinnedValidationDoesNotWarn() async throws {
        let pin = "sha256-" + Data(SHA256.hash(data: Data(metadata.utf8))).base64EncodedString()
        let lines = try await captureWarnings {
            _ = try await TransactionDataPipeline(source: source()).validate(request([entry(), entry()], pins: ["vct#integrity": pin]))
        }
        XCTAssertTrue(lines.isEmpty)
    }

    func testTheWarningContainsNothingPrivate() async throws {
        let lines = try await captureWarnings {
            _ = try await TransactionDataPipeline(source: source()).validate(request([entry()]))
            // ... including when the validation is then refused.
            _ = try? await TransactionDataPipeline(source: source()).validate(request([entry(#"{"transaction_id":"TX-9f3c-UNIQUE"}"#)]))
        }
        XCTAssertEqual(lines.count, 1, "the refused validation warns about nothing")
        let all = lines.joined(separator: "\n") + TransactionDataDiagnostics.unpinnedMessage
        for secret in ["secret-bank", "platinum", "TX-9f3c", "Zebra", "DE-UNIQUE", "98765", "EUR", "https://", entry(), "urn:eudi", "pay"] {
            XCTAssertFalse(all.contains(secret), "leaked: \(secret)")
        }
    }

    /// A validation that ends in a refusal used no metadata to a decision: no warning.
    func testARefusedValidationDoesNotWarn() async {
        let lines = await captureWarnings {
            _ = try? await TransactionDataPipeline(source: source()).validate(request([raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":{}}"#)]))
        }
        XCTAssertTrue(lines.isEmpty, "\(lines)")
    }

    /// Two credentials whose (vct, pin) pairs would collide in a delimiter-joined key must not share a cached document.
    func testTheMetadataCacheKeyCannotCollideAcrossVctAndPin() async {
        let vctA = "a\u{0}b"
        let docA = #"{"vct":"a\u0000b","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{"urn:eudi:sca:payment:1":{"schema":"urn:eudi:sca:payment:1"}}}"#
        final class ByVct: TransactionMetadataSource, @unchecked Sendable {
            let docs: [String: String]
            init(_ d: [String: String]) { docs = d }
            func typeMetadataDocument(vct: String, expectedIntegrity: String?, maxBytes: Int) async -> String? { docs[vct] }
            func fetchResource(uri: String, maxBytes: Int) async -> Data? { nil }
        }
        let src = ByVct([vctA: docA, "a": docA])   // "a" returns a document that is for ANOTHER vct
        let req = TransactionDataRequest(
            entries: [TransactionDataEntryInput(raw: raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["one","two"],"payload":\#(payload)}"#))],
            responseMode: "dc_api",
            credentials: [
                TransactionDataCredential(queryId: "one", format: "dc+sd-jwt", vct: vctA, integrityClaims: [:]),
                TransactionDataCredential(queryId: "two", format: "dc+sd-jwt", vct: "a", integrityClaims: ["vct#integrity": "b\u{0}"]),
            ]
        )
        do { _ = try await TransactionDataPipeline(source: src).validate(req); XCTFail("the second credential must be checked on its own, not served from the first's cache entry") }
        catch let e as TransactionDataError { XCTAssertEqual(e.reason, .metadataUnavailable) }
        catch { XCTFail("\(error)") }
    }

    func testAnUnpinnedReferencedDocumentAlsoWarnsOnce() async throws {
        final class DocSource: TransactionMetadataSource, @unchecked Sendable {
            let doc: String
            init(_ d: String) { doc = d }
            func typeMetadataDocument(vct: String, expectedIntegrity: String?, maxBytes: Int) async -> String? { doc }
            func fetchResource(uri: String, maxBytes: Int) async -> Data? { Data(#"{"type":"object"}"#.utf8) }
        }
        let doc = #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{"https://x.example/t":{"schema_uri":"https://schemas.example/s.json"}}}"#
        let pin = "sha256-" + Data(SHA256.hash(data: Data(doc.utf8))).base64EncodedString()
        let e = raw(#"{"type":"https://x.example/t","credential_ids":["pay"],"payload":{}}"#)
        let lines = try await captureWarnings {
            // metadata pinned, the referenced schema is not
            _ = try await TransactionDataPipeline(source: DocSource(doc)).validate(request([e, e], pins: ["vct#integrity": pin]))
        }
        XCTAssertEqual(lines.count, 1)
    }
}
