// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials
import SirosTransport

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Records what the pipeline asked for and answers from fixed documents.
private final class FakeSource: TransactionMetadataSource, @unchecked Sendable {
    var documents: [String: String] = [:]
    var resources: [String: Data] = [:]
    var delayNanos: UInt64 = 0
    private let lock = NSLock()
    private var _resourceFetches: [(uri: String, maxBytes: Int)] = []
    var resourceFetches: [(uri: String, maxBytes: Int)] { lock.lock(); defer { lock.unlock() }; return _resourceFetches }
    private var _expectedIntegrities: [String?] = []
    var expectedIntegrities: [String?] { lock.lock(); defer { lock.unlock() }; return _expectedIntegrities }

    func typeMetadataDocument(vct: String, expectedIntegrity: String?, maxBytes: Int) async -> String? {
        lock.lock(); _expectedIntegrities.append(expectedIntegrity); lock.unlock()
        if delayNanos > 0 { try? await Task.sleep(nanoseconds: delayNanos) }
        return documents[vct]
    }

    func fetchResource(uri: String, maxBytes: Int) async -> Data? {
        lock.lock(); _resourceFetches.append((uri, maxBytes)); lock.unlock()
        return resources[uri]
    }
}

final class TransactionDataPipelineTests: XCTestCase {
    private let vct = "https://pay.example/card"
    private let payment = "urn:eudi:sca:payment:1"
    private let validPayload = #"{"transaction_id":"tx-1","payee":{"name":"Shop AB","id":"SE1"},"currency":"EUR","amount":49.99}"#

    private func raw(_ json: String) -> String {
        Data(json.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private func entry(
        type: String? = "urn:eudi:sca:payment:1", ids: String = #"["pay"]"#, payload: String? = nil, extra: String = ""
    ) -> String {
        var members: [String] = []
        if let type { members.append(#""type":"\#(type)""#) }
        members.append(#""credential_ids":\#(ids)"#)
        if let payload { members.append(#""payload":\#(payload)"#) } else { members.append(#""payload":\#(validPayload)"#) }
        if !extra.isEmpty { members.append(extra) }
        return raw("{" + members.joined(separator: ",") + "}")
    }

    private func metadata(category: String? = "urn:eu:europa:ec:eudi:sua:sca", types: String? = nil, vct: String? = nil) -> String {
        var members = [#""vct":"\#(vct ?? self.vct)""#]
        if let category { members.append(#""category":"\#(category)""#) }
        members.append(#""transaction_data_types":\#(types ?? #"{"urn:eudi:sca:payment:1":{"schema":"urn:eudi:sca:payment:1"}}"#)"#)
        return "{" + members.joined(separator: ",") + "}"
    }

    private func credential(format: String = "dc+sd-jwt", pins: [String: String] = [:]) -> TransactionDataCredential {
        TransactionDataCredential(queryId: "pay", format: format, vct: vct, integrityClaims: pins)
    }

    private func source(_ doc: String? = nil) -> FakeSource {
        let s = FakeSource()
        s.documents[vct] = doc ?? metadata()
        return s
    }

    private func request(
        _ entries: [TransactionDataEntryInput], credentials: [TransactionDataCredential]? = nil, responseMode: String? = "dc_api"
    ) -> TransactionDataRequest {
        TransactionDataRequest(entries: entries, responseMode: responseMode, credentials: credentials ?? [credential()])
    }

    private func expectRefusal(
        _ reason: TransactionDataError.Reason, _ req: TransactionDataRequest, source: FakeSource? = nil,
        timeout: TimeInterval = 10, file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await TransactionDataPipeline(source: source ?? self.source(), fetchTimeout: timeout).validate(req)
            XCTFail("expected \(reason)", file: file, line: line)
        } catch let error as TransactionDataError {
            XCTAssertEqual(error.reason, reason, error.description, file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
    }

    // MARK: - Success

    func testValidPaymentIsAcceptedAndBoundByRawString() async throws {
        let e = entry()
        let result = try await TransactionDataPipeline(source: source()).validate(request([.init(raw: e)]))
        XCTAssertEqual(result.entries.count, 1)
        XCTAssertEqual(result.entries[0].raw, e)
        XCTAssertEqual(result.entries[0].type, payment)
        XCTAssertEqual(result.entries[0].acceptableHashAlgorithms, ["sha-256"])
        let binding = try XCTUnwrap(result.binding(forQueryId: "pay", factors: [
            AuthenticationFactor(.knowledge, "other"), AuthenticationFactor(.possession, "key_in_remote_wscd"),
        ]))
        XCTAssertEqual(binding.rawEntries, [e])
        XCTAssertEqual(binding.responseMode, "dc_api")
        let claims = try binding.kbJwtClaims(jti: "j")
        XCTAssertEqual(claims["transaction_data_hashes"] as? [String], [TransactionDataHashing.hash(raw: e, algorithm: "sha-256")!])
    }

    func testAgreeingHintIsAccepted() async throws {
        let e = entry()
        let hint = TransactionDataHint(type: payment, credentialIds: ["pay"], payload: try StrictJSON.parse(validPayload))
        _ = try await TransactionDataPipeline(source: source()).validate(request([.init(raw: e, hint: hint)]))
    }

    func testBuiltInTypeNotListedByTheAttestationIsAcceptedPerContract() async throws {
        let s = source(metadata(types: #"{"urn:eudi:sca:login_risk_transaction:1":{}}"#))
        _ = try await TransactionDataPipeline(source: s).validate(request([.init(raw: entry())]))
    }

    func testCustomTypeWithEmbeddedSchemaObject() async throws {
        let types = #"{"https://std.example/trx":{"schema":{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"],"additionalProperties":false}}}"#
        let s = source(metadata(types: types))
        let ok = entry(type: "https://std.example/trx", payload: #"{"n":3}"#)
        _ = try await TransactionDataPipeline(source: s).validate(request([.init(raw: ok)]))
        await expectRefusal(.schemaViolation, request([.init(raw: entry(type: "https://std.example/trx", payload: #"{"n":"3"}"#))]), source: s)
    }

    func testCustomTypeWithSchemaUriAndMatchingIntegrity() async throws {
        let schema = #"{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}"#
        let sri = "sha256-" + Data(SHA256.hash(data: Data(schema.utf8))).base64EncodedString()
        let types = #"{"https://std.example/trx":{"schema_uri":"https://std.example/s.json"}}"#
        let s = source(metadata(types: types))
        s.resources["https://std.example/s.json"] = Data(schema.utf8)
        let pinKey = "transaction_data_types['https://std.example/trx'].schema_uri#integrity"
        let e = entry(type: "https://std.example/trx", payload: #"{"n":3}"#)
        _ = try await TransactionDataPipeline(source: s).validate(request([.init(raw: e)], credentials: [credential(pins: [pinKey: sri])]))
        // A wrong pin refuses.
        await expectRefusal(.metadataUnavailable, request([.init(raw: e)], credentials: [credential(pins: [pinKey: "sha256-AAAA"])]), source: s)
    }

    // MARK: - Step 1: decoding and orchestrator consistency

    func testUndecodableRawIsRefused() async {
        for bad in ["", "!!!", "e+0", raw("not json"), raw("[1]"), raw(#"{"type":"t","type":"u"}"#)] {
            await expectRefusal(.invalidEntry, request([.init(raw: bad)]))
        }
    }

    func testOrchestratorHintDisagreementIsRefused() async throws {
        let e = entry()
        let payloadJson = try StrictJSON.parse(validPayload)
        let tampered = try StrictJSON.parse(#"{"transaction_id":"tx-1","payee":{"name":"Evil","id":"SE1"},"currency":"EUR","amount":1.00}"#)
        let hints = [
            TransactionDataHint(type: "urn:eudi:sca:login_risk_transaction:1", credentialIds: ["pay"], payload: payloadJson),
            TransactionDataHint(type: payment, credentialIds: ["other"], payload: payloadJson),
            TransactionDataHint(type: payment, credentialIds: ["pay"], payload: tampered),
        ]
        for hint in hints {
            await expectRefusal(.inconsistentWithOrchestrator, request([.init(raw: e, hint: hint)]))
        }
    }

    func testDecodedRawIsUsedNotTheHint() async throws {
        // The hint is never consulted for the result: it can only cause refusal.
        let e = entry()
        let result = try await TransactionDataPipeline(source: source()).validate(
            request([.init(raw: e, hint: TransactionDataHint(type: nil, credentialIds: nil, payload: nil))])
        )
        XCTAssertEqual(result.entries[0].payload, try StrictJSON.parse(validPayload))
    }

    // MARK: - Step 2: structure

    func testStructureRefusals() async {
        let cases = [
            entry(type: nil),
            entry(type: ""),
            entry(ids: "[]"),
            entry(ids: "[1]"),
            entry(ids: #"["unknown"]"#),
            raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"]}"#),
            raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":"x"}"#),
        ]
        for c in cases { await expectRefusal(.invalidEntry, request([.init(raw: c)])) }
    }

    func testEmptyRequestAndMissingResponseModeAreRefused() async {
        await expectRefusal(.invalidEntry, request([]))
        await expectRefusal(.invalidEntry, request([.init(raw: entry())], responseMode: nil))
        await expectRefusal(.invalidEntry, request([.init(raw: entry())], responseMode: ""))
    }

    // MARK: - Step 3: format

    func testNonSdJwtFormatIsRefused() async {
        for format in ["mso_mdoc", "ldp_vc", "jwt_vc_json"] {
            await expectRefusal(.unsupportedFormat, request([.init(raw: entry())], credentials: [credential(format: format)]))
        }
    }

    func testBothSdJwtFormatNamesAreAccepted() async throws {
        for format in ["dc+sd-jwt", "vc+sd-jwt"] {
            _ = try await TransactionDataPipeline(source: source()).validate(request([.init(raw: entry())], credentials: [credential(format: format)]))
        }
    }

    // MARK: - Step 4: SCA attestation and metadata

    func testNonScaCategoryIsRefused() async {
        await expectRefusal(.notScaAttestation, request([.init(raw: entry())]), source: source(metadata(category: nil)))
        await expectRefusal(.notScaAttestation, request([.init(raw: entry())]), source: source(metadata(category: "urn:eu:europa:ec:eudi:sua:other")))
    }

    func testUnavailableMetadataIsARefusalNotASkip() async {
        let empty = FakeSource()
        await expectRefusal(.metadataUnavailable, request([.init(raw: entry())]), source: empty)
        await expectRefusal(.metadataUnavailable, request([.init(raw: entry())], credentials: [TransactionDataCredential(queryId: "pay", format: "dc+sd-jwt", vct: nil)]))
        await expectRefusal(.metadataUnavailable, request([.init(raw: entry())]), source: source("not json"))
        await expectRefusal(.metadataUnavailable, request([.init(raw: entry())]), source: source(metadata(vct: "https://other.example/x")))
    }

    func testMetadataFetchIsBoundedInTime() async {
        let slow = source()
        slow.delayNanos = 5_000_000_000
        let started = Date()
        await expectRefusal(.metadataUnavailable, request([.init(raw: entry())]), source: slow, timeout: 0.2)
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
    }

    /// A source that never answers and ignores cancellation must still not hold validation past its time limit.
    func testAHungNonCancellableSourceStillTimesOut() async {
        final class Hung: TransactionMetadataSource, @unchecked Sendable {
            func typeMetadataDocument(vct: String, expectedIntegrity: String?, maxBytes: Int) async -> String? {
                await withCheckedContinuation { (_: CheckedContinuation<Void, Never>) in }
                return nil
            }
            func fetchResource(uri: String, maxBytes: Int) async -> Data? { nil }
        }
        let started = Date()
        do {
            _ = try await TransactionDataPipeline(source: Hung(), fetchTimeout: 0.2).validate(request([.init(raw: entry())]))
            XCTFail("expected refusal")
        } catch let e as TransactionDataError { XCTAssertEqual(e.reason, .metadataUnavailable) } catch { XCTFail("\(error)") }
        XCTAssertLessThan(Date().timeIntervalSince(started), 3)
    }

    /// Metadata accepted for one credential must not skip another credential's pin.
    func testAMetadataDocumentIsCheckedAgainstEveryBoundCredentialsOwnPin() async throws {
        let doc = metadata()
        let good = "sha256-" + Data(SHA256.hash(data: Data(doc.utf8))).base64EncodedString()
        let s = source(doc)
        let two = [TransactionDataCredential(queryId: "pay", format: "dc+sd-jwt", vct: vct, integrityClaims: ["vct#integrity": good]),
                   TransactionDataCredential(queryId: "other", format: "dc+sd-jwt", vct: vct, integrityClaims: ["vct#integrity": "sha256-AAAA"])]
        let e = entry(ids: #"["pay","other"]"#)
        await expectRefusal(.metadataUnavailable, request([.init(raw: e)], credentials: two), source: s)
        // The other way round, and an unpinned credential first.
        await expectRefusal(.metadataUnavailable, request([.init(raw: e)], credentials: [
            TransactionDataCredential(queryId: "pay", format: "dc+sd-jwt", vct: vct),
            TransactionDataCredential(queryId: "other", format: "dc+sd-jwt", vct: vct, integrityClaims: ["vct#integrity": "sha256-AAAA"]),
        ]), source: s)
        // Both correctly pinned is fine.
        let ok = [TransactionDataCredential(queryId: "pay", format: "dc+sd-jwt", vct: vct, integrityClaims: ["vct#integrity": good]),
                  TransactionDataCredential(queryId: "other", format: "dc+sd-jwt", vct: vct, integrityClaims: ["vct#integrity": good])]
        _ = try await TransactionDataPipeline(source: s).validate(request([.init(raw: e)], credentials: ok))
    }

    /// A hint that differs from raw only beyond binary floating point is still a disagreement.
    func testAHintThatDiffersOnlyInTheLastDigitsIsRefused() async throws {
        let rawEntry = raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":0.10000000000000001}}"#)
        let sameDouble = TransactionDataHint(type: payment, credentialIds: ["pay"], payload: TransactionDataEntryInput(
            TransactionData(type: payment, credentialIds: ["pay"], payload: .object_([
                "transaction_id": .string("t"), "payee": .object_(["name": .string("S"), "id": .string("1")]), "currency": .string("EUR"), "amount": .double(0.1),
            ]))).hint?.payload)
        await expectRefusal(.inconsistentWithOrchestrator, request([.init(raw: rawEntry, hint: sameDouble)]))
        // The honest hint (the same number) is accepted.
        let honestRaw = raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":49.99}}"#)
        let honest = TransactionDataEntryInput(TransactionData(type: payment, credentialIds: ["pay"], payload: .object_([
            "transaction_id": .string("t"), "payee": .object_(["name": .string("S"), "id": .string("1")]), "currency": .string("EUR"), "amount": .double(49.99),
        ])))
        let ok = TransactionDataEntryInput(raw: honestRaw, hint: honest.hint)
        _ = try await TransactionDataPipeline(source: source()).validate(request([ok]))
    }

    func testHintNumbersAreComparedExactly() async {
        let big = raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":9007199254740993}}"#)
        let hint = TransactionDataHint(type: payment, credentialIds: ["pay"],
                                       payload: try? StrictJSON.parse(#"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":9007199254740992}"#))
        await expectRefusal(.inconsistentWithOrchestrator, request([.init(raw: big, hint: hint)]))
    }

    func testASchemaUriIsFetchedOncePerRequestWithTheByteLimit() async throws {
        let schema = #"{"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}"#
        let types = #"{"https://std.example/trx":{"schema_uri":"https://std.example/s.json"}}"#
        let s = source(metadata(types: types))
        s.resources["https://std.example/s.json"] = Data(schema.utf8)
        let e = entry(type: "https://std.example/trx", ids: #"["pay","other"]"#, payload: #"{"n":3}"#)
        let creds = [credential(), TransactionDataCredential(queryId: "other", format: "dc+sd-jwt", vct: vct)]
        _ = try await TransactionDataPipeline(source: s, maxResourceBytes: 1234).validate(request([.init(raw: e), .init(raw: e)], credentials: creds))
        XCTAssertEqual(s.resourceFetches.count, 1, "four checks, one fetch")
        XCTAssertEqual(s.resourceFetches.first?.maxBytes, 1234, "the limit is handed to the source")
    }

    func testRequestLimitsAreEnforced() async {
        let many = (0..<17).map { _ in TransactionDataEntryInput(raw: entry()) }
        await expectRefusal(.invalidEntry, request(many))
        let ids = "[" + (0..<9).map { "\"c\($0)\"" }.joined(separator: ",") + "]"
        await expectRefusal(.invalidEntry, request([.init(raw: entry(ids: ids))]))
    }

    func testTheWholeRequestHasADeadline() async {
        let slow = source()
        slow.delayNanos = 400_000_000        // each lookup is within its own limit...
        let two = [TransactionDataCredential(queryId: "pay", format: "dc+sd-jwt", vct: vct),
                   TransactionDataCredential(queryId: "x", format: "dc+sd-jwt", vct: vct + "2")]
        slow.documents[vct + "2"] = metadata(vct: vct + "2")
        let e = entry(ids: #"["pay","x"]"#)
        let started = Date()
        do {
            _ = try await TransactionDataPipeline(source: slow, fetchTimeout: 5, requestTimeout: 0.5).validate(request([.init(raw: e)], credentials: two))
            XCTFail("expected refusal")
        } catch let error as TransactionDataError { XCTAssertEqual(error.reason, .metadataUnavailable) } catch { XCTFail("\(error)") }
        XCTAssertLessThan(Date().timeIntervalSince(started), 3, "...but together they exceed the request deadline")
    }

    func testOversizedMetadataIsRefused() async throws {
        let big = metadata().dropLast() + #","pad":"\#(String(repeating: "x", count: 2000))"}"#
        let s = source(String(big))
        do {
            _ = try await TransactionDataPipeline(source: s, maxMetadataBytes: 1000).validate(request([.init(raw: entry())]))
            XCTFail("expected refusal")
        } catch let e as TransactionDataError { XCTAssertEqual(e.reason, .metadataUnavailable) }
    }

    func testVctIntegrityMismatchIsRefusedAndTheExpectationIsPassedToTheSource() async throws {
        let doc = metadata()
        let good = "sha256-" + Data(SHA256.hash(data: Data(doc.utf8))).base64EncodedString()
        let s = source(doc)
        _ = try await TransactionDataPipeline(source: s).validate(request([.init(raw: entry())], credentials: [credential(pins: ["vct#integrity": good])]))
        XCTAssertEqual(s.expectedIntegrities.compactMap { $0 }, [good])
        await expectRefusal(.metadataUnavailable, request([.init(raw: entry())], credentials: [credential(pins: ["vct#integrity": "sha256-AAAA"])]), source: source(doc))
    }

    /// A pinned document that starts with a UTF-8 BOM is accepted: the pin covers the bytes as downloaded.
    func testPinnedMetadataWithALeadingBomIsAccepted() async throws {
        let doc = "\u{FEFF}" + metadata()
        let pin = "sha256-" + Data(SHA256.hash(data: Data(doc.utf8))).base64EncodedString()
        XCTAssertEqual(Array(doc.utf8.prefix(3)), [0xEF, 0xBB, 0xBF])
        _ = try await TransactionDataPipeline(source: source(doc)).validate(request([.init(raw: entry())], credentials: [credential(pins: ["vct#integrity": pin])]))
    }

    /// Which queries a transaction is bound to is read from the entries before validation.
    func testBoundQueryIdsAreReadFromTheEntries() {
        let a = raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay","pay2"],"payload":{}}"#)
        let b = raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["other"],"payload":{}}"#)
        XCTAssertEqual(TransactionDataPipeline.boundQueryIds(rawEntries: [a, b, "not-base64!", ""]), ["pay", "pay2", "other"])
        XCTAssertEqual(TransactionDataPipeline.boundQueryIds(rawEntries: []), [])
    }

    // MARK: - Step 5: type support

    func testUnknownTypeIsRefused() async {
        await expectRefusal(.unsupportedType, request([.init(raw: entry(type: "https://unlisted.example/trx"))]))
        await expectRefusal(.unsupportedType, request([.init(raw: entry(type: "urn:eudi:sca:payment:2"))]))
    }

    func testOneUnknownTypeAmongSeveralRefusesTheWholeRequest() async {
        await expectRefusal(.unsupportedType, request([.init(raw: entry()), .init(raw: entry(type: "https://unlisted.example/trx"))]))
    }

    // MARK: - Step 6: schema

    func testSchemaViolationsAreRefused() async {
        for payload in [
            #"{"transaction_id":"tx-1","payee":{"name":"S","id":"1"},"currency":"EUR","amount":"49.99"}"#,
            #"{"transaction_id":"tx-1","payee":{"name":"S"},"currency":"EUR","amount":1}"#,
            #"{"transaction_id":"tx-1","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1,"extra":true}"#,
            #"{}"#,
        ] {
            await expectRefusal(.schemaViolation, request([.init(raw: entry(payload: payload))]))
        }
    }

    func testUnevaluableSchemaIsRefusedNotSkipped() async {
        let types = #"{"https://std.example/trx":{"schema":{"type":"object","patternProperties":{"^x":{"type":"string"}}}}}"#
        await expectRefusal(.schemaViolation, request([.init(raw: entry(type: "https://std.example/trx", payload: #"{"x1":1}"#))]), source: source(metadata(types: types)))
    }

    func testAmbiguousOrMissingSchemaMetadataIsRefused() async {
        let both = #"{"https://std.example/trx":{"schema":{"type":"object"},"schema_uri":"https://std.example/s.json"}}"#
        await expectRefusal(.metadataUnavailable, request([.init(raw: entry(type: "https://std.example/trx", payload: "{}"))]), source: source(metadata(types: both)))
        let none = #"{"https://std.example/trx":{}}"#
        await expectRefusal(.metadataUnavailable, request([.init(raw: entry(type: "https://std.example/trx", payload: "{}"))]), source: source(metadata(types: none)))
        let unreachable = #"{"https://std.example/trx":{"schema_uri":"https://std.example/missing.json"}}"#
        await expectRefusal(.metadataUnavailable, request([.init(raw: entry(type: "https://std.example/trx", payload: "{}"))]), source: source(metadata(types: unreachable)))
    }

    // MARK: - Step 7: hash algorithm

    func testHashAlgorithmSelection() async throws {
        func accepted(_ alg: String) async throws -> [String] {
            let e = entry(extra: #""transaction_data_hashes_alg":\#(alg)"#)
            return try await TransactionDataPipeline(source: source()).validate(request([.init(raw: e)])).entries[0].acceptableHashAlgorithms
        }
        let a1 = try await accepted(#"["sha-1","sha-384","sha-256"]"#)
        XCTAssertEqual(a1, ["sha-384", "sha-256"])
        let a2 = try await accepted(#""sha-512""#)
        XCTAssertEqual(a2, ["sha-512"])
        let none = entry()
        let r = try await TransactionDataPipeline(source: source()).validate(request([.init(raw: none)]))
        XCTAssertEqual(r.entries[0].acceptableHashAlgorithms, ["sha-256"], "absent means sha-256")
        let validated = try await TransactionDataPipeline(source: source())
            .validate(request([.init(raw: entry(extra: #""transaction_data_hashes_alg":["sha-1","sha-384","sha-256"]"#))]))
        let binding = try XCTUnwrap(validated.binding(forQueryId: "pay", factors: []))
        XCTAssertEqual(binding.hashAlgorithm, "sha-384", "the first listed algorithm that is supported")
    }

    func testNoSupportedHashAlgorithmIsRefused() async {
        await expectRefusal(.unsupportedHashAlgorithm, request([.init(raw: entry(extra: #""transaction_data_hashes_alg":["sha-1","md5"]"#))]))
        await expectRefusal(.invalidEntry, request([.init(raw: entry(extra: #""transaction_data_hashes_alg":[]"#))]))
        await expectRefusal(.invalidEntry, request([.init(raw: entry(extra: #""transaction_data_hashes_alg":5"#))]))
    }

    // MARK: - Binding

    func testBindingCoversOnlyTheEntriesBoundToTheCredentialAndAgreesOnOneAlgorithm() async throws {
        let creds = [credential(), TransactionDataCredential(queryId: "other", format: "dc+sd-jwt", vct: vct)]
        let e1 = entry(extra: #""transaction_data_hashes_alg":["sha-512","sha-256"]"#)
        let e2 = entry(ids: #"["pay","other"]"#, extra: #""transaction_data_hashes_alg":["sha-256","sha-384"]"#)
        let e3 = entry(ids: #"["other"]"#)
        let result = try await TransactionDataPipeline(source: source()).validate(request([.init(raw: e1), .init(raw: e2), .init(raw: e3)], credentials: creds))
        let pay = try XCTUnwrap(result.binding(forQueryId: "pay", factors: []))
        XCTAssertEqual(pay.rawEntries, [e1, e2], "verifier order, only entries naming this credential")
        XCTAssertEqual(pay.hashAlgorithm, "sha-256", "the only algorithm every bound entry accepts")
        let other = try XCTUnwrap(result.binding(forQueryId: "other", factors: []))
        XCTAssertEqual(other.rawEntries, [e2, e3])
        XCTAssertNil(try result.binding(forQueryId: "none", factors: []))
    }

    func testBindingWithNoCommonAlgorithmIsRefused() async throws {
        let e1 = entry(extra: #""transaction_data_hashes_alg":["sha-512"]"#)
        let e2 = entry(extra: #""transaction_data_hashes_alg":["sha-384"]"#)
        let result = try await TransactionDataPipeline(source: source()).validate(request([.init(raw: e1), .init(raw: e2)]))
        XCTAssertThrowsError(try result.binding(forQueryId: "pay", factors: [])) {
            XCTAssertEqual(($0 as? TransactionDataError)?.reason, .unsupportedHashAlgorithm)
        }
    }

    // MARK: - KB-JWT claims

    private func binding(factors: [AuthenticationFactor], alg: String = "sha-256", entries: [String] = ["abc"]) -> TransactionDataBinding {
        TransactionDataBinding(rawEntries: entries, hashAlgorithm: alg, responseMode: "direct_post.jwt", factors: factors)
    }

    func testClaimsMatchTheVerifierContract() throws {
        let b = binding(factors: [AuthenticationFactor(.knowledge, "pin_6_or_more_digits"), AuthenticationFactor(.inherence, "fingerprint_device")])
        let c = try b.kbJwtClaims()
        XCTAssertEqual(c["transaction_data_hashes_alg"] as? String, "sha-256", "a string, not an array")
        XCTAssertEqual(c["response_mode"] as? String, "direct_post.jwt")
        XCTAssertEqual((c["transaction_data_hashes"] as? [String])?.count, 1)
        let amr = try XCTUnwrap(c["amr"] as? [[String: String]])
        XCTAssertEqual(amr, [["knowledge": "pin_6_or_more_digits"], ["inherence": "fingerprint_device"]])
        XCTAssertFalse(try XCTUnwrap(c["jti"] as? String).isEmpty)
    }

    func testJtiIsFreshEveryTime() throws {
        let b = binding(factors: [AuthenticationFactor(.knowledge, "other"), AuthenticationFactor(.possession, "other")])
        let jtis = try (0..<50).map { _ in try XCTUnwrap(b.kbJwtClaims()["jti"] as? String) }
        XCTAssertEqual(Set(jtis).count, 50)
    }

    func testFewerThanTwoCategoriesIsRefused() {
        let cases: [[AuthenticationFactor]] = [
            [],
            [AuthenticationFactor(.possession, "key_in_remote_wscd")],
            [AuthenticationFactor(.knowledge, "other"), AuthenticationFactor(.knowledge, "pattern")],
        ]
        for factors in cases {
            XCTAssertThrowsError(try binding(factors: factors).kbJwtClaims()) {
                XCTAssertEqual(($0 as? TransactionDataError)?.reason, .insufficientAuthenticationFactors)
            }
        }
    }

    func testFactorOutsideTheVocabularyIsRefused() {
        let b = binding(factors: [AuthenticationFactor(.knowledge, "pwd"), AuthenticationFactor(.possession, "hwk")])
        XCTAssertThrowsError(try b.kbJwtClaims()) {
            XCTAssertEqual(($0 as? TransactionDataError)?.reason, .insufficientAuthenticationFactors)
        }
    }

    func testBindingWithUnsupportedAlgorithmOrNoEntriesIsRefused() {
        let f = [AuthenticationFactor(.knowledge, "other"), AuthenticationFactor(.possession, "other")]
        XCTAssertThrowsError(try binding(factors: f, alg: "sha-1").kbJwtClaims()) {
            XCTAssertEqual(($0 as? TransactionDataError)?.reason, .unsupportedHashAlgorithm)
        }
        XCTAssertThrowsError(try binding(factors: f, entries: []).kbJwtClaims()) {
            XCTAssertEqual(($0 as? TransactionDataError)?.reason, .invalidEntry)
        }
    }

    // MARK: - Wire conversion

    func testEntryInputFromTheWireKeepsRawAndPayload() throws {
        let e = entry()
        let wire = try JSONDecoder().decode(TransactionData.self, from: Data(
            #"{"raw":"\#(e)","type":"\#(payment)","credential_ids":["pay"],"payload":{"amount":49.99,"n":null,"t":true}}"#.utf8
        ))
        let input = TransactionDataEntryInput(wire)
        XCTAssertEqual(input.raw, e)
        XCTAssertEqual(input.hint?.payload?["amount"], .decimal("49.99"), "a hint number is kept as its decimal text")
        XCTAssertEqual(input.hint?.payload?["t"], .bool(true))
        XCTAssertEqual(input.hint?.payload?["n"], .null)
        // A wire entry with no raw cannot be hashed: refused.
        let noRaw = TransactionDataEntryInput(TransactionData(type: payment, credentialIds: ["pay"]))
        XCTAssertEqual(noRaw.raw, "")
    }

    func testWireEntryWithoutRawIsRefused() async {
        await expectRefusal(.invalidEntry, request([TransactionDataEntryInput(TransactionData(type: payment, credentialIds: ["pay"]))]))
    }
}
