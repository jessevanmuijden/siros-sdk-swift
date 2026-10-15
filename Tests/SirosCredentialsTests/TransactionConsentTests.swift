// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

private final class Source: TransactionMetadataSource, @unchecked Sendable {
    var documents: [String: String] = [:]
    var resources: [String: Data] = [:]
    func typeMetadataDocument(vct: String, expectedIntegrity: String?, maxBytes: Int) async -> String? { documents[vct] }
    var delayNanos: UInt64 = 0
    private let lock = NSLock()
    private var _fetches: [String: Int] = [:]
    var fetches: [String: Int] { lock.lock(); defer { lock.unlock() }; return _fetches }
    func fetchResource(uri: String, maxBytes: Int) async -> Data? {
        lock.lock(); _fetches[uri, default: 0] += 1; lock.unlock()
        if delayNanos > 0 { try? await Task.sleep(nanoseconds: delayNanos) }
        return resources[uri]
    }
}

private final class Handler: TransactionConsentHandler, @unchecked Sendable {
    enum Mode { case yes, no, throwing, hang }
    var mode: Mode
    private let lock = NSLock()
    private var _seen: [TransactionConsentRequest] = []
    var seen: [TransactionConsentRequest] { lock.lock(); defer { lock.unlock() }; return _seen }
    struct Boom: Error {}
    init(_ mode: Mode) { self.mode = mode }
    func confirm(_ request: TransactionConsentRequest) async throws -> Bool {
        lock.lock(); _seen.append(request); lock.unlock()
        switch mode {
        case .yes: return true
        case .no: return false
        case .throwing: throw Boom()
        case .hang: await withCheckedContinuation { (_: CheckedContinuation<Void, Never>) in } ; return true
        }
    }
}

/// A capability probe with a fixed answer that records which keys it was asked about.
private final class FixedCapability: ScaAuthenticationCapability, @unchecked Sendable {
    let can: Bool
    private let lock = NSLock()
    private var asked: [String?] = []
    var queries: [String?] { lock.lock(); defer { lock.unlock() }; return asked }
    init(can: Bool) { self.can = can }
    func canEstablishTwoCategories(keyId: String?) async -> Bool {
        lock.lock(); asked.append(keyId); lock.unlock()
        return can
    }
}

/// Display model, consent handling and logging (TS12 v1.0.1 3.1, 3.3, 5.3).
final class TransactionConsentTests: XCTestCase {
    private let vct = "https://pay.example/card"

    private func raw(_ json: String) -> String {
        Data(json.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private let payload = #"{"transaction_id":"tx-1","payee":{"name":"Shop AB","id":"SE1"},"currency":"EUR","amount":49.99}"#

    private func paymentRaw(payload: String? = nil) -> String {
        raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["pay"],"payload":\#(payload ?? self.payload)}"#)
    }

    private func claim(_ path: String, level: Int?, labels: [(String, String)]) -> String {
        let display = labels.map { #"{"lang":"\#($0.0)","label":"\#($0.1)"}"# }.joined(separator: ",")
        let vis = level.map { #","visualisation":\#($0)"# } ?? ""
        return #"{"path":["payload",\#(path)]\#(vis),"display":[\#(display)]}"#
    }

    private func claimsJson(levelOverrides: [String: Int?] = [:], skip: Set<String> = []) -> String {
        let all: [(String, String, Int?, [(String, String)])] = [
            (#""amount""#, "amount", 1, [("en", "Amount"), ("sv", "Belopp")]),
            (#""currency""#, "currency", 1, [("en", "Currency"), ("sv", "Valuta")]),
            (#""payee","name""#, "payee.name", 2, [("en", "Payee"), ("sv", "Mottagare")]),
            (#""payee","id""#, "payee.id", nil, [("en", "Payee ID")]),
            (#""transaction_id""#, "transaction_id", 4, [("en", "Transaction ID")]),
        ]
        let items = all.filter { !skip.contains($0.1) }.map { claim($0.0, level: levelOverrides[$0.1] ?? $0.2, labels: $0.3) }
        return "[" + items.joined(separator: ",") + "]"
    }

    private func withClaim(_ claims: String, _ extra: String) -> String {
        String(claims.dropLast(1)) + "," + extra + "]"
    }

    private func firstLog(_ log: InMemoryTransactionLogStore) async throws -> TransactionLogEntry {
        let all = await log.entries()
        return try XCTUnwrap(all.first)
    }

    private let labels = #"""
    {"affirmative_action_label":[{"lang":"en","value":"Confirm Payment"},{"lang":"sv","value":"Bekräfta betalning"}],
     "denial_action_label":[{"lang":"en","value":"Cancel Payment"}],
     "transaction_title":[{"lang":"en","value":"Confirm your payment"}],
     "security_hint":[{"lang":"en","value":"Never confirm a payment you did not start."}]}
    """#

    private func metadata(claims: String? = nil, labels: String? = nil, extra: String = "", noEntry: Bool = false) -> String {
        let entry = #"{"schema":"urn:eudi:sca:payment:1","claims":\#(claims ?? claimsJson()),"ui_labels":\#(labels ?? self.labels)\#(extra)}"#
        let types = noEntry ? "{}" : #"{"urn:eudi:sca:payment:1":\#(entry)}"#
        return #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":\#(types)}"#
    }

    private func source(_ doc: String? = nil) -> Source {
        let s = Source()
        s.documents[vct] = doc ?? metadata()
        return s
    }

    private func credential(pins: [String: String] = [:]) -> TransactionDataCredential {
        TransactionDataCredential(queryId: "pay", format: "dc+sd-jwt", vct: vct, integrityClaims: pins)
    }

    private func request(_ raws: [String]? = nil) -> TransactionDataRequest {
        TransactionDataRequest(entries: (raws ?? [paymentRaw()]).map { TransactionDataEntryInput(raw: $0) }, responseMode: "dc_api", credentials: [credential()])
    }

    private func service(
        _ source: Source, handler: Handler?, canEstablish: Bool = true, log: InMemoryTransactionLogStore = InMemoryTransactionLogStore(),
        timeout: TimeInterval = 5
    ) -> TransactionDataService {
        TransactionDataService(
            source: source, consentHandler: handler, authentication: FixedCapability(can: canEstablish),
            log: log, consentTimeout: timeout, fetchTimeout: 2
        )
    }

    private func context(signed: Bool? = nil, locale: String = "en-GB") -> TransactionDataContext {
        TransactionDataContext(verifier: "Shop AB (verified)", requestSigned: signed, locale: locale, credentialNames: ["pay": "Visa card"])
    }

    private func expectRefusal(_ reason: TransactionDataError.Reason, _ svc: TransactionDataService, _ req: TransactionDataRequest? = nil,
                               file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await svc.process(req ?? request(), context: context())
            XCTFail("expected \(reason)", file: file, line: line)
        } catch let e as TransactionDataError {
            XCTAssertEqual(e.reason, reason, e.description, file: file, line: line)
        } catch { XCTFail("\(error)", file: file, line: line) }
    }

    // MARK: - Model

    func testModelCarriesLabelsLevelsAndOrder() async throws {
        let h = Handler(.yes)
        _ = try await service(source(), handler: h).process(request(), context: context(signed: false))
        let model = try XCTUnwrap(h.seen.first)
        XCTAssertEqual(model.verifier, "Shop AB (verified)")
        XCTAssertEqual(model.credentialName, "Visa card")
        XCTAssertEqual(model.requestSigned, false)
        XCTAssertEqual(model.locale, "en-GB")
        let e = try XCTUnwrap(model.entries.first)
        XCTAssertEqual(e.typeName, "Payment Confirmation")
        XCTAssertEqual(e.title, "Confirm your payment")
        XCTAssertEqual(e.affirmativeLabel, "Confirm Payment")
        XCTAssertEqual(e.denialLabel, "Cancel Payment")
        XCTAssertEqual(e.securityHint, "Never confirm a payment you did not start.")
        // level 1 (claim order), level 2; the payee id has no level set (default 3) but is a decision field of a built-in type, so it is raised to 2; level 4
        XCTAssertEqual(e.fields.map(\.label), ["Amount", "Currency", "Payee", "Payee ID", "Transaction ID"])
        XCTAssertEqual(e.fields.map(\.level), [1, 1, 2, 2, 4])
        XCTAssertEqual(e.fields.first?.value, "49.99")
        XCTAssertEqual(e.fields.first?.path, ["amount"])
        XCTAssertEqual(e.fields.first(where: { $0.label == "Payee" })?.path, ["payee", "name"])
    }

    func testUnsignedFlagIsNilWhenUnknown() async throws {
        let h = Handler(.yes)
        _ = try await service(source(), handler: h).process(request(), context: context(signed: nil))
        XCTAssertNil(h.seen.first?.requestSigned)
    }

    func testLocaleSelection() async throws {
        for (locale, amount, affirmative) in [("sv-SE", "Belopp", "Bekräfta betalning"), ("sv", "Belopp", "Bekräfta betalning"),
                                              ("en_US", "Amount", "Confirm Payment"), ("fr", "Amount", "Confirm Payment")] {
            let h = Handler(.yes)
            _ = try await service(source(), handler: h).process(request(), context: context(locale: locale))
            let e = try XCTUnwrap(h.seen.first?.entries.first)
            XCTAssertEqual(e.fields.first?.label, amount, locale)
            XCTAssertEqual(e.affirmativeLabel, affirmative, locale)
        }
    }

    func testEnglishIsTheFallbackBeforeTheFirstOfferedLanguage() async throws {
        let l = #"{"affirmative_action_label":[{"lang":"de","value":"Bestätigen"},{"lang":"en","value":"Confirm"}]}"#
        let h = Handler(.yes)
        _ = try await service(source(metadata(labels: l)), handler: h).process(request(), context: context(locale: "fr"))
        XCTAssertEqual(h.seen.first?.entries.first?.affirmativeLabel, "Confirm")
        let h2 = Handler(.yes)
        let onlyDe = #"{"affirmative_action_label":[{"lang":"de","value":"Bestätigen"},{"lang":"nl","value":"Bevestig"}]}"#
        _ = try await service(source(metadata(labels: onlyDe)), handler: h2).process(request(), context: context(locale: "fr"))
        XCTAssertEqual(h2.seen.first?.entries.first?.affirmativeLabel, "Bestätigen", "the first offered when nothing matches")
    }

    func testFieldsAreOrderedByLevelNotByMetadataOrder() async throws {
        // Metadata lists level 4, 3, 2, 1 in that order.
        let c = "[" + [
            claim(#""transaction_id""#, level: 4, labels: [("en", "Transaction ID")]),
            claim(#""payee","id""#, level: nil, labels: [("en", "Payee ID")]),
            claim(#""payee","name""#, level: 2, labels: [("en", "Payee")]),
            claim(#""currency""#, level: 1, labels: [("en", "Currency")]),
            claim(#""amount""#, level: 1, labels: [("en", "Amount")]),
        ].joined(separator: ",") + "]"
        let h = Handler(.yes)
        _ = try await service(source(metadata(claims: c)), handler: h).process(request(), context: context())
        let fields = try XCTUnwrap(h.seen.first?.entries.first?.fields)
        XCTAssertEqual(fields.map(\.level), [1, 1, 2, 2, 4])
        XCTAssertEqual(fields.map(\.label), ["Currency", "Amount", "Payee ID", "Payee", "Transaction ID"], "claim order within a level")
    }

    func testOversizedReferencedDocumentRefuses() async {
        let entry = #"{"schema":"urn:eudi:sca:payment:1","claims_uri":"https://pay.example/c.json","ui_labels":\#(labels)}"#
        let doc = #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{"urn:eudi:sca:payment:1":\#(entry)}}"#
        let s = source(doc)
        let padded = String(claimsJson().dropLast(1)) + String(repeating: " ", count: 300 * 1024) + "]"
        s.resources["https://pay.example/c.json"] = Data(padded.utf8)
        await expectRefusal(.metadataUnavailable, service(s, handler: Handler(.yes)))
    }

    func testCommonLabelsOnlyWhenEveryEntryAgrees() {
        func entry(_ yes: String, _ no: String?) -> TransactionConsentEntry {
            TransactionConsentEntry(title: nil, typeName: "t", fields: [], affirmativeLabel: yes, denialLabel: no, securityHint: nil)
        }
        func request(_ entries: [TransactionConsentEntry]) -> TransactionConsentRequest {
            TransactionConsentRequest(verifier: "v", credentialName: "c", entries: entries, requestSigned: nil, locale: "en")
        }
        let same = request([entry("Pay", "Cancel"), entry("Pay", "Cancel")])
        XCTAssertEqual(same.commonAffirmativeLabel, "Pay")
        XCTAssertEqual(same.commonDenialLabel, "Cancel")
        let mixed = request([entry("Pay", "Cancel"), entry("Log in", "Cancel")])
        XCTAssertNil(mixed.commonAffirmativeLabel, "one button must not consent to differently worded transactions under the first one's label")
        XCTAssertEqual(mixed.commonDenialLabel, "Cancel")
        XCTAssertNil(request([entry("Pay", "No"), entry("Pay", nil)]).commonDenialLabel)
        XCTAssertNil(request([]).commonAffirmativeLabel)
    }

    func testDecimalsAreShownExactlyAsSent() async throws {
        let h = Handler(.yes)
        let p = paymentRaw(payload: #"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":0.10000000000000001}"#)
        _ = try await service(source(), handler: h).process(request([p]), context: context())
        XCTAssertEqual(h.seen.first?.entries.first?.fields.first?.value, "0.10000000000000001")
        let trailing = paymentRaw(payload: #"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":10.50}"#)
        let h2 = Handler(.yes)
        _ = try await service(source(), handler: h2).process(request([trailing]), context: context())
        XCTAssertEqual(h2.seen.first?.entries.first?.fields.first?.value, "10.50")
    }

    // MARK: text safety

    func testUnsafeValuesAreRefusedNotCleaned() async {
        let evil: [(String, String)] = [
            ("bidi override", "Shop \u{202E}AB"), ("bidi isolate", "Shop \u{2066}AB\u{2069}"), ("zero width", "Sh\u{200B}op"),
            ("zwj", "a\u{200D}b"), ("bom", "\u{FEFF}Shop"), ("newline", "Shop\nPay 1 EUR"), ("tab", "A\tB"), ("nul", "A\u{0}B"),
            ("line separator", "A\u{2028}B"), ("private use", "A\u{E000}B"),
        ]
        for (name, value) in evil {
            let payload = #"{"transaction_id":"t","payee":{"name":"\#(value.unicodeScalars.map { String(format: "\\u%04x", $0.value) }.joined())","id":"1"},"currency":"EUR","amount":1}"#
            let h = Handler(.yes)
            do { _ = try await service(source(), handler: h).process(request([paymentRaw(payload: payload)]), context: context()); XCTFail(name) }
            catch let e as TransactionDataError { XCTAssertEqual(e.reason, .invalidEntry, name) } catch { XCTFail("\(error)") }
            XCTAssertTrue(h.seen.isEmpty, "\(name): the user is never shown it")
        }
    }

    func testOrdinaryInternationalTextIsAccepted() async throws {
        let h = Handler(.yes)
        let payload = #"{"transaction_id":"t","payee":{"name":"Åkesson & Söner – 東京 \ud83d\ude00","id":"1"},"currency":"EUR","amount":1}"#
        _ = try await service(source(), handler: h).process(request([paymentRaw(payload: payload)]), context: context())
        XCTAssertEqual(h.seen.first?.entries.first?.fields.first(where: { $0.label == "Payee" })?.value, "Åkesson & Söner – 東京 \u{1F600}")
    }

    func testOverlongValuesAreRefusedNotTruncated() async {
        let long = String(repeating: "x", count: 1001)
        let payload = #"{"transaction_id":"t","payee":{"name":"\#(long)","id":"1"},"currency":"EUR","amount":1}"#
        await expectRefusal(.invalidEntry, service(source(), handler: Handler(.yes)), request([paymentRaw(payload: payload)]))
        let ok = String(repeating: "x", count: 1000)
        _ = try? await service(source(), handler: Handler(.yes)).process(request([paymentRaw(payload: #"{"transaction_id":"t","payee":{"name":"\#(ok)","id":"1"},"currency":"EUR","amount":1}"#)]), context: context())
    }

    func testUnsafeLabelsFromMetadataAreRefused() async {
        let l = #"{"affirmative_action_label":[{"lang":"en","value":"Confirm\u202E"}]}"#
        await expectRefusal(.invalidEntry, service(source(metadata(labels: l)), handler: Handler(.yes)))
        let c = claimsJson().replacingOccurrences(of: #""label":"Amount""#, with: #""label":"Amo\u200Bunt""#)
        await expectRefusal(.invalidEntry, service(source(metadata(claims: c)), handler: Handler(.yes)))
    }

    // MARK: every displayed string is checked, whoever supplied it

    func testVerifierCredentialAndAttributeNamesAreCheckedToo() async {
        let unsafe = "Shop\u{202E}AB"
        func refuse(_ ctx: TransactionDataContext, _ what: String, line: UInt = #line) async {
            let h = Handler(.yes)
            do { _ = try await service(source(), handler: h).process(request(), context: ctx); XCTFail(what, line: line) }
            catch let e as TransactionDataError { XCTAssertEqual(e.reason, .invalidEntry, what, line: line) } catch { XCTFail("\(error)", line: line) }
            XCTAssertTrue(h.seen.isEmpty, what, line: line)
        }
        await refuse(TransactionDataContext(verifier: unsafe, locale: "en", credentialNames: ["pay": "Visa"]), "verifier")
        await refuse(TransactionDataContext(verifier: "v", locale: "en", credentialNames: ["pay": unsafe]), "credential name")
        await refuse(TransactionDataContext(verifier: "v", locale: "en", credentialNames: ["pay": "Visa"], disclosedClaims: ["pay": ["given\nname"]]), "claim name")
        await refuse(TransactionDataContext(verifier: String(repeating: "v", count: 201), locale: "en"), "over-long verifier")
    }

    func testACustomTypeNameIsChecked() async {
        let types = #"{"https://std.example/t\u202E":{"schema":{"type":"object"},"claims":[],"ui_labels":{"affirmative_action_label":[{"lang":"en","value":"OK"}]}}}"#
        let s = Source()
        s.documents[vct] = #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":\#(types)}"#
        let e = raw(#"{"type":"https://std.example/t\u202E","credential_ids":["pay"],"payload":{}}"#)
        let h = Handler(.yes)
        let svc = service(s, handler: h)
        do { _ = try await svc.process(request([e]), context: context()); XCTFail("must refuse") }
        catch let err as TransactionDataError { XCTAssertEqual(err.reason, .invalidEntry) } catch { XCTFail("\(error)") }
        XCTAssertTrue(h.seen.isEmpty)
    }

    // MARK: display floor for built-in types

    /// Whatever the metadata says, what is paid, in what currency, and to whom is shown at level 2 or higher.
    func testBuiltInDecisionFieldsAreNeverBelowLevelTwo() async throws {
        let c = "[" + [
            claim(#""amount""#, level: 4, labels: [("en", "Amount")]),
            claim(#""currency""#, level: 3, labels: [("en", "Currency")]),
            claim(#""payee","name""#, level: 4, labels: [("en", "Payee")]),
            claim(#""payee","id""#, level: nil, labels: [("en", "Payee ID")]),
            claim(#""transaction_id""#, level: 4, labels: [("en", "Transaction ID")]),
        ].joined(separator: ",") + "]"
        let h = Handler(.yes)
        _ = try await service(source(metadata(claims: c)), handler: h).process(request(), context: context())
        let fields = try XCTUnwrap(h.seen.first?.entries.first?.fields)
        func level(_ label: String) -> Int? { fields.first { $0.label == label }?.level }
        XCTAssertEqual(level("Amount"), 2)
        XCTAssertEqual(level("Currency"), 2)
        XCTAssertEqual(level("Payee"), 2)
        XCTAssertEqual(level("Payee ID"), 2)
        XCTAssertEqual(level("Transaction ID"), 4, "a non-decision field keeps what the metadata says")
        XCTAssertTrue(fields.allSatisfy { $0.level <= 4 })
    }

    func testTheDefaultLevelIsThreeForAFieldWithNoneSet() async throws {
        let c = withClaim(claimsJson(skip: ["transaction_id"]), #"{"path":["payload","transaction_id"],"display":[{"lang":"en","label":"Transaction ID"}]}"#)
        let h = Handler(.yes)
        _ = try await service(source(metadata(claims: c)), handler: h).process(request(), context: context())
        XCTAssertEqual(h.seen.first?.entries.first?.fields.first(where: { $0.label == "Transaction ID" })?.level, 3)
    }

    func testBuiltInDecisionFieldsKeepAHigherLevelWhenTheMetadataGivesOne() async throws {
        let h = Handler(.yes)
        _ = try await service(source(), handler: h).process(request(), context: context())
        XCTAssertEqual(h.seen.first?.entries.first?.fields.first(where: { $0.label == "Amount" })?.level, 1)
    }

    func testADecisionFieldWithoutANameCannotBeHiddenByLevelFour() async {
        let c = withClaim(claimsJson(skip: ["amount"]), #"{"path":["payload","amount"],"visualisation":4}"#)
        await expectRefusal(.metadataUnavailable, service(source(metadata(claims: c)), handler: Handler(.yes)))
    }

    // MARK: attributes shown with the transaction

    func testTheRequestedAttributesAreInTheConsentModel() async throws {
        let h = Handler(.yes)
        let ctx = TransactionDataContext(verifier: "v", locale: "en", credentialNames: ["pay": "Visa card"],
                                         disclosedClaims: ["pay": ["given_name", "family_name"]])
        _ = try await service(source(), handler: h).process(request(), context: ctx)
        XCTAssertEqual(h.seen.first?.attributes, [TransactionConsentAttributes(credentialName: "Visa card", claims: ["given_name", "family_name"])])
    }

    // MARK: log content

    func testRefusalsAreOneRecordPerRequestAndEachRecordNamesItsOwnCredential() async throws {
        let many = (0..<5).map { _ in paymentRaw() }
        let refused = TransactionLogEntry.records(rawEntries: many, verifier: "v", credentialLabel: { _ in "c" }, outcome: .refused, reason: "invalidEntry")
        XCTAssertEqual(refused.count, 1, "an unauthenticated sender cannot multiply refusal records")
        let consented = TransactionLogEntry.records(rawEntries: many, verifier: "v", credentialLabel: { _ in "c" }, outcome: .consented)
        XCTAssertEqual(consented.count, 5)
        let a = raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["a"],"payload":{"transaction_id":"1"}}"#)
        let b = raw(#"{"type":"urn:eudi:sca:payment:1","credential_ids":["b"],"payload":{"transaction_id":"2"}}"#)
        let both = TransactionLogEntry.records(rawEntries: [a, b], verifier: "v", credentialLabel: { $0 == "a" ? "Card A" : "Card B" }, outcome: .consented)
        XCTAssertEqual(both.map(\.credential), ["Card A", "Card B"])
    }

    /// Text from a request cannot spoof the log: newlines, bidi controls and other format characters are neutralised.
    func testLoggedTextIsNeutralised() {
        let spoof = "Refund\nApproved \u{202E}evil\u{200B}\u{0007}"
        let e = TransactionLogEntry(
            subject: TransactionLogSubject(transactionId: spoof, typeName: spoof, entities: ["payee": spoof]),
            verifier: spoof, credential: spoof, outcome: .refused, reason: "unsupportedType"
        )
        for value in [e.transactionId!, e.typeName!, e.entities["payee"]!, e.verifier, e.credential] {
            XCTAssertEqual(value, "Refund\u{FFFD}Approved \u{FFFD}evil\u{FFFD}\u{FFFD}")
            XCTAssertFalse(value.contains("\n"))
        }
        XCTAssertEqual(TransactionLogEntry.displaySafe("plain text"), "plain text")
    }

    func testLoggedFieldsAreCapped() {
        let long = String(repeating: "y", count: 5000)
        let e = TransactionLogEntry(subject: TransactionLogSubject(transactionId: long, typeName: long, entities: ["payee": long]),
                                    verifier: long, credential: long, outcome: .consented)
        for value in [e.transactionId!, e.typeName!, e.entities["payee"]!, e.verifier, e.credential] {
            XCTAssertEqual(value.count, TransactionLogEntry.maxFieldLength)
            XCTAssertTrue(value.hasSuffix(TransactionLogEntry.truncationMarker))
        }
        let short = TransactionLogEntry(subject: TransactionLogSubject(transactionId: "tx-1", typeName: "t"), verifier: "v", credential: "c", outcome: .consented)
        XCTAssertEqual(short.transactionId, "tx-1", "short values are untouched")
    }

    func testRefusalsDoNotEvictConsentedRecordsInMemory() async throws {
        let log = InMemoryTransactionLogStore(capacity: 3, refusedCapacity: 2)
        func e(_ i: Int, _ o: TransactionLogEntry.Outcome) -> TransactionLogEntry {
            TransactionLogEntry(id: "\(i)", timestamp: Int64(i), subject: TransactionLogSubject(transactionId: nil, typeName: nil), verifier: "v", credential: "c", outcome: o)
        }
        try await log.append([e(1, .consented), e(2, .declined)])
        for i in 10..<40 { try await log.append([e(i, .refused)]) }
        let all = await log.entries()
        XCTAssertEqual(all.filter { $0.outcome != .refused }.count, 2)
        XCTAssertEqual(all.filter { $0.outcome == .refused }.count, 2)
    }

    func testOptionalLabelsAreAbsentWhenNotProvided() async throws {
        let h = Handler(.yes)
        let l = #"{"affirmative_action_label":[{"lang":"en","value":"OK"}]}"#
        _ = try await service(source(metadata(labels: l)), handler: h).process(request(), context: context())
        let e = try XCTUnwrap(h.seen.first?.entries.first)
        XCTAssertNil(e.title)
        XCTAssertNil(e.denialLabel)
        XCTAssertNil(e.securityHint, "no hint is shown unless the attestation provides one")
    }

    func testMissingRequiredLabelRefuses() async {
        await expectRefusal(.metadataUnavailable, service(source(metadata(labels: #"{"denial_action_label":[{"lang":"en","value":"No"}]}"#)), handler: Handler(.yes)))
        await expectRefusal(.metadataUnavailable, service(source(metadata(labels: #"{"affirmative_action_label":[]}"#)), handler: Handler(.yes)))
    }

    func testOverlongLabelsRefuse() async {
        let long = String(repeating: "x", count: 31)
        let l = #"{"affirmative_action_label":[{"lang":"en","value":"\#(long)"}]}"#
        await expectRefusal(.metadataUnavailable, service(source(metadata(labels: l)), handler: Handler(.yes)))
        let hint = String(repeating: "h", count: 251)
        let l2 = #"{"affirmative_action_label":[{"lang":"en","value":"OK"}],"security_hint":[{"lang":"en","value":"\#(hint)"}]}"#
        await expectRefusal(.metadataUnavailable, service(source(metadata(labels: l2)), handler: Handler(.yes)))
    }

    func testParameterWithoutALocalisedNameRefuses() async {
        await expectRefusal(.metadataUnavailable, service(source(metadata(claims: claimsJson(skip: ["amount"]))), handler: Handler(.yes)))
        // A claim with metadata but no display at all, at a level that must be shown.
        let noDisplay = withClaim(claimsJson(skip: ["currency"]), #"{"path":["payload","currency"],"visualisation":1}"#)
        await expectRefusal(.metadataUnavailable, service(source(metadata(claims: noDisplay)), handler: Handler(.yes)))
    }

    func testLevelFourParameterWithoutNameMayBeLeftOut() async throws {
        let c = withClaim(claimsJson(skip: ["transaction_id"]), #"{"path":["payload","transaction_id"],"visualisation":4}"#)
        let h = Handler(.yes)
        _ = try await service(source(metadata(claims: c)), handler: h).process(request(), context: context())
        XCTAssertFalse(try XCTUnwrap(h.seen.first?.entries.first).fields.contains { $0.path == ["transaction_id"] })
    }

    func testInvalidVisualisationRefuses() async {
        await expectRefusal(.metadataUnavailable, service(source(metadata(claims: claimsJson(levelOverrides: ["amount": 5]))), handler: Handler(.yes)))
    }

    func testAttestationWithoutEntryForTheTypeCannotBeDisplayed() async {
        await expectRefusal(.metadataUnavailable, service(source(metadata(noEntry: true)), handler: Handler(.yes)))
    }

    func testClaimsAndLabelsByUriWithIntegrity() async throws {
        let claims = claimsJson()
        let sri = { (t: String) in "sha256-" + Data(self.sha256(Data(t.utf8))).base64EncodedString() }
        let entry = #"{"schema":"urn:eudi:sca:payment:1","claims_uri":"https://pay.example/c.json","ui_labels_uri":"https://pay.example/l.json"}"#
        let doc = #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{"urn:eudi:sca:payment:1":\#(entry)}}"#
        let s = source(doc)
        s.resources["https://pay.example/c.json"] = Data(claims.utf8)
        s.resources["https://pay.example/l.json"] = Data(labels.utf8)
        let pins = [
            "transaction_data_types['urn:eudi:sca:payment:1'].claims_uri#integrity": sri(claims),
            "transaction_data_types['urn:eudi:sca:payment:1'].ui_labels_uri#integrity": sri(labels),
        ]
        var req = request()
        req.credentials = [credential(pins: pins)]
        let h = Handler(.yes)
        _ = try await service(s, handler: h).process(req, context: context())
        XCTAssertEqual(h.seen.first?.entries.first?.affirmativeLabel, "Confirm Payment")
        // Tampered labels no longer match the pin.
        s.resources["https://pay.example/l.json"] = Data(labels.replacingOccurrences(of: "Confirm Payment", with: "Send all your money").utf8)
        await expectRefusal(.metadataUnavailable, service(s, handler: Handler(.yes)), req)
        // Unreachable resource refuses.
        s.resources["https://pay.example/c.json"] = nil
        await expectRefusal(.metadataUnavailable, service(s, handler: Handler(.yes)), req)
    }

    private func uriDoc() -> String {
        let entry = #"{"schema":"urn:eudi:sca:payment:1","claims_uri":"https://pay.example/c.json","ui_labels_uri":"https://pay.example/l.json"}"#
        return #"{"vct":"\#(vct)","category":"urn:eu:europa:ec:eudi:sua:sca","transaction_data_types":{"urn:eudi:sca:payment:1":\#(entry)}}"#
    }

    /// Several entries naming the same documents download each once per validation.
    func testEachReferencedDocumentIsFetchedOncePerValidation() async throws {
        let s = source(uriDoc())
        s.resources["https://pay.example/c.json"] = Data(claimsJson().utf8)
        s.resources["https://pay.example/l.json"] = Data(labels.utf8)
        let three = [paymentRaw(), paymentRaw(), paymentRaw()]
        _ = try await service(s, handler: Handler(.yes)).process(request(three), context: context())
        XCTAssertEqual(s.fetches["https://pay.example/c.json"], 1)
        XCTAssertEqual(s.fetches["https://pay.example/l.json"], 1)
    }

    /// All fetching shares one deadline: slow documents that each beat the per-fetch timeout still end the validation together.
    func testFetchingSharesOneRequestWideDeadline() async {
        let s = source(uriDoc())
        s.resources["https://pay.example/c.json"] = Data(claimsJson().utf8)
        s.resources["https://pay.example/l.json"] = Data(labels.utf8)
        s.delayNanos = 190_000_000      // each below the 0.2 s per-fetch timeout, together above 0.3 s
        let svc = TransactionDataService(
            source: s, consentHandler: Handler(.yes), authentication: FixedCapability(can: true),
            log: InMemoryTransactionLogStore(), consentTimeout: 5, fetchTimeout: 0.2
        )
        await expectRefusal(.metadataUnavailable, svc, request())
    }

    /// A request cancelled while a document is being fetched ends as a cancellation, not as a logged refusal.
    func testACancelledValidationIsNotLoggedAsARefusal() async throws {
        let s = source(uriDoc())
        s.resources["https://pay.example/c.json"] = Data(claimsJson().utf8)
        s.resources["https://pay.example/l.json"] = Data(labels.utf8)
        s.delayNanos = 5_000_000_000
        let log = InMemoryTransactionLogStore()
        let svc = service(s, handler: Handler(.yes), log: log)
        let req = request()
        let ctx = context()
        let task = Task { try await svc.process(req, context: ctx) }
        try await Task.sleep(nanoseconds: 200_000_000)
        task.cancel()
        do { _ = try await task.value; XCTFail("expected an error") } catch is CancellationError {} catch { XCTFail("\(error)") }
        let entries = await log.entries()
        XCTAssertTrue(entries.isEmpty, "no refusal was recorded for a cancelled request: \(entries.map(\.reason))")
    }

    /// A blank verifier is refused before the user is asked, whatever else is fine.
    func testABlankVerifierIsRefusedBeforeConsent() async {
        for blank in ["", "   ", "\n\t "] {
            let h = Handler(.yes)
            do {
                _ = try await service(source(), handler: h).process(request(), context: TransactionDataContext(verifier: blank, locale: "en-GB", credentialNames: ["pay": "Visa card"]))
                XCTFail("must refuse")
            } catch let e as TransactionDataError { XCTAssertEqual(e.reason, .invalidEntry) } catch { XCTFail("\(error)") }
            XCTAssertTrue(h.seen.isEmpty, "the user was not asked")
        }
    }

    func testClaimsBothInlineAndByUriRefuses() async {
        let doc = metadata(extra: #","claims_uri":"https://pay.example/c.json""#)
        await expectRefusal(.metadataUnavailable, service(source(doc), handler: Handler(.yes)))
    }

    /// `-0` is displayed as written, never as `0`.
    func testANegativeZeroIsShownAsWritten() async throws {
        XCTAssertEqual(try StrictJSON.parse("-0"), .decimal("-0"))
        XCTAssertEqual(try StrictJSON.parse("0"), .int(0))
        for lexeme in ["-0", "-0.0"] {
            let h = Handler(.yes)
            let raw = paymentRaw(payload: #"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":\#(lexeme)}"#)
            _ = try await service(source(), handler: h).process(request([raw]), context: context())
            XCTAssertEqual(h.seen.first?.entries.first?.fields.first?.value, lexeme)
        }
    }

    func testNumbersAreShownExactly() async throws {
        let h = Handler(.yes)
        let big = paymentRaw(payload: #"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1000000}"#)
        _ = try await service(source(), handler: h).process(request([big]), context: context())
        XCTAssertEqual(h.seen.first?.entries.first?.fields.first?.value, "1000000")
        let exp = paymentRaw(payload: #"{"transaction_id":"t","payee":{"name":"S","id":"1"},"currency":"EUR","amount":1e21}"#)
        await expectRefusal(.invalidEntry, service(source(), handler: Handler(.yes)), request([exp]))
    }

    // MARK: - Consent

    func testNoHandlerRefusesAndIsLogged() async throws {
        let log = InMemoryTransactionLogStore()
        await expectRefusal(.noConsentHandler, service(source(), handler: nil, log: log))
        let e = try await firstLog(log)
        XCTAssertEqual(e.outcome, .refused)
        XCTAssertEqual(e.reason, "noConsentHandler")
    }

    func testDeclineThrowAndTimeoutAreAllDeclinedNeverConsent() async throws {
        for mode in [Handler.Mode.no, .throwing, .hang] {
            let log = InMemoryTransactionLogStore()
            let started = Date()
            await expectRefusal(.declined, service(source(), handler: Handler(mode), log: log, timeout: 0.3))
            XCTAssertLessThan(Date().timeIntervalSince(started), 3, "\(mode) must not hang the flow")
            let entry = try await firstLog(log)
            XCTAssertEqual(entry.outcome, .declined, "\(mode)")
            XCTAssertNil(entry.reason)
        }
    }

    func testConsentYieldsBindingsAndLogEntry() async throws {
        let log = InMemoryTransactionLogStore()
        let r = request()
        let plan = try await service(source(), handler: Handler(.yes), log: log).process(r, context: context())
        let b = try XCTUnwrap(plan.bindings["pay"])
        XCTAssertEqual(b.rawEntries, [r.entries[0].raw])
        let before = await log.entries()
        XCTAssertTrue(before.isEmpty, "consent is recorded only once signing succeeded")
        await plan.complete(signed: true)
        let entry = try await firstLog(log)
        XCTAssertEqual(entry.outcome, .consented)
        XCTAssertEqual(entry.transactionId, "tx-1")
        XCTAssertEqual(entry.typeName, "Payment Confirmation")
        XCTAssertEqual(entry.entities, ["payee": "Shop AB"])
        XCTAssertEqual(entry.verifier, "Shop AB (verified)")
        XCTAssertEqual(entry.credential, "Visa card")
    }

    func testHandlerIsNotAskedWhenValidationFails() async {
        let h = Handler(.yes)
        await expectRefusal(.schemaViolation, service(source(), handler: h), request([paymentRaw(payload: #"{"transaction_id":"t"}"#)]))
        XCTAssertTrue(h.seen.isEmpty, "the user is never asked to consent to a request that is refused")
    }

    /// A request that can never satisfy two categories is refused BEFORE the user is shown anything.
    func testInsufficientFactorsRefuseBeforeConsentAndAreLogged() async throws {
        let log = InMemoryTransactionLogStore()
        let h = Handler(.yes)
        let svc = service(source(), handler: h, canEstablish: false, log: log)
        await expectRefusal(.insufficientAuthenticationFactors, svc)
        XCTAssertTrue(h.seen.isEmpty, "the user was never asked to confirm something that cannot succeed")
        let entry = try await firstLog(log)
        XCTAssertEqual(entry.reason, "insufficientAuthenticationFactors")
    }

    /// Without a capability probe the wallet cannot satisfy SCA: refused before consent.
    func testTheDefaultCapabilityRefusesBeforeConsent() async {
        let h = Handler(.yes)
        let svc = TransactionDataService(source: source(), consentHandler: h,
                                         log: InMemoryTransactionLogStore(), consentTimeout: 5, fetchTimeout: 2)
        await expectRefusal(.insufficientAuthenticationFactors, svc)
        XCTAssertTrue(h.seen.isEmpty)
    }

    func testSigningFailureIsLoggedAsRefusedNotConsented() async throws {
        let log = InMemoryTransactionLogStore()
        let plan = try await service(source(), handler: Handler(.yes), log: log).process(request(), context: context())
        await plan.complete(signed: false)
        await plan.complete(signed: true)   // later calls do nothing
        let all = await log.entries()
        XCTAssertEqual(all.count, 1)
        XCTAssertEqual(all.first?.outcome, .refused)
        XCTAssertEqual(all.first?.reason, "signingFailed")
    }

    func testACallerMayRecordTheRealRefusalReason() async throws {
        let log = InMemoryTransactionLogStore()
        let plan = try await service(source(), handler: Handler(.yes), log: log).process(request(), context: context())
        await plan.complete(signed: false, refusal: .invalidEntry)
        let all = await log.entries()
        XCTAssertEqual(all.count, 1)
        XCTAssertEqual(all.first?.reason, "invalidEntry")
    }

    func testTheWalletsOwnCancellationIsNotADeclineAndIsNotLoggedAsOne() async throws {
        let log = InMemoryTransactionLogStore()
        let svc = service(source(), handler: Handler(.yes), log: log)
        let r = request()
        let ctx = context()
        let task = Task { () -> Bool in
            // Cancel ourselves just before the answer is evaluated.
            do { _ = try await svc.process(r, context: ctx); return false } catch is CancellationError { return true } catch { return false }
        }
        task.cancel()
        let cancelled = await task.value
        XCTAssertTrue(cancelled, "cancellation propagates")
        let entries = await log.entries()
        XCTAssertFalse(entries.contains { $0.outcome == .declined }, "never recorded as the user declining")
    }

    func testAHandlerThatThrowsCancellationIsADecline() async throws {
        final class Cancelling: TransactionConsentHandler, @unchecked Sendable {
            func confirm(_ request: TransactionConsentRequest) async throws -> Bool { throw CancellationError() }
        }
        let svc = TransactionDataService(source: source(), consentHandler: Cancelling(), authentication: FixedCapability(can: true),
                                         log: InMemoryTransactionLogStore(), consentTimeout: 5, fetchTimeout: 2)
        await expectRefusal(.declined, svc)
    }

    func testEveryCredentialMustBeBoundWhenTheTransportRequiresIt() async {
        let other = TransactionDataCredential(queryId: "age", format: "dc+sd-jwt", vct: "urn:age")
        var req = request()
        req.credentials.append(other)
        let h = Handler(.yes)
        let svc = service(source(), handler: h)
        do {
            _ = try await svc.process(req, context: TransactionDataContext(verifier: "v", locale: "en", requireEveryCredentialBound: true))
            XCTFail("must refuse")
        } catch let e as TransactionDataError { XCTAssertEqual(e.reason, .invalidEntry) } catch { XCTFail("\(error)") }
        XCTAssertTrue(h.seen.isEmpty, "refused before the user is asked, not after")
    }

    func testAnUnboundCredentialIsFineWhenTheTransportAllowsIt() async throws {
        var req = request()
        req.credentials.append(TransactionDataCredential(queryId: "age", format: "mso_mdoc", vct: nil))
        let plan = try await service(source(), handler: Handler(.yes)).process(req, context: context())
        XCTAssertEqual(Set(plan.bindings.keys), ["pay"])
    }

    func testLogFailureIsSurfacedToTheCaller() async throws {
        struct Failing: TransactionLogStore {
            func append(_ entries: [TransactionLogEntry]) async throws { throw TransactionLogError("disk full") }
            func entries() async -> [TransactionLogEntry] { [] }
        }
        final class Counter: @unchecked Sendable { var n = 0 }
        let counter = Counter()
        let svc = TransactionDataService(source: source(), consentHandler: Handler(.yes), authentication: FixedCapability(can: true),
                                         log: Failing(), consentTimeout: 5, fetchTimeout: 2, onLogFailure: { _ in counter.n += 1 })
        let plan = try await svc.process(request(), context: context())
        await plan.complete(signed: true)
        XCTAssertEqual(counter.n, 1)
        await expectRefusal(.invalidEntry, svc, request(["!!!"]))
        XCTAssertEqual(counter.n, 2)
    }

    func testRefusalOfAMalformedEntryIsStillLogged() async throws {
        let log = InMemoryTransactionLogStore()
        await expectRefusal(.invalidEntry, service(source(), handler: Handler(.yes), log: log), request(["!!!"]))
        let e = try await firstLog(log)
        XCTAssertEqual(e.outcome, .refused)
        XCTAssertNil(e.transactionId)
    }

    func testLogNeverCarriesThePayloadBeyondTheNamedFields() async throws {
        let log = InMemoryTransactionLogStore()
        let plan = try await service(source(), handler: Handler(.yes), log: log).process(request(), context: context())
        await plan.complete(signed: true)    // the record is written only now
        let entries = await log.entries()
        XCTAssertEqual(entries.count, 1, "there is something to inspect")
        let encoded = String(decoding: try JSONEncoder().encode(entries), as: UTF8.self)
        XCTAssertTrue(encoded.contains("tx-1"), "the named fields are there")
        for secret in ["49.99", "SE1", "EUR"] { XCTAssertFalse(encoded.contains(secret), secret) }
    }

    // MARK: - Log entries per TS12 5.3

    func testLogEntitiesPerTransactionType() {
        func fields(_ json: String) -> TransactionLogFields { TransactionLogFields(raw: raw(json)) }
        let pay = fields(#"{"type":"urn:eudi:sca:payment:1","payload":{"transaction_id":"a","payee":{"name":"P"},"pisp":{"legal_name":"PISP Ltd"}}}"#)
        XCTAssertEqual(pay.entities, ["payee": "P", "pisp": "PISP Ltd"])
        XCTAssertEqual(pay.typeName, "Payment Confirmation")
        let login = fields(#"{"type":"urn:eudi:sca:login_risk_transaction:1","payload":{"transaction_id":"a","service":"Bank"}}"#)
        XCTAssertEqual(login.entities, ["service": "Bank"])
        XCTAssertEqual(login.typeName, "Login, Risk-based Authentication")
        let access = fields(#"{"type":"urn:eudi:sca:account_access:1","payload":{"transaction_id":"a","aisp":{"legal_name":"AISP"}}}"#)
        XCTAssertEqual(access.entities, ["aisp": "AISP"])
        XCTAssertEqual(access.typeName, "Payment Account Information Access")
        let mandate = fields(#"{"type":"urn:eudi:sca:emandate:1","payload":{"transaction_id":"a","payment_payload":{"payee":{"name":"M"},"pisp":{"legal_name":"X"}}}}"#)
        XCTAssertEqual(mandate.entities, ["payee": "M", "pisp": "X"])
        XCTAssertEqual(mandate.typeName, "E-mandate")
        let custom = fields(#"{"type":"https://x.example/t","payload":{"transaction_id":"a","payee":{"name":"hidden"}}}"#)
        XCTAssertEqual(custom.entities, [:])
        XCTAssertEqual(custom.typeName, "https://x.example/t")
        XCTAssertEqual(custom.transactionId, "a")
    }

    func testInMemoryLogIsBoundedAndNewestFirst() async throws {
        let log = InMemoryTransactionLogStore(capacity: 3)
        for i in 0..<5 {
            try await log.append([TransactionLogEntry(id: "\(i)", timestamp: Int64(i), subject: TransactionLogSubject(transactionId: "\(i)", typeName: nil), verifier: "v", credential: "c", outcome: .consented)])
        }
        let ids = await log.entries().map(\.id)
        XCTAssertEqual(ids, ["4", "3", "2"])
    }

    // MARK: - Capability probe

    /// Only the credentials the transaction is bound to are probed, each by its own key.
    func testOnlyBoundCredentialsAreProbed() async throws {
        var req = request()
        req.credentials.append(TransactionDataCredential(queryId: "age", format: "mso_mdoc", vct: nil))
        let probe = FixedCapability(can: true)
        let svc = TransactionDataService(source: source(), consentHandler: Handler(.yes), authentication: probe,
                                         log: InMemoryTransactionLogStore(), consentTimeout: 5, fetchTimeout: 2)
        let ctx = TransactionDataContext(verifier: "v", locale: "en", keyIds: ["pay": "bound", "age": "unrelated"])
        let plan = try await svc.process(req, context: ctx)
        XCTAssertEqual(Set(plan.bindings.keys), ["pay"])
        XCTAssertEqual(probe.queries, ["bound"], "the unbound credential's key was never probed")
    }

    /// A credential whose key is unknown is probed with no key and refused.
    func testAnUnknownKeyIsRefusedBeforeConsent() async {
        let h = Handler(.yes)
        let probe = FixedCapability(can: false)
        let svc = TransactionDataService(source: source(), consentHandler: h, authentication: probe,
                                         log: InMemoryTransactionLogStore(), consentTimeout: 5, fetchTimeout: 2)
        await expectRefusal(.insufficientAuthenticationFactors, svc)
        XCTAssertEqual(probe.queries.count, 1)
        XCTAssertTrue(h.seen.isEmpty)
    }

    func testLoggedFieldsAreCappedByScalarsNotCharacters() {
        let combining = "e" + String(repeating: "\u{0301}", count: 50_000)    // one character, 50,001 scalars
        XCTAssertEqual(combining.count, 1)
        let e = TransactionLogEntry(subject: TransactionLogSubject(transactionId: combining, typeName: nil), verifier: "v", credential: "c", outcome: .refused)
        XCTAssertEqual(e.transactionId?.unicodeScalars.count, TransactionLogEntry.maxFieldLength)
    }

    func testRefusalLoggingDoesNotDecodeWhatValidationWouldNotAccept() {
        // A VALID document padded past the pipeline's bound: it would decode, so only the bound stops it.
        let padded = raw(#"{"type":"urn:eudi:sca:payment:1","payload":{"transaction_id":"x"}}"# + String(repeating: " ", count: 70_000))
        XCTAssertGreaterThan(padded.utf8.count, 64 * 1024)
        let okFields = TransactionLogFields(raw: raw(#"{"type":"urn:eudi:sca:payment:1","payload":{"transaction_id":"x"}}"#))
        XCTAssertEqual(okFields.transactionId, "x", "the same document without padding is read")
        let fields = TransactionLogFields(raw: padded)
        XCTAssertNil(fields.transactionId)
        XCTAssertNil(fields.typeName)
        let huge = padded
        let rec = TransactionLogEntry.records(rawEntries: [huge], verifier: "v", credentialLabel: { _ in "" }, outcome: .refused, reason: "invalidEntry")
        XCTAssertEqual(rec.count, 1)
    }

    private func sha256(_ data: Data) -> [UInt8] {
        #if canImport(CryptoKit)
        return Array(CryptoKit.SHA256.hash(data: data))
        #else
        return Array(Crypto.SHA256.hash(data: data))
        #endif
    }
}

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
