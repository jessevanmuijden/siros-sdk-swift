// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

/// The SDK-owned consent wording (approved, identical to the Kotlin SDK's): every locale, every key,
/// and what the text may and may not say.
final class PresentationConsentTextTests: XCTestCase {
    private let languages = ["en", "sv", "fi", "el", "pt"]

    private func text(_ language: String) -> PresentationConsentText { PresentationConsentText(locale: Locale(identifier: language)) }

    private func placeholders(_ text: String) -> [String] {
        let regex = try! NSRegularExpression(pattern: "%\\d\\$[sd]")
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text))
            .compactMap { Range($0.range, in: text).map { String(text[$0]) } }.sorted()
    }

    func testEveryStringExistsInEveryLocaleWithTheSamePlaceholders() throws {
        let english = try XCTUnwrap(ConsentStringTable.table["en"])
        XCTAssertEqual(Set(english.keys), Set(ConsentString.allCases))
        XCTAssertEqual(ConsentString.allCases.count, 29)
        for language in languages {
            let localised = try XCTUnwrap(ConsentStringTable.table[language], language)
            XCTAssertEqual(Set(localised.keys), Set(english.keys), language)
            for (key, value) in localised {
                XCTAssertFalse(value.trimmingCharacters(in: .whitespaces).isEmpty, "\(language)/\(key)")
                XCTAssertEqual(placeholders(value), placeholders(try XCTUnwrap(english[key])), "\(language)/\(key)")
                XCTAssertFalse(value.lowercased().contains("framework"), "\(language)/\(key)")
            }
        }
    }

    private let ssc = PresentationConsentItem.pseudonym(
        config: "known-offender-matching-ssc", scope: .perVerifier, remappableByIssuer: true, crossSite: false, verifierId: "rp.example", verifierContext: nil)
    private let psc = PresentationConsentItem.pseudonym(
        config: "known-offender-matching-psc", scope: .perVerifier, remappableByIssuer: false, crossSite: false, verifierId: "rp.example", verifierContext: nil)

    private func age(_ form: PredicateAgeForm) -> PresentationConsentItem {
        .predicate(PresentationConsentPredicate(
            functionId: "age_check", claim: PresentationConsentClaimRef(path: ["birth_date"], label: nil), valueType: .date,
            conditions: [], ageForm: form))
    }

    private func predicate(_ label: String?, path: [String] = ["c"], _ type: PredicateValueType, _ op: PredicateOp, _ values: [String], function: String = "x_check") -> PresentationConsentItem {
        .predicate(PresentationConsentPredicate(
            functionId: function, claim: PresentationConsentClaimRef(path: path, label: label), valueType: type,
            conditions: [PredicateCondition(op: op, values: values)], ageForm: nil))
    }

    private func request(_ items: [PresentationConsentItem], verifierId: String? = "rp.example") -> PresentationConsentRequest {
        PresentationConsentRequest(
            verifier: PresentationConsentVerifier(
                label: "Example RP", trustFramework: "etsi-tl", trustIdentifier: "rp.example", verifierId: verifierId,
                verifierIdType: "x509_san_dns", intermediaryRisk: false),
            entries: [PresentationConsentEntry(credential: PresentationConsentCredential(name: "Nym", issuer: "Example Issuer"), items: items)],
            requestSigned: true)
    }

    private func lines(_ language: String, _ items: [PresentationConsentItem]) throws -> [String] {
        try text(language).render(request(items)).entries[0].lines
    }

    func testTheApprovedEnglishWording() throws {
        let screen = try text("en").render(request([ssc, age(.between(from: "1990-01-01", to: "2008-10-19", minYears: 18, maxYears: 36))]))
        XCTAssertEqual(screen.header, "Example RP is asking you to prove:")
        XCTAssertEqual(screen.entries[0].lines, [
            "A pseudonym for Example RP is shared. You get the same pseudonym every time you visit this service, and a different one at every other service. The service that issued your credential can work out who this pseudonym belongs to.",
            "You were born between January 1, 1990 and October 19, 2008 (about 18–36 years old). Your exact birth date is not shared.",
        ])
        XCTAssertEqual(screen.footer, "No other personal data is shared.")
        XCTAssertEqual(screen.title, "Confirm sharing")
        XCTAssertEqual(screen.entries[0].credentialName, "Nym")
        XCTAssertEqual(try lines("en", [age(.atLeast(years: 18))]), ["You are at least 18 years old. Your exact birth date is not shared."])
        XCTAssertEqual(try lines("en", [age(.atMost(years: 26))]), ["You are at most 26 years old. Your exact birth date is not shared."])
    }

    func testTheVerifierLineIsLocalisedAndNothingTechnicalShows() throws {
        let expected = [
            "en": "Example RP is asking you to prove:", "sv": "Example RP ber dig bevisa:", "fi": "Example RP pyytää sinua todistamaan:",
            "el": "Η υπηρεσία Example RP σας ζητά να αποδείξετε:", "pt": "Example RP pede-lhe que prove:",
        ]
        for (language, line) in expected {
            let screen = try text(language).render(request([ssc, age(.atLeast(years: 18))]))
            XCTAssertEqual(screen.header, line, language)
            for text in [screen.title, screen.header, screen.footer, screen.shareLabel, screen.cancelLabel] + screen.entries.flatMap(\.lines) {
                XCTAssertFalse(text.contains("etsi-tl") || text.contains("x509_san_dns"), "\(language): \(text)")
            }
        }
        // An unknown locale reads English.
        XCTAssertEqual(try text("de").render(request([ssc])).header, "Example RP is asking you to prove:")
    }

    func testTheIssuerLinkabilitySentenceIsThereExactlyWhenTheIssuerCanRemap() throws {
        for language in languages {
            let remappable = try lines(language, [ssc])[0], plain = try lines(language, [psc])[0]
            XCTAssertTrue(remappable.count > plain.count && remappable.hasPrefix(plain), language)
        }
    }

    func testTheVerifierIdIsADetailLineVerbatimAndShortenedForDisplayOnly() throws {
        let did = "did:web:verifier.example.org:very:long:path:segment:identifying:this:verifier"
        let detail = try XCTUnwrap(text("en").render(request([ssc], verifierId: did)).verifierDetail)
        XCTAssertEqual(detail.full, did)
        XCTAssertEqual(detail.shortened, String(did.prefix(18)) + "…" + String(did.suffix(18)))
        XCTAssertNil(try text("en").render(request([age(.atLeast(years: 18))], verifierId: nil)).verifierDetail)
    }

    func testALegacyDisclosureIsADisclosureScreen() throws {
        let screen = try text("en").render(request([.claim(name: "family_name"), .legacyPseudonym(verifierContext: "ctx")]))
        XCTAssertEqual(screen.header, "Example RP is asking you to share:")
        XCTAssertEqual(screen.entries[0].lines, ["The value of “family_name” from your credential is shared.", "A pseudonym is shared with Example RP."])
    }

    func testAPseudonymScopeTheWordingDoesNotCoverFailsInsteadOfBeingOmitted() {
        let xsite = PresentationConsentItem.pseudonym(
            config: "x", scope: .crossSite, remappableByIssuer: true, crossSite: true, verifierId: "r", verifierContext: nil)
        XCTAssertThrowsError(try text("en").render(request([xsite])))
        let withContext = PresentationConsentItem.pseudonym(
            config: "x", scope: .perVerifier, remappableByIssuer: true, crossSite: false, verifierId: "r", verifierContext: "acct")
        XCTAssertThrowsError(try text("en").render(request([withContext])))
    }

    /// One literal value `SE, FI` and two alternatives `SE`, `FI` read differently; quotes, backslashes and line
    /// breaks inside an operand cannot imitate a separator or end the quoted text.
    func testStringOperandsAreQuotedSoDifferentSetsNeverReadTheSame() throws {
        let one = try lines("en", [predicate("Country", path: ["country"], .string, .in, ["SE, FI"])])
        let two = try lines("en", [predicate("Country", path: ["country"], .string, .in, ["SE", "FI"])])
        XCTAssertNotEqual(one, two)
        XCTAssertEqual(one, ["Country is one of: \"SE, FI\"."])
        let tricky = try lines("en", [predicate("Country", path: ["country"], .string, .in, ["a\", \"b", "line1\nline2", "back\\slash"])])
        XCTAssertEqual(tricky, ["Country is one of: \"a\\\", \\\"b\", \"line1\\nline2\", \"back\\\\slash\"."])
        XCTAssertEqual(try lines("en", [predicate("Score", .number, .ge, ["10"])]), ["Score is at least 10."], "numbers stay plain")
    }

    func testAGenericPredicateSaysWhatIsProvedAndNeverReassuresAboutTheValue() throws {
        XCTAssertEqual(try lines("en", [predicate("Credit score", path: ["score"], .number, .ge, ["10"]), predicate("Credit score", path: ["score"], .number, .le, ["20"])]),
                       ["Credit score is at least 10.", "Credit score is at most 20."])
        XCTAssertEqual(try lines("en", [predicate("Country", path: ["country"], .string, .in, ["SE", "FI"])]), ["Country is one of: \"SE\", \"FI\"."])
        // No label: the path is the fallback, never an invented name.
        XCTAssertEqual(try lines("en", [predicate(nil, path: ["address", "country"], .string, .eq, ["SE"])]), ["address.country is \"SE\"."])
        for language in languages {
            for op in [PredicateOp.eq, .ne, .lt, .le, .gt, .ge, .in] {
                let operands = op == .in ? ["A", "B"] : ["A"]
                let sentence = try lines(language, [predicate("CLAIMLABEL", .string, op, operands)])
                XCTAssertEqual(sentence.count, 1, "\(language) \(op)")
                XCTAssertTrue(sentence[0].contains("CLAIMLABEL") && sentence[0].contains("A") && !sentence[0].contains("%"), "\(language) \(op): \(sentence[0])")
            }
        }
    }

    func testADateClaimUsesTheDateSentencesANumberKeepsTheGenericOnes() throws {
        func line(_ type: PredicateValueType, _ op: PredicateOp, _ values: [String]) throws -> String {
            try lines("en", [predicate("Issue date", path: ["d"], type, op, values)])[0]
        }
        XCTAssertEqual(try line(.date, .eq, ["2024-03-01"]), "Issue date is on March 1, 2024.")
        XCTAssertEqual(try line(.date, .ne, ["2024-03-01"]), "Issue date is not on March 1, 2024.")
        XCTAssertEqual(try line(.date, .lt, ["2024-03-01"]), "Issue date is before March 1, 2024.")
        XCTAssertEqual(try line(.date, .le, ["2024-03-01"]), "Issue date is on or before March 1, 2024.")
        XCTAssertEqual(try line(.date, .gt, ["2024-03-01"]), "Issue date is after March 1, 2024.")
        XCTAssertEqual(try line(.date, .ge, ["2024-03-01"]), "Issue date is on or after March 1, 2024.")
        XCTAssertEqual(try line(.date, .in, ["2024-03-01", "2024-04-01"]), "Issue date is one of the dates: March 1, 2024, April 1, 2024.")
        XCTAssertEqual(try line(.number, .ge, ["10"]), "Issue date is at least 10.")
        XCTAssertEqual(try line(.number, .gt, ["10"]), "Issue date is greater than 10.")
        for language in languages {
            for op in [PredicateOp.eq, .ne, .lt, .le, .gt, .ge, .in] {
                let operands = op == .in ? ["2024-03-01", "2024-04-01"] : ["2024-03-01"]
                let date = try lines(language, [predicate("CLAIMLABEL", .date, op, operands)])[0]
                XCTAssertTrue(date.contains("CLAIMLABEL") && !date.contains("%") && !date.contains("2024-03-01"), "\(language) \(op): \(date)")
            }
        }
    }

    func testAnArgumentContainingAPlaceholderIsNotExpanded() throws {
        XCTAssertEqual(try lines("en", [predicate("%2$s", .string, .eq, ["%1$s"])]), ["%2$s is \"%1$s\"."])
    }

    func testAHostRendererTakesPrecedenceOverTheGenericWording() throws {
        let t = PresentationConsentText(locale: Locale(identifier: "en"), predicateRenderers: ["x_check": { _ in ["custom"] }])
        XCTAssertEqual(try t.render(request([predicate(nil, .string, .eq, ["A"])])).entries[0].lines, ["custom"])
        XCTAssertNotEqual(try t.render(request([predicate(nil, .string, .eq, ["A"], function: "other")])).entries[0].lines, ["custom"])
    }

    /// A host renderer that says nothing would drop the predicate from the screen the user approves: refused.
    func testARendererThatReturnsNoWordingIsRefusedNotSilentlyDropped() throws {
        for output in [[String](), [""], ["   "], ["ok", " \n"]] {
            let t = PresentationConsentText(locale: Locale(identifier: "en"), predicateRenderers: ["x_check": { _ in output }])
            XCTAssertThrowsError(try t.render(request([predicate(nil, .string, .eq, ["A"])])), "renderer output \(output)") {
                XCTAssertTrue($0 is PresentationConsentTextError)
            }
        }
    }

    func testTheRefusalMessagesAreLocalised() {
        XCTAssertEqual(text("en").userDeclinedMessage(), "You did not approve this request, so nothing was shared.")
        XCTAssertEqual(text("sv").consentUnavailableMessage(), "Din plånbok kan inte be om ditt godkännande just nu, så ingenting delades.")
    }
}
