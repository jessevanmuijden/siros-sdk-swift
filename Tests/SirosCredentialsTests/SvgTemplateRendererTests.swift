// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials

final class SvgTemplateRendererTests: XCTestCase {

    func testSubstitutesMatchedToken() {
        let template = "<text>{{givenName}} {{familyName}}</text>"
        let claims = [
            DisplayClaim(key: "credentialSubject.givenName", label: "Given Name", value: "Alice", svgId: "givenName"),
            DisplayClaim(key: "credentialSubject.familyName", label: "Family Name", value: "Wonderland", svgId: "familyName"),
        ]
        XCTAssertEqual(SvgTemplateRenderer.substitute(template, claims: claims), "<text>Alice Wonderland</text>")
    }

    func testBlanksUnmatchedTokenInsteadOfShowingItLiterally() {
        let template = "<text>{{title}}</text><text>{{givenName}}</text>"
        let claims = [
            DisplayClaim(key: "credentialSubject.givenName", label: "Given Name", value: "Alice", svgId: "givenName"),
        ]
        let result = SvgTemplateRenderer.substitute(template, claims: claims)
        XCTAssertEqual(result, "<text></text><text>Alice</text>")
        XCTAssertFalse(result.contains("{{"))
    }

    func testClaimsWithoutSvgIdAreIgnored() {
        let template = "<text>{{givenName}}</text>"
        let claims = [
            DisplayClaim(key: "some.other.claim", label: "Other", value: "ignored", svgId: nil),
        ]
        XCTAssertEqual(SvgTemplateRenderer.substitute(template, claims: claims), "<text></text>")
    }

    func testEscapesXmlSpecialCharactersInSubstitutedValues() {
        let template = "<text>{{name}}</text>"
        let claims = [
            DisplayClaim(key: "name", label: "Name", value: "A & B <C> \"D\" 'E'", svgId: "name"),
        ]
        let result = SvgTemplateRenderer.substitute(template, claims: claims)
        XCTAssertEqual(result, "<text>A &amp; B &lt;C&gt; &quot;D&quot; &apos;E&apos;</text>")
    }

    func testSubstitutesImageDataUriRatherThanValueWhenClaimCarriesOne() {
        let template = "<image href=\"{{portrait}}\"/>"
        let claims = [
            DisplayClaim(
                key: "org.iso.18013.5.1.portrait", label: "Portrait", value: "<1234 bytes>",
                svgId: "portrait", imageDataUri: "data:image/jpeg;base64,AAAA"
            ),
        ]
        XCTAssertEqual(
            SvgTemplateRenderer.substitute(template, claims: claims),
            "<image href=\"data:image/jpeg;base64,AAAA\"/>"
        )
    }

    /// Per Copilot review of #178: a legitimate text claim whose value
    /// happens to look exactly like `CredentialUtils.formatCborValue`'s
    /// `"<N bytes>"` placeholder must NOT be misclassified as an
    /// undecodable byte string - `substitute` reads `isUndecodableBytes`
    /// directly rather than inferring provenance from `value`'s text, so
    /// this is now impossible by construction rather than by coincidence.
    func testDoesNotMisclassifyATextClaimThatCoincidentallyLooksLikeTheBytesPlaceholder() {
        let template = "<text>{{serial}}</text>"
        let claims = [
            DisplayClaim(key: "serial", label: "Serial", value: "<12 bytes>", svgId: "serial"),
        ]
        XCTAssertEqual(SvgTemplateRenderer.substitute(template, claims: claims), "<text>&lt;12 bytes&gt;</text>")
    }

    func testIsANoOpOnTemplatesWithNoTokens() {
        let template = "<svg><rect width=\"100\" height=\"100\"/></svg>"
        XCTAssertEqual(SvgTemplateRenderer.substitute(template, claims: []), template)
    }

    func testEscapeXmlHandlesAllFiveSpecialCharacters() {
        XCTAssertEqual(SvgTemplateRenderer.escapeXml("&<>\"'"), "&amp;&lt;&gt;&quot;&apos;")
    }

    func testSubstitutesADataUriImageClaimUnescaped() {
        let template = #"<image href="{{portrait}}"/>"#
        let dataUri = "data:image/jpeg;base64,/9j/4AAQ"
        let claims = [
            DisplayClaim(key: "org.iso.23220.1.portrait", label: "Portrait", value: dataUri, svgId: "portrait"),
        ]
        XCTAssertEqual(SvgTemplateRenderer.substitute(template, claims: claims), #"<image href="\#(dataUri)"/>"#)
    }

    func testRendersADashForAnSvgBoundClaimThatCouldNotBeDecodedAsAnImage() {
        // Mirrors CredentialUtils.formatCborValue's fallback for a byte
        // string that isn't a recognized JPEG/PNG (e.g. JPEG 2000) - showing
        // the raw byte count where an image was expected would be more
        // confusing than an explicit "not shown" marker. `isUndecodableBytes`
        // is read directly (not inferred from `value`'s text - see
        // `testDoesNotMisclassifyATextClaimThatCoincidentallyLooksLikeTheBytesPlaceholder`).
        let template = #"<image href="{{portrait}}"/>"#
        let claims = [
            DisplayClaim(
                key: "org.iso.23220.1.portrait", label: "Portrait", value: "<38000 bytes>",
                svgId: "portrait", isUndecodableBytes: true
            ),
        ]
        XCTAssertEqual(SvgTemplateRenderer.substitute(template, claims: claims), #"<image href="-"/>"#)
    }

    func testRealDc4euDiplomaTemplateSubstitutesCorrectly() {
        // Reproduces the actual live template fetched from the diploma VCTM
        // during manual verification of the Kotlin SDK.
        let template = """
        <text>Title</text>
        <text>{{title}}</text>
        <text>Name</text>
        <text>{{givenName}} {{familyName}}</text>
        <text>Institution</text>
        <text>{{awardingInstitution}} {{country}}</text>
        <text>Awarding Date</text>
        <text>{{awardingDate}}</text>
        """
        let claims = [
            DisplayClaim(key: "a", label: "Title", value: "HBO Master Architectuur", svgId: "title"),
            DisplayClaim(key: "b", label: "Given Name", value: "Alice", svgId: "givenName"),
            DisplayClaim(key: "c", label: "Family Name", value: "Wonderland", svgId: "familyName"),
            DisplayClaim(key: "d", label: "Institution", value: "ArtEZ", svgId: "awardingInstitution"),
            DisplayClaim(key: "e", label: "Country", value: "Netherlands", svgId: "country"),
            DisplayClaim(key: "f", label: "Awarding Date", value: "2004-03-31", svgId: "awardingDate"),
        ]
        let result = SvgTemplateRenderer.substitute(template, claims: claims)
        XCTAssertTrue(result.contains("HBO Master Architectuur"))
        XCTAssertTrue(result.contains("Alice Wonderland"))
        XCTAssertTrue(result.contains("ArtEZ Netherlands"))
        XCTAssertTrue(result.contains("2004-03-31"))
        XCTAssertFalse(result.contains("{{"))
    }
}
