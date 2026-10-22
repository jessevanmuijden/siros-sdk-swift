// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosSampleApp

/// What a card draws for a credential type that publishes no rendering block.
/// Twin of Kotlin's `CredentialCardTest` in siros-sdk-kotlin PR 211.
final class CredentialCardStyleTests: XCTestCase {

    private let realTypes = [
        "uri:eu.ebw.oid.1", "urn:eudi:eucc:1", "uri:eu.eudi.eu-poa.1",
        "eu.we-build.iban-ov.1", "urn:eudi:pid:arf-1.8:1", "eu.europa.ec.eudi.pid.1",
    ]

    // MARK: labels

    /// The card used to decide its text slots separately, so a credential with
    /// no metadata read "dc+sd-jwt" as its name and "DC+SD-JWT" again beneath.
    func testCardLabelsNeverSayTheSameThingTwice() {
        let everyShape = [
            cardLabels(name: "Company Certificate", format: "dc+sd-jwt", typeId: "urn:eudi:eucc:1"),
            cardLabels(name: nil, format: "dc+sd-jwt", typeId: "uri:eu.ebw.oid.1"),
            cardLabels(name: "dc+sd-jwt", format: "dc+sd-jwt", typeId: "uri:eu.ebw.oid.1"),
            cardLabels(name: "uri:eu.ebw.oid.1", format: "dc+sd-jwt", typeId: "uri:eu.ebw.oid.1"),
            cardLabels(name: nil, format: "dc+sd-jwt", typeId: nil),
            cardLabels(name: "  ", format: "mso_mdoc", typeId: nil),
        ]
        for labels in everyShape {
            let shown = [labels.title] + (labels.typeBadge.map { [$0] } ?? [])
            XCTAssertEqual(shown.count, Set(shown).count, "\(labels) repeats itself")
        }
    }

    func testCardLabelsPreferARealNameThenTheTypeThenTheFormat() {
        XCTAssertEqual(
            cardLabels(name: "Company Certificate", format: "dc+sd-jwt", typeId: "urn:eudi:eucc:1"),
            CardLabels(title: "Company Certificate", typeBadge: "urn:eudi:eucc:1")
        )
        // No name: the type is the most identifying thing left, and the badge drops out.
        XCTAssertEqual(
            cardLabels(name: nil, format: "dc+sd-jwt", typeId: "uri:eu.ebw.oid.1"),
            CardLabels(title: "uri:eu.ebw.oid.1", typeBadge: nil)
        )
        // Nothing at all: the format, said once, because something must name the card.
        XCTAssertEqual(
            cardLabels(name: nil, format: "dc+sd-jwt", typeId: nil),
            CardLabels(title: "dc+sd-jwt", typeBadge: nil)
        )
    }

    func testIssuerLabelFallsBackToTheHostOfTheIssuerUrl() {
        XCTAssertEqual(issuerLabel(name: "SIROS ID (dev)", url: "https://issuer.example"), "SIROS ID (dev)")
        XCTAssertEqual(issuerLabel(name: nil, url: "https://issuer.example/path"), "issuer.example")
        XCTAssertEqual(issuerLabel(name: "  ", url: "https://issuer.example"), "issuer.example")
        XCTAssertEqual(issuerLabel(name: nil, url: "not a url"), "not a url")
        XCTAssertNil(issuerLabel(name: nil, url: nil))
        XCTAssertNil(issuerLabel(name: nil, url: "  "))
    }

    /// Cutting at the last dot is right for a hostname and wrong for every
    /// reverse-DNS or URN identifier: `uri:eu.ebw.oid.1` came out as "1".
    func testTypeBadgeShortensOnlyUrlShapedIdentifiers() {
        XCTAssertEqual(credentialTypeBadge("https://example.com/credentials/student-id"), "student-id")
        XCTAssertEqual(credentialTypeBadge("https://registry.siros.org/sunet/mdl.vctm.json"), "mdl")
        XCTAssertEqual(credentialTypeBadge("https://example.com/"), "https://example.com/")
        XCTAssertEqual(credentialTypeBadge("https://example.com"), "https://example.com")
        for whole in realTypes { XCTAssertEqual(credentialTypeBadge(whole), whole) }
    }

    // MARK: tint

    func testTypeTintIsTheSameEveryTime() {
        for type in realTypes {
            XCTAssertEqual(typeTintColor(typeId: type, dark: false), typeTintColor(typeId: type, dark: false))
            XCTAssertEqual(typeTintColor(typeId: type, dark: true), typeTintColor(typeId: type, dark: true))
        }
    }

    /// Pinned values: the colour is part of what a credential looks like to its
    /// holder, so it must not change between releases or between platforms (the
    /// same type in the Kotlin sample app must give the same colour, which holds
    /// because both hash the UTF-16 code units with FNV-1a). The expected values
    /// were computed independently, in Python, from that definition - not by
    /// running either implementation.
    func testTypeTintIsPinnedForTheEbwTypes() throws {
        // (type, light RGB, dark RGB)
        let expected: [(String, [Double], [Double])] = [
            ("uri:eu.ebw.oid.1", [0.688, 0.8, 0.912], [0.1404, 0.26, 0.3796]),
            ("urn:eudi:eucc:1", [0.912, 0.688, 0.8], [0.3796, 0.1404, 0.26]),
            ("uri:eu.eudi.eu-poa.1", [0.8, 0.944, 0.656], [0.26, 0.4212, 0.0988]),
            ("eu.we-build.iban-ov.1", [0.944, 0.872, 0.656], [0.4212, 0.3406, 0.0988]),
        ]
        for (type, light, dark) in expected {
            for (isDark, rgb) in [(false, light), (true, dark)] {
                let tint = try XCTUnwrap(typeTintColor(typeId: type, dark: isDark))
                XCTAssertEqual(tint.red, rgb[0], accuracy: 0.001, "\(type) dark=\(isDark)")
                XCTAssertEqual(tint.green, rgb[1], accuracy: 0.001, "\(type) dark=\(isDark)")
                XCTAssertEqual(tint.blue, rgb[2], accuracy: 0.001, "\(type) dark=\(isDark)")
            }
        }
    }

    /// The point of the change: four EU Business Wallet types declare no colour
    /// of their own and used to draw as four copies of one card. Not a claim
    /// that no two types ever collide, only about the types this wallet carries.
    func testTypeTintSeparatesTheTypesThatRelyOnIt() {
        let noColourOfTheirOwn = [
            "uri:eu.ebw.oid.1", "urn:eudi:eucc:1", "uri:eu.eudi.eu-poa.1", "eu.we-build.iban-ov.1",
        ]
        for dark in [false, true] {
            let tints = noColourOfTheirOwn.map { typeTintColor(typeId: $0, dark: dark)! }
            XCTAssertEqual(tints.count, Set(tints.map { "\($0)" }).count, "dark=\(dark)")
        }
    }

    /// Two different tints must also LOOK different: an earlier version took the
    /// hue straight from the hash and put two types 2 degrees apart.
    func testTwoTypeTintsAreNeverANearMiss() {
        for dark in [false, true] {
            let tints = realTypes.compactMap { typeTintColor(typeId: $0, dark: dark) }
            for i in tints.indices {
                for j in (i + 1)..<tints.count where tints[i] != tints[j] {
                    let distance = abs(tints[i].red - tints[j].red) + abs(tints[i].green - tints[j].green) + abs(tints[i].blue - tints[j].blue)
                    XCTAssertGreaterThanOrEqual(distance, 0.06, "tints differ but only by \(distance) (dark=\(dark))")
                }
            }
        }
    }

    func testTypeTintHasNothingToOfferWithoutAnIdentifier() {
        XCTAssertNil(typeTintColor(typeId: nil, dark: false))
        XCTAssertNil(typeTintColor(typeId: "", dark: false))
        XCTAssertNil(typeTintColor(typeId: "   ", dark: false))
    }

    /// Every generated tint sits in one lightness band per theme, so the
    /// contrast logic resolves against it exactly as against a declared colour.
    func testEveryTypeTintCarriesReadableText() throws {
        for dark in [false, true] {
            for i in 0..<400 {
                let bg = try XCTUnwrap(typeTintColor(typeId: "urn:probe:\(i)", dark: dark))
                let fg = contrastingCardTextColor(on: bg)
                XCTAssertGreaterThanOrEqual(cardContrastRatio(fg, bg), minReadableContrastRatio, "urn:probe:\(i) dark=\(dark)")
            }
        }
    }

    func testTheTwoThemesTintDifferently() {
        for type in realTypes {
            XCTAssertNotEqual(typeTintColor(typeId: type, dark: false), typeTintColor(typeId: type, dark: true))
        }
    }

    // MARK: contrast

    /// The floor holds for ANY colour, including one an issuer declares: black
    /// and white are equally readable at luminance 0.179, still 4.6:1 there.
    func testTextIsReadableOnAnyBackground() {
        let steps = 12.0
        for r in 0...12 {
            for g in 0...12 {
                for b in 0...12 {
                    let bg = CardRGB(red: Double(r) / steps, green: Double(g) / steps, blue: Double(b) / steps)
                    XCTAssertGreaterThanOrEqual(
                        cardContrastRatio(contrastingCardTextColor(on: bg), bg), minReadableContrastRatio,
                        "unreadable on \(bg)"
                    )
                }
            }
        }
    }

    /// A saturated blue sits at luminance ~0.39: the old mid-grey threshold chose
    /// white at 2.4:1 where black gives 8.8:1.
    func testASaturatedBlueGetsBlackText() throws {
        let blue = try XCTUnwrap(CardRGB(hex: "#4A90FF"))
        XCTAssertEqual(contrastingCardTextColor(on: blue), .black)
        XCTAssertEqual(contrastingCardTextColor(on: .white), .black)
        XCTAssertEqual(contrastingCardTextColor(on: .black), .white)
    }

    func testHslConversionHitsThePrimaries() {
        XCTAssertEqual(cardColorFromHSL(hue: 0, saturation: 1, lightness: 0.5), CardRGB(red: 1, green: 0, blue: 0))
        XCTAssertEqual(cardColorFromHSL(hue: 120, saturation: 1, lightness: 0.5), CardRGB(red: 0, green: 1, blue: 0))
        XCTAssertEqual(cardColorFromHSL(hue: 240, saturation: 1, lightness: 0.5), CardRGB(red: 0, green: 0, blue: 1))
        XCTAssertEqual(cardColorFromHSL(hue: 0, saturation: 1, lightness: 0), .black)
        XCTAssertEqual(cardColorFromHSL(hue: 0, saturation: 1, lightness: 1), .white)
        // Hue wraps rather than clamping.
        XCTAssertEqual(cardColorFromHSL(hue: 10, saturation: 0.5, lightness: 0.5), cardColorFromHSL(hue: 370, saturation: 0.5, lightness: 0.5))
    }

    func testHexParsing() {
        XCTAssertEqual(CardRGB(hex: "#FF0000"), CardRGB(red: 1, green: 0, blue: 0))
        XCTAssertNil(CardRGB(hex: "#FFF"))
        XCTAssertNil(CardRGB(hex: "not a colour"))
    }
}
