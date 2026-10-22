// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// What a card draws for a credential type that publishes no rendering block of
// its own - which is every type that comes from someone else's catalog. Pure
// Foundation (no SwiftUI), so it is unit-tested without a view. Port of the
// Kotlin sample app's helpers in `CredentialCard.kt`
// (https://github.com/sirosfoundation/siros-sdk-kotlin/pull/211).

/// An sRGB colour, components 0...1. Kept apart from SwiftUI's `Color` so the
/// colour logic can be tested without a view.
struct CardRGB: Equatable {
    let red: Double
    let green: Double
    let blue: Double

    /// WCAG relative luminance.
    var luminance: Double {
        func linear(_ c: Double) -> Double {
            c <= 0.03928 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)
    }

    static let black = CardRGB(red: 0, green: 0, blue: 0)
    static let white = CardRGB(red: 1, green: 1, blue: 1)

    /// Parse `#RRGGBB`; nil for anything else.
    init?(hex: String) {
        var s = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("#") { s.removeFirst() }
        guard s.count == 6, let value = UInt64(s, radix: 16) else { return nil }
        self.init(
            red: Double((value >> 16) & 0xFF) / 255.0,
            green: Double((value >> 8) & 0xFF) / 255.0,
            blue: Double(value & 0xFF) / 255.0
        )
    }

    init(red: Double, green: Double, blue: Double) {
        self.red = red
        self.green = green
        self.blue = blue
    }
}

/// Smallest contrast ratio the card text must reach (WCAG AA, normal text).
let minReadableContrastRatio = 4.5

/// WCAG contrast ratio between two colours, from 1 (identical) to 21.
func cardContrastRatio(_ a: CardRGB, _ b: CardRGB) -> Double {
    let (lighter, darker) = a.luminance >= b.luminance ? (a, b) : (b, a)
    return (lighter.luminance + 0.05) / (darker.luminance + 0.05)
}

/// Black or white, whichever actually reads better against `background`, not
/// whichever side of mid-grey the background falls on: a saturated blue card
/// sits at luminance 0.39, where a mid-grey threshold chose white at 2.4:1
/// although black gives 8.8:1. The two are equal at luminance 0.179, where
/// both give 4.6:1, so no background - issuer-declared or derived here - can
/// produce unreadable text.
func contrastingCardTextColor(on background: CardRGB) -> CardRGB {
    cardContrastRatio(.black, background) >= cardContrastRatio(.white, background) ? .black : .white
}

/// HSL to RGB; hue in degrees, saturation and lightness 0...1.
func cardColorFromHSL(hue: Double, saturation: Double, lightness: Double) -> CardRGB {
    let c = (1 - abs(2 * lightness - 1)) * saturation
    let hPrime = (hue.truncatingRemainder(dividingBy: 360) + 360).truncatingRemainder(dividingBy: 360) / 60
    let x = c * (1 - abs(hPrime.truncatingRemainder(dividingBy: 2) - 1))
    let (r1, g1, b1): (Double, Double, Double)
    switch Int(hPrime) {
    case 0: (r1, g1, b1) = (c, x, 0)
    case 1: (r1, g1, b1) = (x, c, 0)
    case 2: (r1, g1, b1) = (0, c, x)
    case 3: (r1, g1, b1) = (0, x, c)
    case 4: (r1, g1, b1) = (x, 0, c)
    default: (r1, g1, b1) = (c, 0, x)
    }
    let m = lightness - c / 2
    func clamp(_ v: Double) -> Double { min(max(v, 0), 1) }
    return CardRGB(red: clamp(r1 + m), green: clamp(g1 + m), blue: clamp(b1 + m))
}

/// Hue steps, and tones per hue, for `typeTintColor`.
///
/// The hue is quantised rather than taken straight from the hash so that two
/// types cannot land a couple of degrees apart and read as the same colour.
/// Quantising trades that near-miss for an honest exact collision: with
/// `tintHues * tintTones` slots two types can share one, and nothing can rule
/// that out without the types agreeing with each other. That is a far smaller
/// problem than the single shared colour this replaces.
private let tintHues: UInt32 = 24
private let tintTones: UInt32 = 3

/// A background tint for a credential type that declares no colour of its own,
/// derived from the type identifier so the same type is always the same colour
/// on every device and two types are all but never the same.
///
/// Lightness is fixed per theme and only saturation varies with the tone, so
/// every tint sits in one lightness band and `contrastingCardTextColor`
/// resolves against it exactly as against a declared colour. The hash is
/// written out (FNV-1a, 32-bit) rather than taken from `hashValue`, which is
/// randomly seeded per process in Swift: a colour that is part of what a
/// credential looks like must not change between launches.
///
/// Nil when there is no identifier to derive from.
func typeTintColor(typeId: String?, dark: Bool) -> CardRGB? {
    guard let typeId, !typeId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
    var hash: UInt32 = 0x811C_9DC5
    // Kotlin hashes UTF-16 code units (`Char.code`); do the same so the same
    // type is the same colour on both platforms.
    for unit in typeId.utf16 {
        hash ^= UInt32(unit)
        hash = hash &* 0x0100_0193
    }
    let slot = hash % (tintHues * tintTones)
    let tone = Double(slot / tintHues)
    return cardColorFromHSL(
        hue: Double(slot % tintHues) * (360.0 / Double(tintHues)),
        saturation: (dark ? 0.30 : 0.40) + tone * 0.16,
        lightness: dark ? 0.26 : 0.80
    )
}

/// The short label for a credential type. Only a URL-shaped identifier is
/// shortened, to its last path segment minus any document extension
/// (`https://example.com/credentials/student-id` reads `student-id`,
/// `https://registry.siros.org/sunet/mdl.vctm.json` reads `mdl`); everything
/// else is left whole, because cutting a reverse-DNS or URN identifier at its
/// last dot gives a wrong fragment (`uri:eu.ebw.oid.1` -> "1").
func credentialTypeBadge(_ typeId: String) -> String {
    let afterScheme = typeId.range(of: "://").map { String(typeId[$0.upperBound...]) } ?? typeId
    guard let slash = afterScheme.firstIndex(of: "/") else { return typeId }
    let path = String(afterScheme[afterScheme.index(after: slash)...])
    if path.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return typeId }
    var trimmed = Substring(path)
    while trimmed.hasSuffix("/") { trimmed = trimmed.dropLast() }
    let lastSegment = trimmed.split(separator: "/", omittingEmptySubsequences: false).last.map(String.init) ?? ""
    if lastSegment.isEmpty { return typeId }
    let stem = lastSegment.split(separator: ".", omittingEmptySubsequences: false).first.map(String.init) ?? ""
    return stem.isEmpty ? lastSegment : stem
}

/// What a card says on its two text slots, decided together so that neither
/// repeats the other (separately, each slot fell back on its own and both
/// landed on the wire format: "dc+sd-jwt" as the name and again underneath).
///
/// The format is no longer a slot of its own: it is what a credential is
/// encoded as, not what it is, and survives only as the last thing left to call
/// a credential that says nothing else.
struct CardLabels: Equatable {
    /// The large line: the credential's name, else its type, else its format.
    let title: String
    /// The small label beneath; nil when the title is already saying it.
    let typeBadge: String?
}

func cardLabels(name: String?, format: String, typeId: String?) -> CardLabels {
    let blank: (String) -> Bool = { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    let badge = typeId.flatMap { blank($0) ? nil : credentialTypeBadge($0) }
    // A "name" that is only the format or the type repeated is not a name.
    let realName = name.flatMap { n -> String? in
        if blank(n) || n.caseInsensitiveCompare(format) == .orderedSame || n == typeId || n == badge { return nil }
        return n
    }
    if let realName { return CardLabels(title: realName, typeBadge: badge) }
    if let badge { return CardLabels(title: badge, typeBadge: nil) }
    return CardLabels(title: format, typeBadge: nil)
}

/// How to name the issuer, or nil when the credential does not say. A
/// credential built from an offer carries the issuer's display name; one the
/// wallet had to reconstruct carries only the identifier it was issued from,
/// and its host is a better answer than nothing.
func issuerLabel(name: String?, url: String?) -> String? {
    if let name, !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return name }
    guard let raw = url, !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
    return URL(string: raw)?.host ?? raw
}
