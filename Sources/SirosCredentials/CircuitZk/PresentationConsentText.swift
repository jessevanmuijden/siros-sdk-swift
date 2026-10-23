// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One credential of the request as the user reads it.
public struct PresentationConsentScreenEntry: Sendable, Equatable {
    public let credentialName: String?
    public let issuerName: String?
    /// One sentence per item, in order.
    public let lines: [String]
}

/// The `verifier_id` for display: ``shortened`` for the screen, ``full`` on expand. Never altered otherwise.
public struct PresentationConsentVerifierDetail: Sendable, Equatable {
    public let shortened: String
    public let full: String
}

/// The text of a ``PresentationConsentRequest``.
public struct PresentationConsentScreen: Sendable, Equatable {
    public let title: String
    /// "{name} is asking you to prove:" (or "share:" when a claim is disclosed).
    public let header: String
    public let entries: [PresentationConsentScreenEntry]
    /// "No other personal data is shared."
    public let footer: String
    /// The verifier id value, with no type label; nil when the request uses none.
    public let verifierDetail: PresentationConsentVerifierDetail?
    public let shareLabel: String
    public let cancelLabel: String
}

/// A request this wording does not cover. Thrown rather than showing a consent that omits it.
public struct PresentationConsentTextError: Error, Sendable, Equatable {
    public let reason: String
}

/// Turns a ``PresentationConsentRequest`` into the SDK's wording: the same approved sentences as the
/// Kotlin SDK in en, sv, fi, el and pt (any other locale reads English), parameterised per item and
/// never concatenated. The trust framework and the `verifier_id_type` never appear in it. Nothing
/// here logs; callers must not log the result either.
public struct PresentationConsentText: Sendable {
    /// Words a predicate function in a host's own terms; returns the sentences for the item.
    public typealias PredicateRenderer = @Sendable (PresentationConsentPredicate) -> [String]

    private let language: String
    private let locale: Locale
    private let predicateRenderers: [String: PredicateRenderer]

    /// - Parameters:
    ///   - locale: the user's locale; its language picks the sentences and its date style the dates.
    ///   - predicateRenderers: specialised renderers by function id. Without one a function is an
    ///     age when its declaration says so, else the comparison wording (date-specific sentences
    ///     for a date claim, generic ones for numbers, strings and booleans).
    public init(locale: Locale = .current, predicateRenderers: [String: PredicateRenderer] = [:]) {
        self.locale = locale
        let code = locale.languageCode ?? "en"
        language = ConsentStringTable.locales.contains(code) ? code : "en"
        self.predicateRenderers = predicateRenderers
    }

    public func render(_ request: PresentationConsentRequest) throws -> PresentationConsentScreen {
        let name = request.verifier.label
        let discloses = request.entries.flatMap(\.items).contains {
            switch $0 {
            case .claim, .legacyPseudonym: return true
            default: return false
            }
        }
        return PresentationConsentScreen(
            title: text(.title),
            header: text(discloses ? .verifierShare : .verifierProve, name),
            entries: try request.entries.map { entry in
                PresentationConsentScreenEntry(
                    credentialName: entry.credential.name, issuerName: entry.credential.issuer,
                    lines: try entry.items.flatMap { try lines($0, verifierName: name) })
            },
            footer: text(.footer),
            verifierDetail: request.verifier.verifierId.map {
                PresentationConsentVerifierDetail(shortened: PresentationConsentRequest.shortened(verifierId: $0), full: $0)
            },
            shareLabel: text(.share), cancelLabel: text(.cancel))
    }

    /// The refusal messages shown when nothing could be asked or the user declined.
    public func consentUnavailableMessage() -> String { text(.refusedConsentUnavailable) }
    public func userDeclinedMessage() -> String { text(.refusedUserDeclined) }

    // MARK: -

    private func lines(_ item: PresentationConsentItem, verifierName: String) throws -> [String] {
        switch item {
        case .predicate(let predicate):
            return predicateRenderers[predicate.functionId]?(predicate) ?? predicateLines(predicate)
        case .pseudonym(_, let scope, let remappable, let crossSite, _, let context):
            guard scope == .perVerifier, !crossSite, context == nil else {
                throw PresentationConsentTextError(reason: "unsupported pseudonym scope")
            }
            return [text(remappable ? .pseudonymIssuer : .pseudonym, verifierName)]
        case .legacyPseudonym:
            return [text(.legacyPseudonym, verifierName)]
        case .claim(let name):
            return [text(.claim, name)]
        }
    }

    /// An age (approved wording) when the item carries one, else one sentence per condition. There is
    /// no "the value is not shared" reassurance: a proof of `country == SE` does reveal the value.
    private func predicateLines(_ item: PresentationConsentPredicate) -> [String] {
        if let age = item.ageForm {
            switch age {
            case .between(let from, let to, let minYears, let maxYears):
                return [text(.ageBetween, date(from), date(to), String(minYears), String(maxYears))]
            case .atLeast(let years): return [text(.ageAtLeast, String(years))]
            case .atMost(let years): return [text(.ageAtMost, String(years))]
            }
        }
        let claim = item.claim.label ?? item.claim.path.joined(separator: ".")
        let isDate = item.valueType == .date
        return item.conditions.map { condition in
            let key: ConsentString
            switch condition.op {
            case .eq: key = isDate ? .predicateDateEq : .predicateEq
            case .ne: key = isDate ? .predicateDateNe : .predicateNe
            case .lt: key = isDate ? .predicateDateLt : .predicateLt
            case .le: key = isDate ? .predicateDateLe : .predicateLe
            case .gt: key = isDate ? .predicateDateGt : .predicateGt
            case .ge: key = isDate ? .predicateDateGe : .predicateGe
            case .in: key = isDate ? .predicateDateIn : .predicateIn
            }
            let operands = condition.values.map { value -> String in
                if isDate { return date(value) }
                // A string operand is quoted and escaped: `["SE, FI"]` (one value) and `["SE", "FI"]` (two) must not
                // read the same on the screen the user approves.
                return item.valueType == .string ? Self.quoted(value) : value
            }
            return text(key, claim, operands.joined(separator: ", "))
        }
    }

    /// A string operand as the user reads it: double-quoted, with `\`, `"` and control characters escaped.
    static func quoted(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 || scalar.value == 0x7f { out += String(format: "\\u{%04X}", scalar.value) } else { out.unicodeScalars.append(scalar) }
            }
        }
        return out + "\""
    }

    /// The date as the user's locale writes it; the input is a validated RFC 3339 full-date.
    private func date(_ iso: String) -> String {
        guard let day = CivilDate(iso) else { return iso }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .current
        let components = DateComponents(calendar: calendar, timeZone: calendar.timeZone, year: day.year, month: day.month, day: day.day, hour: 12)
        // Foundation's Gregorian calendar normalises the dates the historical cutover skips (1582-10-10 becomes
        // 1582-10-20). The consent must name the predicate's own date, so a conversion that does not preserve year,
        // month and day falls back to the original ISO text.
        guard let value = calendar.date(from: components),
              calendar.dateComponents([.year, .month, .day], from: value) == DateComponents(year: day.year, month: day.month, day: day.day)
        else { return iso }
        let formatter = DateFormatter()
        formatter.locale = locale
        formatter.calendar = calendar
        formatter.timeZone = calendar.timeZone
        formatter.dateStyle = .long
        formatter.timeStyle = .none
        return formatter.string(from: value)
    }

    /// The sentence with its positional arguments (`%1$s`, `%2$d`) filled in a SINGLE pass, so an
    /// argument that itself contains a placeholder is never expanded.
    private func text(_ key: ConsentString, _ arguments: String...) -> String {
        let template = ConsentStringTable.table[language]?[key] ?? ConsentStringTable.table["en"]?[key] ?? ""
        var out = ""
        var index = template.startIndex
        while index < template.endIndex {
            if template[index] == "%", let digit = template[template.index(after: index)...].first, let position = digit.wholeNumberValue,
               position >= 1, position <= arguments.count {
                let rest = template[template.index(after: index)...].dropFirst()
                if rest.hasPrefix("$s") || rest.hasPrefix("$d") {
                    out += arguments[position - 1]
                    index = template.index(index, offsetBy: 4)
                    continue
                }
            }
            out.append(template[index])
            index = template.index(after: index)
        }
        return out
    }
}
