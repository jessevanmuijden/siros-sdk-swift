// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// `circuit_zk` predicate functions are DATA. The set of functions is open-ended (a predicate can
// be about any claim, unlike TS12), so nothing outside a nymauth-specific adapter hard-codes
// `birth_date` or `age_check`: a registry declares, per function id, which claim it is about, its
// value type, which params are which comparison, an optional minimum span (a privacy rule) and
// whether it reads as an age. Consent, the local pre-check and the cross-query merge are driven
// by this registry. A function that is not in it cannot be described, so it is refused.

/// A predicate function: the claim it is about, its type and its comparisons.
public struct PredicateFunction: Sendable, Equatable {
    /// Where the function's claim comes from.
    public enum ClaimSource: Sendable, Equatable {
        /// A fixed path (e.g. `birth_date` for an age function).
        case fixed([String])
        /// The request's `claim` param: a non-empty string, or a non-empty array of non-empty strings (a path).
        case param
    }

    /// Which param carries which comparison, in display order.
    public struct Comparison: Sendable, Equatable {
        public let param: String
        public let op: PredicateOp

        public init(param: String, op: PredicateOp) {
            self.param = param
            self.op = op
        }
    }

    public let id: String
    public let claim: ClaimSource
    public let valueType: PredicateValueType
    public let comparisons: [Comparison]
    /// The smallest width (date: days inclusive; number: `le - ge`) the combined `ge`/`le` bounds of
    /// all queries answered with one credential must keep, or nil for no merge rule.
    public let minSpan: Int?
    /// Whether the function reads as an age: its bounds are dates of birth.
    public let ageSpecialisation: Bool

    public init(
        id: String, claim: ClaimSource, valueType: PredicateValueType, comparisons: [Comparison],
        minSpan: Int? = nil, ageSpecialisation: Bool = false
    ) {
        self.id = id
        self.claim = claim
        self.valueType = valueType
        self.comparisons = comparisons
        self.minSpan = minSpan
        self.ageSpecialisation = ageSpecialisation
    }

    /// The nymauth `age_check`: `ge`/`le` on `birth_date`, at least 365 days wide when combined.
    public static let ageCheck = PredicateFunction(
        id: "age_check", claim: .fixed(["birth_date"]), valueType: .date,
        comparisons: [Comparison(param: "ge", op: .ge), Comparison(param: "le", op: .le)],
        minSpan: 365, ageSpecialisation: true)
}

/// The registry of predicate functions, keyed by id.
public struct PredicateFunctions: Sendable {
    private let byId: [String: PredicateFunction]

    public init(_ functions: [PredicateFunction]) {
        byId = Dictionary(functions.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    /// Only the nymauth `age_check`. Other functions come from the catalog's capability
    /// constraints or the host.
    public static let `default` = PredicateFunctions([.ageCheck])

    public subscript(id: String) -> PredicateFunction? { byId[id] }
}

/// A function's params read as a claim and its conditions.
struct ParsedPredicate {
    let path: [String]
    let conditions: [PredicateCondition]
}

extension PredicateFunction {
    /// The claim path and conditions of a planned function, or nil when its params are not a
    /// conjunction of comparisons on one claim: another param, an operand of the wrong type, an
    /// empty or duplicated `in`, a bad claim param, or no comparison at all.
    func parse(_ function: CircuitZkFunction) -> ParsedPredicate? {
        let params = function.params
        let path: [String]
        switch claim {
        case .fixed(let fixed):
            path = fixed
        case .param:
            switch params["claim"] {
            case .string(let name)? where !name.isEmpty: path = [name]
            case .array(let parts)?:
                let names = parts.compactMap { $0.stringValue }
                guard !parts.isEmpty, names.count == parts.count, names.allSatisfy({ !$0.isEmpty }) else { return nil }
                path = names
            default: return nil
            }
        }
        var allowed = Set(comparisons.map(\.param))
        if case .param = claim { allowed.insert("claim") }
        guard params.keys.allSatisfy({ allowed.contains($0) }) else { return nil }

        var conditions: [PredicateCondition] = []
        for comparison in comparisons {
            guard let raw = params[comparison.param] else { continue }
            if comparison.op == .in {
                guard let items = raw.arrayValue, !items.isEmpty else { return nil }
                let values = items.map { PredicateOperand.text(of: $0, as: valueType) }
                guard values.allSatisfy({ $0 != nil }) else { return nil }
                let texts = values.compactMap { $0 }
                // Duplicates are judged by VALUE (1, 1.0 and 1e0 are one number), not by spelling.
                let keys = texts.map { PredicateOperand.canonicalKey($0, as: valueType) }
                guard keys.allSatisfy({ $0 != nil }), Set(keys.compactMap { $0 }).count == texts.count else { return nil }
                conditions.append(PredicateCondition(op: .in, values: texts))
            } else {
                guard let text = PredicateOperand.text(of: raw, as: valueType) else { return nil }
                conditions.append(PredicateCondition(op: comparison.op, values: [text]))
            }
        }
        return conditions.isEmpty ? nil : ParsedPredicate(path: path, conditions: conditions)
    }
}

enum PredicateOperand {
    /// An operand as text of the value type, or nil when it is not of that type.
    static func text(of value: JSONValue, as type: PredicateValueType) -> String? {
        switch type {
        case .date:
            guard let text = value.stringValue, CivilDate(text) != nil else { return nil }
            return text
        case .string:
            return value.stringValue
        case .bool:
            guard let flag = value.boolValue else { return nil }
            return flag ? "true" : "false"
        case .number:
            switch value {
            case .int(let integer): return String(integer)
            case .decimal(let text): return decimal(text) == nil ? nil : text // not exactly representable: refused
            case .double(let number): return "\(number)"
            default: return nil
            }
        }
    }

    private static let number = try? NSRegularExpression(pattern: "^-?[0-9]+(\\.[0-9]+)?([eE][+-]?[0-9]+)?$")

    /// A number operand or claim text as an EXACT decimal, or nil: `Decimal` silently rounds
    /// beyond 38 significant digits or out of its exponent range, and a rounded bound would
    /// change a comparison or the merge check, so such a value is refused instead.
    static func decimal(_ text: String) -> Decimal? {
        let range = NSRange(text.startIndex..., in: text)
        guard number?.firstMatch(in: text, range: range) != nil else { return nil }
        return JSONValue.decimal(text).exactNumber
    }

    /// Whether `a - b` fits `Decimal`'s 38 significant digits exactly once both are aligned to the
    /// smaller exponent (so the subtraction is neither rounded nor lossy). Both must be valid numbers.
    static func differenceIsExact(_ a: String, _ b: String) -> Bool {
        guard let left = scale(a), let right = scale(b) else { return false }
        let exponent = min(left.exponent, right.exponent)
        let digits = max(left.digits + (left.exponent - exponent), right.digits + (right.exponent - exponent))
        return digits + 1 <= 38
    }

    /// The significant digits and the power of ten of a number text: value = coefficient * 10^exponent.
    private static func scale(_ text: String) -> (digits: Int, exponent: Int)? {
        let lower = text.lowercased()
        let parts = lower.split(separator: "e", maxSplits: 1).map(String.init)
        let mantissa = parts[0].hasPrefix("-") ? String(parts[0].dropFirst()) : parts[0]
        guard let exponentPart = parts.count == 2 ? Int(parts[1]) : 0 else { return nil }
        let pieces = mantissa.split(separator: ".", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        let fraction = pieces.count == 2 ? pieces[1] : ""
        let coefficient = (pieces[0] + fraction).drop(while: { $0 == "0" })
        return (coefficient.count, exponentPart - fraction.count)
    }

    /// A key that is equal exactly when the VALUES are equal: the exact decimal for a number,
    /// the day number for a date, the text for the others. Nil when the text is not exact.
    static func canonicalKey(_ text: String, as type: PredicateValueType) -> String? {
        switch type {
        case .number: return decimal(text).map { "\($0)" }
        case .date: return CivilDate(text).map { String($0.daysSinceEpoch) }
        case .string, .bool: return text
        }
    }
}

/// What a claim lookup found in the credential, for the local pre-check.
public enum PredicateClaimLookup: Sendable, Equatable {
    /// The claim is present, with its type and canonical text (a number as digits, a bool as `true`/`false`).
    case found(type: PredicateValueType, text: String)
    /// The credential has no such claim.
    case absent
    /// The claim cannot be read here (a path or format the reader does not support): never guessed.
    case unsupported
}

extension PredicateFunctions {
    /// The local satisfiability check, before anything is asked: false when the credential
    /// DEFINITELY does not satisfy a function (an absent claim, a type mismatch, a failed
    /// comparison, or params that are not valid for the function); true when every function holds
    /// OR cannot be judged. `lookups[i]` is the lookup for `functions[i]`'s claim (a different
    /// count is false); an `unsupported` one is skipped, not guessed.
    public func precheck(functions: [CircuitZkFunction], lookups: [PredicateClaimLookup]) -> Bool {
        // A missing lookup must not silently skip a function: callers pass `.unsupported` for a claim
        // they cannot read.
        guard functions.count == lookups.count else { return false }
        for (function, lookup) in zip(functions, lookups) {
            guard let registered = self[function.id], let parsed = registered.parse(function) else { return false }
            switch lookup {
            case .absent: return false
            case .unsupported: continue
            case .found(let type, let text):
                guard type == registered.valueType, Self.holds(type, parsed.conditions, text) else { return false }
            }
        }
        return true
    }

    private static func holds(_ type: PredicateValueType, _ conditions: [PredicateCondition], _ text: String) -> Bool {
        for condition in conditions {
            switch type {
            case .date:
                guard let value = CivilDate(text)?.daysSinceEpoch else { return false }
                let operands = condition.values.compactMap { CivilDate($0)?.daysSinceEpoch }
                guard operands.count == condition.values.count, compare(condition.op, value, operands) else { return false }
            case .number:
                guard let value = PredicateOperand.decimal(text) else { return false }
                let operands = condition.values.compactMap { PredicateOperand.decimal($0) }
                guard operands.count == condition.values.count, compare(condition.op, value, operands) else { return false }
            case .string, .bool:
                switch condition.op {
                case .eq: if text != condition.values.first { return false }
                case .ne: if text == condition.values.first { return false }
                case .in: if !condition.values.contains(text) { return false }
                default: return false // an ordering on a non-ordered type
                }
            }
        }
        return true
    }

    private static func compare<T: Comparable>(_ op: PredicateOp, _ value: T, _ operands: [T]) -> Bool {
        guard let first = operands.first else { return false }
        switch op {
        case .eq: return value == first
        case .ne: return value != first
        case .lt: return value < first
        case .le: return value <= first
        case .gt: return value > first
        case .ge: return value >= first
        case .in: return operands.contains(value)
        }
    }

    /// The cross-query privacy rule. The proofs of one request together reveal the INTERSECTION
    /// of their predicates on a claim, so for plans answered with the SAME credential, per claim
    /// path and over functions that DECLARE a `minSpan`: lower = greatest `ge`, upper = least
    /// `le`; with both, the span (date: days inclusive; number: `le - ge`) must reach the
    /// strictest declared `minSpan`. Functions that declare none have no merge rule. An unreadable
    /// bound is not ok. The caller groups queries by credential.
    public func combinedBoundsOk(plans: [[CircuitZkFunction]]) -> Bool {
        struct Group {
            var lower: Decimal?
            var upper: Decimal?
            var lowerText = ""
            var upperText = ""
            var minSpan = 0
            let type: PredicateValueType
        }
        var groups: [[String]: Group] = [:]
        for plan in plans {
            for function in plan {
                guard let registered = self[function.id], let minSpan = registered.minSpan else { continue }
                guard let parsed = registered.parse(function) else { return false }
                var group = groups[parsed.path] ?? Group(type: registered.valueType)
                group.minSpan = max(group.minSpan, minSpan)
                for condition in parsed.conditions {
                    guard let text = condition.values.first, let value = Self.ordinal(text, group.type) else { return false }
                    if condition.op == .ge, group.lower.map({ value > $0 }) ?? true { group.lower = value; group.lowerText = text }
                    if condition.op == .le, group.upper.map({ value < $0 }) ?? true { group.upper = value; group.upperText = text }
                }
                groups[parsed.path] = group
            }
        }
        for group in groups.values {
            guard let lower = group.lower, let upper = group.upper else { continue }
            // Checked arithmetic: a width that cannot be computed exactly (loss of precision) is refused.
            guard group.type == .date || PredicateOperand.differenceIsExact(group.upperText, group.lowerText),
                  let width = Self.exactDifference(upper, lower) else { return false }
            let span = group.type == .date ? width + 1 : width
            if span < Decimal(group.minSpan) { return false }
        }
        return true
    }

    /// `a - b`, or nil when the result is not exact.
    private static func exactDifference(_ a: Decimal, _ b: Decimal) -> Decimal? {
        var result = Decimal()
        var left = a, right = b
        guard NSDecimalSubtract(&result, &left, &right, .plain) == .noError else { return nil }
        return result
    }

    /// A bound as a comparable number: days since the epoch for a date, the decimal itself for a number.
    private static func ordinal(_ text: String, _ type: PredicateValueType) -> Decimal? {
        switch type {
        case .date: return CivilDate(text).map { Decimal($0.daysSinceEpoch) }
        case .number: return PredicateOperand.decimal(text)
        default: return nil
        }
    }
}
