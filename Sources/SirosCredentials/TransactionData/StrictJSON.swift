// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A JSON value with exact number kinds, used by the EC TS12 pipeline.
///
/// Parsed with `StrictJSON`, not `JSONSerialization`, because the pipeline
/// must (a) tell booleans from numbers and integers from reals reliably on
/// every platform, and (b) refuse documents a lenient parser would accept in
/// an ambiguous way (duplicate object keys, trailing content, runaway
/// nesting), since the user is asked to consent to what this parse says.
public enum JSONValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    /// A number from a lossy source (the orchestrator's decoded hint). A
    /// number parsed from a document is never a `double`: see `decimal`.
    case double(Double)
    /// A number that is not an `Int64`, kept as the exact text it was written
    /// with, so display and comparison never go through binary floating point
    /// (`0.10000000000000001` and `0.1` are different numbers here).
    case decimal(String)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var objectValue: [String: JSONValue]? { if case .object(let o) = self { return o }; return nil }
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { return a }; return nil }
    public var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }

    public subscript(key: String) -> JSONValue? { objectValue?[key] }

    /// Numeric value as a `Double` (lossy), `nil` for a non-number.
    public var numberValue: Double? {
        switch self {
        case .int(let i): return Double(i)
        case .double(let d): return d
        case .decimal(let text): return Double(text)
        default: return nil
        }
    }

    /// The exact value of an `.int` or `.decimal`; `nil` for anything else
    /// (including a `.decimal` too long for `Decimal`, which then never
    /// compares equal to or ordered against anything: fail closed).
    var exactNumber: Decimal? {
        switch self {
        case .int(let i): return Decimal(i)
        case .decimal(let text):
            // `Decimal` rounds silently beyond 38 significant digits and for
            // out-of-range exponents; such a number is not comparable exactly.
            guard JSONValue.significantDigits(text) <= 38,
                  let value = Decimal(string: text, locale: Locale(identifier: "en_US_POSIX")), !value.isNaN else { return nil }
            return value
        default: return nil
        }
    }

    /// Digits of the coefficient, without sign, leading zeros, decimal point or exponent.
    static func significantDigits(_ text: String) -> Int {
        let mantissa = text.lowercased().split(separator: "e", maxSplits: 1).first.map(String.init) ?? text
        let digits = mantissa.filter(\.isNumber).drop(while: { $0 == "0" })
        return digits.count
    }

    var isNumber: Bool {
        switch self {
        case .int, .double, .decimal: return true
        default: return false
        }
    }

    /// Whether this number has no fractional part (JSON Schema `integer`).
    var isIntegral: Bool { integrality ?? false }

    /// Three-valued: `nil` when integrality cannot be decided exactly (an exact
    /// number too long for `Decimal`), which a caller must not turn into "no".
    var integrality: Bool? {
        switch self {
        case .int: return true
        case .double(let d): return d.rounded() == d
        case .decimal:
            guard var exact = exactNumber else { return nil }
            var rounded = Decimal()
            NSDecimalRound(&rounded, &exact, 0, .plain)
            return rounded == exact
        default: return false
        }
    }

    private static func order<T: Comparable>(_ x: T, _ y: T) -> ComparisonResult {
        if x < y { return .orderedAscending }
        return x == y ? .orderedSame : .orderedDescending
    }

    /// Orders two numbers: exactly when both are exact, through `Double` when
    /// either came from a lossy source. `nil` when either is not a number or
    /// cannot be compared exactly.
    static func compareNumbers(_ a: JSONValue, _ b: JSONValue) -> ComparisonResult? {
        guard a.isNumber, b.isNumber else { return nil }
        if let x = a.exactNumber, let y = b.exactNumber { return order(x, y) }
        // An exact number too long for `Decimal` has no exact value to compare.
        if case .decimal = a, a.exactNumber == nil { return nil }
        if case .decimal = b, b.exactNumber == nil { return nil }
        // One side lossy: only that side's precision is available.
        guard let x = a.numberValue, let y = b.numberValue else { return nil }
        return order(x, y)
    }

    /// Equality in the JSON data model: `1` equals `1.0`, exactly.
    /// An undecidable comparison (a number too long to compare exactly) is not equal.
    public func jsonEquals(_ other: JSONValue) -> Bool {
        equality(other) == true
    }

    /// Three-valued equality: `nil` when it cannot be decided exactly (a
    /// number beyond `Decimal`'s precision somewhere inside). A caller that
    /// negates the answer (`not`) must treat `nil` as a refusal, never as "different".
    public func equality(_ other: JSONValue) -> Bool? {
        switch (self, other) {
        case (.null, .null): return true
        case (.bool(let a), .bool(let b)): return a == b
        case (.string(let a), .string(let b)): return a == b
        case (.array(let a), .array(let b)):
            guard a.count == b.count else { return false }
            return JSONValue.all(zip(a, b).map { $0.equality($1) })
        case (.object(let a), .object(let b)):
            guard a.count == b.count else { return false }
            var results: [Bool?] = []
            for (key, value) in a {
                guard let counterpart = b[key] else { return false }
                results.append(value.equality(counterpart))
            }
            return JSONValue.all(results)
        default:
            guard isNumber, other.isNumber else { return false }
            guard let order = JSONValue.compareNumbers(self, other) else { return nil }
            return order == .orderedSame
        }
    }

    /// `false` if any is definitely false, else `nil` if any is undecided, else `true`.
    private static func all(_ results: [Bool?]) -> Bool? {
        if results.contains(false) { return false }
        return results.contains(where: { $0 == nil }) ? nil : true
    }
}

/// Strict, bounded JSON parser (RFC 8259).
public enum StrictJSON {
    public struct ParseError: Error, Equatable, CustomStringConvertible {
        public let description: String
    }

    /// Maximum nesting depth accepted.
    public static let maxDepth = 32

    public static func parse(_ text: String) throws -> JSONValue {
        try parse(Data(text.utf8))
    }

    public static func parse(_ data: Data) throws -> JSONValue {
        var parser = Parser(bytes: [UInt8](data))
        parser.skipWhitespace()
        let value = try parser.parseValue(depth: 0)
        parser.skipWhitespace()
        guard parser.atEnd else { throw ParseError(description: "trailing content after JSON value") }
        return value
    }

    private struct Parser {
        let bytes: [UInt8]
        var pos = 0
        init(bytes: [UInt8]) { self.bytes = bytes }

        var atEnd: Bool { pos >= bytes.count }

        mutating func skipWhitespace() {
            while pos < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[pos]) { pos += 1 }
        }

        func fail(_ message: String) -> ParseError { ParseError(description: "\(message) at byte \(pos)") }

        mutating func parseValue(depth: Int) throws -> JSONValue {
            guard depth <= StrictJSON.maxDepth else { throw fail("nesting too deep") }
            guard pos < bytes.count else { throw fail("unexpected end") }
            switch bytes[pos] {
            case UInt8(ascii: "{"): return try parseObject(depth: depth)
            case UInt8(ascii: "["): return try parseArray(depth: depth)
            case UInt8(ascii: "\""): return .string(try parseString())
            case UInt8(ascii: "t"): try expect("true"); return .bool(true)
            case UInt8(ascii: "f"): try expect("false"); return .bool(false)
            case UInt8(ascii: "n"): try expect("null"); return .null
            default: return try parseNumber()
            }
        }

        mutating func expect(_ word: String) throws {
            let w = Array(word.utf8)
            guard pos + w.count <= bytes.count, Array(bytes[pos..<pos + w.count]) == w else { throw fail("invalid literal") }
            pos += w.count
        }

        mutating func parseObject(depth: Int) throws -> JSONValue {
            pos += 1
            var result: [String: JSONValue] = [:]
            skipWhitespace()
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "}") { pos += 1; return .object(result) }
            while true {
                skipWhitespace()
                guard pos < bytes.count, bytes[pos] == UInt8(ascii: "\"") else { throw fail("expected object key") }
                let key = try parseString()
                guard result[key] == nil else { throw fail("duplicate object key") }
                skipWhitespace()
                guard pos < bytes.count, bytes[pos] == UInt8(ascii: ":") else { throw fail("expected ':'") }
                pos += 1
                skipWhitespace()
                result[key] = try parseValue(depth: depth + 1)
                skipWhitespace()
                guard pos < bytes.count else { throw fail("unterminated object") }
                if bytes[pos] == UInt8(ascii: ",") { pos += 1; continue }
                if bytes[pos] == UInt8(ascii: "}") { pos += 1; return .object(result) }
                throw fail("expected ',' or '}'")
            }
        }

        mutating func parseArray(depth: Int) throws -> JSONValue {
            pos += 1
            var result: [JSONValue] = []
            skipWhitespace()
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "]") { pos += 1; return .array(result) }
            while true {
                skipWhitespace()
                result.append(try parseValue(depth: depth + 1))
                skipWhitespace()
                guard pos < bytes.count else { throw fail("unterminated array") }
                if bytes[pos] == UInt8(ascii: ",") { pos += 1; continue }
                if bytes[pos] == UInt8(ascii: "]") { pos += 1; return .array(result) }
                throw fail("expected ',' or ']'")
            }
        }

        mutating func parseHex4() throws -> UInt32 {
            guard pos + 4 <= bytes.count else { throw fail("bad \\u escape") }
            var value: UInt32 = 0
            for _ in 0..<4 {
                guard let digit = Character(UnicodeScalar(bytes[pos])).hexDigitValue else { throw fail("bad \\u escape") }
                value = value * 16 + UInt32(digit)
                pos += 1
            }
            return value
        }

        static let simpleEscapes: [UInt8: UInt8] = [
            UInt8(ascii: "\""): 0x22, UInt8(ascii: "\\"): 0x5C, UInt8(ascii: "/"): 0x2F, UInt8(ascii: "b"): 0x08,
            UInt8(ascii: "f"): 0x0C, UInt8(ascii: "n"): 0x0A, UInt8(ascii: "r"): 0x0D, UInt8(ascii: "t"): 0x09,
        ]

        /// The scalar of a `\u` escape (the `\u` already consumed), joining a surrogate pair.
        mutating func parseUnicodeEscape() throws -> [UInt8] {
            var code = try parseHex4()
            if (0xD800...0xDBFF).contains(code) {
                guard pos + 2 <= bytes.count, bytes[pos] == UInt8(ascii: "\\"), bytes[pos + 1] == UInt8(ascii: "u") else {
                    throw fail("lone surrogate")
                }
                pos += 2
                let low = try parseHex4()
                guard (0xDC00...0xDFFF).contains(low) else { throw fail("lone surrogate") }
                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
            } else if (0xDC00...0xDFFF).contains(code) {
                throw fail("lone surrogate")
            }
            guard let scalar = UnicodeScalar(code) else { throw fail("bad \\u escape") }
            return Array(String(Character(scalar)).utf8)
        }

        mutating func parseString() throws -> String {
            pos += 1
            var out = [UInt8]()
            while true {
                guard pos < bytes.count else { throw fail("unterminated string") }
                let b = bytes[pos]
                if b == UInt8(ascii: "\"") { pos += 1; break }
                if b < 0x20 { throw fail("control character in string") }
                pos += 1
                if b != UInt8(ascii: "\\") { out.append(b); continue }
                guard pos < bytes.count else { throw fail("bad escape") }
                let e = bytes[pos]
                pos += 1
                if let simple = Self.simpleEscapes[e] {
                    out.append(simple)
                } else if e == UInt8(ascii: "u") {
                    out.append(contentsOf: try parseUnicodeEscape())
                } else {
                    throw fail("bad escape")
                }
            }
            guard let s = String(bytes: out, encoding: .utf8) else { throw fail("invalid UTF-8 in string") }
            return s
        }

        mutating func parseNumber() throws -> JSONValue {
            let start = pos
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "-") { pos += 1 }
            guard pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 else { throw fail("invalid value") }
            if bytes[pos] == 0x30 {
                pos += 1
                if pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 { throw fail("leading zero") }
            } else {
                while pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 { pos += 1 }
            }
            var isInt = true
            if pos < bytes.count, bytes[pos] == UInt8(ascii: ".") {
                isInt = false
                pos += 1
                let fracStart = pos
                while pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 { pos += 1 }
                guard pos > fracStart else { throw fail("bad fraction") }
            }
            if pos < bytes.count, bytes[pos] == UInt8(ascii: "e") || bytes[pos] == UInt8(ascii: "E") {
                isInt = false
                pos += 1
                if pos < bytes.count, bytes[pos] == UInt8(ascii: "+") || bytes[pos] == UInt8(ascii: "-") { pos += 1 }
                let expStart = pos
                while pos < bytes.count, bytes[pos] >= 0x30, bytes[pos] <= 0x39 { pos += 1 }
                guard pos > expStart else { throw fail("bad exponent") }
            }
            let text = String(decoding: bytes[start..<pos], as: UTF8.self)
            if isInt, let i = Int64(text) { return .int(i) }
            guard let d = Double(text), d.isFinite else { throw fail("number out of range") }
            return .decimal(text)
        }
    }
}
