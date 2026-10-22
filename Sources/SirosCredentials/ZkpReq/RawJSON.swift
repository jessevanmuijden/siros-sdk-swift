// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// JSON that KEEPS duplicate object members (a parsed dictionary would silently keep one). Numbers are
/// kept only as "a number"; nothing here needs their value.
indirect enum RawJSON {
    case object([(String, RawJSON)])
    case array([RawJSON])
    case string(String)
    case number(String)
    case bool(Bool)
    case null

    /// Strict RFC 8259 parse of the whole text, or nil.
    static func parse(_ text: String) -> RawJSON? {
        var parser = Parser(bytes: Array(text.utf8))
        guard let value = parser.value(depth: 0) else { return nil }
        parser.skipSpace()
        return parser.index == parser.bytes.count ? value : nil
    }

    private struct Parser {
        let bytes: [UInt8]
        var index = 0
        static let maxDepth = 64

        mutating func skipSpace() {
            while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
        }

        mutating func value(depth: Int) -> RawJSON? {
            guard depth < Self.maxDepth else { return nil }
            skipSpace()
            guard index < bytes.count else { return nil }
            switch bytes[index] {
            case UInt8(ascii: "{"): return object(depth: depth)
            case UInt8(ascii: "["): return array(depth: depth)
            case UInt8(ascii: "\""): return string().map(RawJSON.string)
            case UInt8(ascii: "t"): return literal("true", .bool(true))
            case UInt8(ascii: "f"): return literal("false", .bool(false))
            case UInt8(ascii: "n"): return literal("null", .null)
            default: return number()
            }
        }

        mutating func literal(_ word: String, _ result: RawJSON) -> RawJSON? {
            let wordBytes = Array(word.utf8)
            guard index + wordBytes.count <= bytes.count, Array(bytes[index..<index + wordBytes.count]) == wordBytes else { return nil }
            index += wordBytes.count
            return result
        }

        /// Consumes one or more digits; false when there is none.
        mutating func digits(_ range: ClosedRange<UInt8> = 0x30...0x39) -> Bool {
            let start = index
            while index < bytes.count, range.contains(bytes[index]) { index += 1 }
            return index > start
        }

        mutating func accept(_ candidates: UInt8...) -> Bool {
            guard index < bytes.count, candidates.contains(bytes[index]) else { return false }
            index += 1
            return true
        }

        mutating func number() -> RawJSON? {
            let start = index
            _ = accept(UInt8(ascii: "-"))
            guard index < bytes.count else { return nil }
            if bytes[index] == UInt8(ascii: "0") {
                index += 1
            } else if digits(0x31...0x39) {
                _ = digits()
            } else {
                return nil
            }
            if accept(UInt8(ascii: ".")), !digits() { return nil }
            if accept(UInt8(ascii: "e"), UInt8(ascii: "E")) {
                _ = accept(UInt8(ascii: "+"), UInt8(ascii: "-"))
                guard digits() else { return nil }
            }
            return .number(String(decoding: bytes[start..<index], as: UTF8.self))
        }

        mutating func string() -> String? {
            guard bytes[index] == UInt8(ascii: "\"") else { return nil }
            index += 1
            var out: [UInt8] = []
            while index < bytes.count {
                let c = bytes[index]
                index += 1
                if c == UInt8(ascii: "\"") { return String(bytes: out, encoding: .utf8) }
                if c < 0x20 { return nil }
                if c == UInt8(ascii: "\\") {
                    guard let escaped = escape() else { return nil }
                    out.append(contentsOf: escaped)
                } else {
                    out.append(c)
                }
            }
            return nil
        }

        /// The bytes of the escape sequence after a backslash.
        mutating func escape() -> [UInt8]? {
            guard index < bytes.count else { return nil }
            let e = bytes[index]
            index += 1
            let simple: [UInt8: UInt8] = [
                UInt8(ascii: "\""): 0x22, UInt8(ascii: "\\"): 0x5C, UInt8(ascii: "/"): 0x2F, UInt8(ascii: "b"): 0x08,
                UInt8(ascii: "f"): 0x0C, UInt8(ascii: "n"): 0x0A, UInt8(ascii: "r"): 0x0D, UInt8(ascii: "t"): 0x09,
            ]
            if let byte = simple[e] { return [byte] }
            guard e == UInt8(ascii: "u"), let scalar = unicodeEscape() else { return nil }
            return Array(String(Character(scalar)).utf8)
        }

        /// The scalar of a `\uXXXX` escape (the `\u` is consumed), joining a surrogate pair.
        mutating func unicodeEscape() -> Unicode.Scalar? {
            guard var unit = hex4() else { return nil }
            if (0xDC00..<0xE000).contains(unit) { return nil }
            if (0xD800..<0xDC00).contains(unit) {
                guard index + 1 < bytes.count, bytes[index] == UInt8(ascii: "\\"), bytes[index + 1] == UInt8(ascii: "u") else { return nil }
                index += 2
                guard let low = hex4(), (0xDC00..<0xE000).contains(low) else { return nil }
                unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
            }
            return Unicode.Scalar(unit)
        }

        mutating func hex4() -> UInt32? {
            guard index + 4 <= bytes.count else { return nil }
            var value: UInt32 = 0
            for _ in 0..<4 {
                let c = bytes[index]
                index += 1
                let digit: UInt32
                switch c {
                case 0x30...0x39: digit = UInt32(c - 0x30)
                case 0x41...0x46: digit = UInt32(c - 0x41 + 10)
                case 0x61...0x66: digit = UInt32(c - 0x61 + 10)
                default: return nil
                }
                value = value << 4 | digit
            }
            return value
        }

        mutating func array(depth: Int) -> RawJSON? {
            index += 1
            var out: [RawJSON] = []
            skipSpace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "]") { index += 1; return .array(out) }
            while true {
                guard let item = value(depth: depth + 1) else { return nil }
                out.append(item)
                skipSpace()
                guard index < bytes.count else { return nil }
                if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
                if bytes[index] == UInt8(ascii: "]") { index += 1; return .array(out) }
                return nil
            }
        }

        mutating func object(depth: Int) -> RawJSON? {
            index += 1
            var out: [(String, RawJSON)] = []
            skipSpace()
            if index < bytes.count, bytes[index] == UInt8(ascii: "}") { index += 1; return .object(out) }
            while true {
                skipSpace()
                guard index < bytes.count, let key = string() else { return nil }
                skipSpace()
                guard index < bytes.count, bytes[index] == UInt8(ascii: ":") else { return nil }
                index += 1
                guard let item = value(depth: depth + 1) else { return nil }
                out.append((key, item))
                skipSpace()
                guard index < bytes.count else { return nil }
                if bytes[index] == UInt8(ascii: ",") { index += 1; continue }
                if bytes[index] == UInt8(ascii: "}") { index += 1; return .object(out) }
                return nil
            }
        }
    }
}

extension RawJSON {
    /// Compact JSON text of the value (a duplicate member is kept as is; a number keeps its text).
    func serialized() -> String {
        switch self {
        case .object(let pairs): return "{" + pairs.map { "\(Self.quote($0.0)):\($0.1.serialized())" }.joined(separator: ",") + "}"
        case .array(let items): return "[" + items.map { $0.serialized() }.joined(separator: ",") + "]"
        case .string(let text): return Self.quote(text)
        case .number(let text): return text
        case .bool(let flag): return flag ? "true" : "false"
        case .null: return "null"
        }
    }

    private static func quote(_ text: String) -> String {
        var out = "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 { out += String(format: "\\u%04x", scalar.value) } else { out.unicodeScalars.append(scalar) }
            }
        }
        return out + "\""
    }

    /// The member of an object by name (the first one).
    func member(_ name: String) -> RawJSON? {
        guard case .object(let pairs) = self else { return nil }
        return pairs.first { $0.0 == name }?.1
    }
}

extension RawJSON {
    /// The value as a ``JSONValue`` (strict parse of its own serialisation; a duplicate member is not representable
    /// there, so callers that care check the raw form first).
    var jsonValue: JSONValue { (try? StrictJSON.parse(serialized())) ?? .null }
}
