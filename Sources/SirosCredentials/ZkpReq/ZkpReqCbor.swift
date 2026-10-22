// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A strict CBOR reader (RFC 8949), only as far as the `ZkpPresentation` shape needs. It walks the raw bytes
/// itself instead of decoding into a generic value: a tag-0 item must not be interpreted as a timestamp (a
/// merely wrong date has to fail as a wrong `proof_time`, not as unparseable), and indefinite-length items are
/// told apart from malformed ones by the encoding, never by the text of a library message.
///
/// Refused: truncation, a reserved encoding, text that is not UTF-8, nesting deeper than 16 levels
/// (malformed); an indefinite-length byte string, text string, array or map at any level; bytes after the item;
/// a map that repeats a key at any level (keys compared structurally, so a repeated key is refused even when the
/// values are identical). Integers and lengths in non-shortest form are accepted: this is not a canonicality check.
enum ZkpReqCbor {
    /// Nesting beyond this is malformed.
    static let maxDepth = 16

    indirect enum Item: Equatable {
        case uint(UInt64)
        case nint(UInt64)
        case bytes([UInt8])
        case text(String)
        case array([Item])
        case map([(Item, Item)])
        case tag(UInt64, Item)
        case bool(Bool)
        /// Null, undefined, simple values and floats, as their raw encoding.
        case other([UInt8])

        static func == (lhs: Item, rhs: Item) -> Bool {
            switch (lhs, rhs) {
            case (.uint(let a), .uint(let b)), (.nint(let a), .nint(let b)): return a == b
            case (.bytes(let a), .bytes(let b)): return a == b
            case (.text(let a), .text(let b)): return a == b
            case (.array(let a), .array(let b)): return a == b
            case (.map(let a), .map(let b)): return a.count == b.count && zip(a, b).allSatisfy { $0.0 == $1.0 && $0.1 == $1.1 }
            case (.tag(let ta, let a), .tag(let tb, let b)): return ta == tb && a == b
            case (.bool(let a), .bool(let b)): return a == b
            case (.other(let a), .other(let b)): return a == b
            default: return false
            }
        }
    }

    enum Failure: Error, Equatable {
        case malformed, indefinite, trailing, duplicateKey
    }

    static func decode(_ bytes: [UInt8]) throws -> Item {
        var reader = Reader(rest: bytes[...])
        let item = try reader.item(depth: 0)
        guard reader.rest.isEmpty else { throw Failure.trailing }
        return item
    }

    private struct Reader {
        var rest: ArraySlice<UInt8>

        mutating func take(_ count: Int) throws -> ArraySlice<UInt8> {
            guard count >= 0, count <= rest.count else { throw Failure.malformed }
            let head = rest.prefix(count)
            rest = rest.dropFirst(count)
            return head
        }

        mutating func argument(_ info: UInt8) throws -> UInt64 {
            let width: Int
            switch info {
            case 0...23: return UInt64(info)
            case 24: width = 1
            case 25: width = 2
            case 26: width = 4
            case 27: width = 8
            default: throw Failure.malformed
            }
            return try take(width).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
        }

        mutating func item(depth: Int) throws -> Item {
            guard depth <= ZkpReqCbor.maxDepth else { throw Failure.malformed }
            guard let initial = rest.first else { throw Failure.malformed }
            rest = rest.dropFirst()
            let major = initial >> 5, info = initial & 0x1F
            if major == 7 { return try simple(initial, info) }
            if info == 31 { throw (2...5).contains(major) ? Failure.indefinite : Failure.malformed }
            let arg = try argument(info)
            switch major {
            case 0: return .uint(arg)
            case 1: return .nint(arg)
            case 2, 3:
                guard let count = Int(exactly: arg) else { throw Failure.malformed }
                let bytes = Array(try take(count))
                if major == 2 { return .bytes(bytes) }
                guard let text = String(validating: bytes, as: UTF8.self) else { throw Failure.malformed }
                return .text(text)
            case 4:
                guard let count = Int(exactly: arg), count <= rest.count else { throw Failure.malformed }
                var out: [Item] = []
                out.reserveCapacity(count)
                for _ in 0..<count { out.append(try item(depth: depth + 1)) }
                return .array(out)
            case 5:
                guard let count = Int(exactly: arg), count <= rest.count else { throw Failure.malformed }
                var out: [(Item, Item)] = []
                out.reserveCapacity(count)
                for _ in 0..<count {
                    let key = try item(depth: depth + 1)
                    let value = try item(depth: depth + 1)
                    if out.contains(where: { $0.0 == key }) { throw Failure.duplicateKey }
                    out.append((key, value))
                }
                return .map(out)
            default:
                return .tag(arg, try item(depth: depth + 1))
            }
        }

        mutating func simple(_ initial: UInt8, _ info: UInt8) throws -> Item {
            switch info {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 28...31: throw Failure.malformed
            default:
                let width: Int
                switch info {
                case 24: width = 1
                case 25: width = 2
                case 26: width = 4
                case 27: width = 8
                default: width = 0
                }
                return .other([initial] + Array(try take(width)))
            }
        }
    }
}
