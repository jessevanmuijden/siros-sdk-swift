// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Strict SVG path-data grammar, applied before SwiftDraw sees a path.
///
/// SwiftDraw 0.29.0's path parser has no progress guarantee: any input where
/// it re-applies a command without consuming input loops forever and grows
/// memory (`M0 0Z0`, `M0 0Z,`, `M0 0Zſ1 2 3 4`), and a non-ASCII letter whose
/// uppercase form is longer than one Character traps (`ß` becomes `SS`). So
/// the grammar is deliberately narrower than the SVG spec and works on ASCII
/// bytes only (never `String.uppercased()`):
///
///     path    = ws* ("M"|"m") args+ (ws* command)*
///     command = ("Z"|"z") | letter args+      -- letter in MmLlHhVvCcSsQqTtAa
///     args    = exactly the command's argument count of numbers
///     number  = [+-]? (digits ["." digits*] | "." digits) ([eE] [+-]? digits)?
///     sep     = whitespace or ",", allowed between numbers and before a command,
///               but NEVER after Z/z (only whitespace there), and any byte that
///               is not ASCII is refused outright.
///
/// Arc flags are a single `0` or `1` and may be written without separators.
///
/// Complexity is bounded as well, because SwiftDraw's close handling scans back to the last move for
/// every `Z` (measured on 0.29.0 release builds: 99,000 compact `Z`s did not finish in 25 s; 5,000
/// lines followed by 30,000 `Z`s took 20 s). A path may have at most `maxSegments` segments (commands
/// plus implicit repeats, `Z` included) and `maxSubpaths` moves, and a document `maxDocumentSegments`
/// in total; typical logos have tens to a few hundred.
enum SvgPathData {
    static let maxSegments = 5000
    static let maxSubpaths = 1000
    static let maxDocumentSegments = 20_000

    static func isValid(_ d: String, maxNumber: Double) -> Bool {
        guard let counts = analyze(d, maxNumber: maxNumber) else { return false }
        return counts.segments <= maxSegments && counts.subpaths <= maxSubpaths
    }

    /// Grammar check plus segment/subpath counts; nil when the syntax is not a strict match.
    static func analyze(_ d: String, maxNumber: Double) -> (segments: Int, subpaths: Int)? {
        let b = Array(d.utf8)
        guard !b.isEmpty, b.count <= 100_000, b.allSatisfy({ $0 < 0x80 }) else { return nil }
        var segments = 0, subpaths = 0
        var i = 0
        func isDigit(_ x: UInt8) -> Bool { x >= 0x30 && x <= 0x39 }
        func isWhitespace(_ x: UInt8) -> Bool { x == 0x20 || x == 0x09 || x == 0x0A || x == 0x0D }
        func isLetter(_ x: UInt8) -> Bool { (x | 0x20) >= 0x61 && (x | 0x20) <= 0x7A }
        func skipWhitespace() { while i < b.count, isWhitespace(b[i]) { i += 1 } }
        func skipSeparators() { while i < b.count, isWhitespace(b[i]) || b[i] == 0x2C { i += 1 } }
        func number() -> Bool {
            let start = i
            if i < b.count, b[i] == 0x2B || b[i] == 0x2D { i += 1 }
            var digits = 0
            while i < b.count, isDigit(b[i]) { i += 1; digits += 1 }
            if i < b.count, b[i] == 0x2E {
                i += 1
                while i < b.count, isDigit(b[i]) { i += 1; digits += 1 }
            }
            guard digits > 0 else { return false }
            if i < b.count, b[i] == 0x65 || b[i] == 0x45 { // exponent only if it has digits
                var j = i + 1
                if j < b.count, b[j] == 0x2B || b[j] == 0x2D { j += 1 }
                var exp = 0
                while j < b.count, isDigit(b[j]) { j += 1; exp += 1 }
                guard exp > 0 else { return false } // a dangling "e" is refused, not skipped
                i = j
            }
            guard let text = String(bytes: b[start..<i], encoding: .ascii), let v = Double(text), v.isFinite else { return false }
            return abs(v) <= maxNumber
        }
        func flag() -> Bool {
            guard i < b.count, b[i] == 0x30 || b[i] == 0x31 else { return false }
            i += 1
            return true
        }
        // ASCII upper-casing of a letter byte, no String involved.
        func upper(_ x: UInt8) -> UInt8 { x >= 0x61 ? x - 0x20 : x }
        let argCounts: [UInt8: Int] = [
            0x4D: 2, 0x4C: 2, 0x54: 2, 0x48: 1, 0x56: 1, 0x43: 6, 0x53: 4, 0x51: 4, 0x41: 7, 0x5A: 0, // M L T H V C S Q A Z
        ]
        skipWhitespace()
        guard i < b.count, b[i] == 0x4D || b[i] == 0x6D else { return nil }
        while true {
            // Whitespace, and commas between segments, but the caller of Z handles its own tail.
            skipSeparators()
            if i >= b.count { return (segments, subpaths) }
            let cmd = b[i]
            guard isLetter(cmd), let n = argCounts[upper(cmd)] else { return nil }
            i += 1
            segments += 1
            if upper(cmd) == 0x4D { subpaths += 1 }
            if segments > 4 * maxSegments { return nil } // stop counting once it is hopeless
            if n == 0 { // Z/z takes nothing: only whitespace may follow, then a command letter or the end
                skipWhitespace()
                if i < b.count, !isLetter(b[i]) { return nil }
                continue
            }
            var groups = 0
            while true {
                skipSeparators()
                if i >= b.count || isLetter(b[i]) { break }
                for k in 0..<n {
                    skipSeparators()
                    let isFlag = upper(cmd) == 0x41 && (k == 3 || k == 4)
                    guard isFlag ? flag() : number() else { return nil }
                }
                groups += 1
                guard groups <= 20_000 else { return nil }
            }
            guard groups >= 1 else { return nil }
            segments += groups - 1 // implicit repeats are segments too
        }
    }
}
