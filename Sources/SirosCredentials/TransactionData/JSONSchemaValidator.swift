// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A deliberately small JSON Schema (draft 2020-12) validator for EC TS12
/// transaction-data payloads.
///
/// It implements the keywords the TS12 schemas use and fails CLOSED on
/// anything else: a schema using a keyword this validator does not implement
/// is reported as `.unsupported`, never silently treated as satisfied, because
/// a skipped constraint would let a payload through that the attestation
/// provider meant to forbid.
///
/// `format` is an annotation, as 2020-12 specifies by default, and is not
/// asserted. References are resolved only through the supplied resolver
/// (local `#/...` pointers and the built-in schema registry); network
/// references are never followed from here.
public struct JSONSchemaValidator: Sendable {
    public enum Outcome: Equatable, Sendable {
        case valid
        /// The payload violates the schema; `path` locates the violation.
        case invalid(path: String, reason: String)
        /// The schema itself uses something this validator cannot evaluate.
        case unsupported(String)
    }

    /// Resolves a non-local `$ref` (for example the file name the TS12
    /// e-mandate schema uses for the payment schema). `nil` = unresolvable.
    public typealias RefResolver = @Sendable (String) -> JSONValue?

    private static let annotationKeywords: Set<String> = [
        "$schema", "$comment", "title", "description", "examples", "default",
        "format", "$defs", "definitions", "deprecated", "readOnly", "writeOnly",
    ]
    private static let maxDepth = 64

    private let resolveRef: RefResolver

    public init(resolveRef: @escaping RefResolver = { _ in nil }) {
        self.resolveRef = resolveRef
    }

    /// Schema evaluations allowed for one `validate` call. A recursive schema
    /// whose branches reference each other can otherwise do exponential work
    /// well inside the depth limit.
    static let evaluationBudget = 20_000

    private final class Budget {
        var remaining = JSONSchemaValidator.evaluationBudget
    }

    public func validate(_ instance: JSONValue, against schema: JSONValue) -> Outcome {
        validate(instance, schema, root: schema, path: "", depth: 0, budget: Budget())
    }

    private func validate(_ instance: JSONValue, _ schema: JSONValue, root: JSONValue, path: String, depth: Int, budget: Budget) -> Outcome {
        budget.remaining -= 1
        guard budget.remaining >= 0 else { return .unsupported("schema evaluation budget exceeded") }
        guard depth <= Self.maxDepth else { return .unsupported("schema nesting or reference depth exceeded") }
        switch schema {
        case .bool(let allowed):
            return allowed ? .valid : .invalid(path: path, reason: "schema is false")
        case .object(let keywords):
            return validateObjectSchema(instance, keywords, root: root, path: path, depth: depth, budget: budget)
        default:
            return .unsupported("a schema must be an object or boolean")
        }
    }

    private func validateObjectSchema(
        _ instance: JSONValue, _ kw: [String: JSONValue], root: JSONValue, path: String, depth: Int, budget: Budget
    ) -> Outcome {
        let known: Set<String> = [
            "type", "properties", "required", "additionalProperties", "items", "minItems", "maxItems",
            "enum", "const", "minLength", "maxLength", "pattern", "minimum", "maximum",
            "exclusiveMinimum", "exclusiveMaximum", "$ref", "allOf", "anyOf", "oneOf", "not",
        ]
        for key in kw.keys where !known.contains(key) && !Self.annotationKeywords.contains(key) {
            return .unsupported("unsupported schema keyword '\(key)'")
        }
        if let problem = Self.keywordShapeProblem(kw) { return .unsupported(problem) }
        var result: Outcome = .valid
        func check(_ outcome: Outcome) -> Bool {
            if outcome != .valid { result = outcome; return false }
            return true
        }

        if let ref = kw["$ref"] {
            guard let target = resolve(ref, root: root) else { return .unsupported("unresolvable $ref") }
            guard check(validate(instance, target.schema, root: target.root, path: path, depth: depth + 1, budget: budget)) else { return result }
        }
        if let type = kw["type"] {
            guard check(checkType(instance, type, path: path)) else { return result }
        }
        if let e = kw["enum"] {
            guard let options = e.arrayValue else { return .unsupported("enum must be an array") }
            let results = options.map { $0.equality(instance) }
            if !results.contains(true) {
                // Undecidable comparisons must not read as "different" (a `not` would invert them).
                if results.contains(where: { $0 == nil }) { return .unsupported("cannot compare exactly") }
                return .invalid(path: path, reason: "not one of the allowed values")
            }
        }
        if let c = kw["const"] {
            guard let same = c.equality(instance) else { return .unsupported("cannot compare exactly") }
            if !same { return .invalid(path: path, reason: "does not equal the required constant") }
        }
        guard check(checkString(instance, kw, path: path)) else { return result }
        guard check(checkNumber(instance, kw, path: path)) else { return result }
        guard check(checkObject(instance, kw, root: root, path: path, depth: depth, budget: budget)) else { return result }
        guard check(checkArray(instance, kw, root: root, path: path, depth: depth, budget: budget)) else { return result }
        guard check(checkCombinators(instance, kw, root: root, path: path, depth: depth, budget: budget)) else { return result }
        return .valid
    }

    /// Known keywords must have the shape the specification gives them, whatever
    /// the instance is: a malformed assertion must not pass just because this
    /// instance is of another type.
    static func keywordShapeProblem(_ kw: [String: JSONValue]) -> String? {
        for key in ["minLength", "maxLength", "minItems", "maxItems"] {
            guard let v = kw[key] else { continue }
            guard case .int(let n) = v, n >= 0 else { return "\(key) must be a non-negative integer" }
        }
        for key in ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"] {
            if let v = kw[key], !v.isNumber { return "\(key) must be a number" }
        }
        if let v = kw["pattern"], v.stringValue == nil { return "pattern must be a string" }
        if let v = kw["required"], v.arrayValue?.allSatisfy({ $0.stringValue != nil }) != true { return "required must be an array of strings" }
        if let v = kw["properties"], v.objectValue == nil { return "properties must be an object" }
        if let v = kw["enum"], v.arrayValue?.isEmpty != false { return "enum must be a non-empty array" }
        func isSchema(_ v: JSONValue) -> Bool { if case .bool = v { return true }; return v.objectValue != nil }
        for key in ["allOf", "anyOf", "oneOf"] {
            guard let v = kw[key] else { continue }
            guard let list = v.arrayValue, !list.isEmpty, list.allSatisfy(isSchema) else { return "\(key) must be a non-empty array of schemas" }
        }
        for key in ["not", "items", "additionalProperties"] {
            if let v = kw[key], !isSchema(v) { return "\(key) must be a schema" }
        }
        if let v = kw["properties"]?.objectValue, !v.values.allSatisfy(isSchema) { return "every property must be a schema" }
        if let v = kw["$ref"], v.stringValue == nil { return "$ref must be a string" }
        if let v = kw["type"] {
            let ok = v.stringValue != nil || (v.arrayValue?.isEmpty == false && v.arrayValue?.allSatisfy { $0.stringValue != nil } == true)
            if !ok { return "type must be a string or a non-empty array of strings" }
        }
        return nil
    }

    private func resolve(_ ref: JSONValue, root: JSONValue) -> (schema: JSONValue, root: JSONValue)? {
        guard let r = ref.stringValue else { return nil }
        if r == "#" { return (root, root) }
        if r.hasPrefix("#/") {
            var node = root
            for raw in r.dropFirst(2).split(separator: "/", omittingEmptySubsequences: false) {
                // RFC 6901: `~` must be followed by `0` or `1`; anything else is a malformed pointer.
                let chars = Array(raw)
                for (i, c) in chars.enumerated() where c == "~" {
                    guard i + 1 < chars.count, chars[i + 1] == "0" || chars[i + 1] == "1" else { return nil }
                }
                let token = String(raw).replacingOccurrences(of: "~1", with: "/").replacingOccurrences(of: "~0", with: "~")
                guard let next = node[token] else { return nil }
                node = next
            }
            return (node, root)
        }
        // Only a bare file name reaches the resolver: anything with a scheme, a
        // host (`//host/...`) or a path never does, so no reference can name a
        // network location from here.
        guard r.range(of: "^[A-Za-z0-9._-]+$", options: .regularExpression) != nil,
              let external = resolveRef(r) else { return nil }
        return (external, external)
    }

    private func checkType(_ instance: JSONValue, _ type: JSONValue, path: String) -> Outcome {
        let names: [String]
        if let s = type.stringValue { names = [s] }
        else if let a = type.arrayValue, a.allSatisfy({ $0.stringValue != nil }) { names = a.compactMap(\.stringValue) }
        else { return .unsupported("type must be a string or array of strings") }
        let known: Set<String> = ["null", "boolean", "object", "array", "number", "integer", "string"]
        guard names.allSatisfy(known.contains) else { return .unsupported("unknown type name") }
        if names.contains(where: { matches(instance, $0) }) { return .valid }
        // Undecidable is not a mismatch: `not` would turn a false into acceptance.
        if names.contains("integer"), instance.isNumber, instance.integrality == nil {
            return .unsupported("integrality of the number cannot be decided exactly")
        }
        return .invalid(path: path, reason: "expected type \(names.joined(separator: " or "))")
    }

    private func matches(_ v: JSONValue, _ name: String) -> Bool {
        switch (name, v) {
        case ("null", .null), ("boolean", .bool), ("object", .object), ("array", .array), ("string", .string): return true
        case ("number", _): return v.isNumber
        case ("integer", _): return v.isIntegral
        default: return false
        }
    }

    private func checkString(_ instance: JSONValue, _ kw: [String: JSONValue], path: String) -> Outcome {
        guard case .string(let s) = instance else { return .valid }
        let length = s.unicodeScalars.count
        if let m = kw["minLength"] {
            guard case .int(let n) = m else { return .unsupported("minLength must be an integer") }
            if Int64(length) < n { return .invalid(path: path, reason: "shorter than minLength") }
        }
        if let m = kw["maxLength"] {
            guard case .int(let n) = m else { return .unsupported("maxLength must be an integer") }
            if Int64(length) > n { return .invalid(path: path, reason: "longer than maxLength") }
        }
        if let p = kw["pattern"] {
            guard let pattern = p.stringValue, RegexSafety.isSafe(pattern),
                  let regex = try? NSRegularExpression(pattern: pattern) else {
                return .unsupported("pattern is not a usable, bounded regular expression")
            }
            // A bounded input too: matching cost grows with the string.
            // Not evaluated: undecided, so the schema is refused (an `.invalid` here would be inverted by `not`).
            guard s.utf8.count <= RegexSafety.maxInputBytes else { return .unsupported("string too long to match a pattern") }
            let range = NSRange(s.startIndex..., in: s)
            if regex.firstMatch(in: s, range: range) == nil { return .invalid(path: path, reason: "does not match pattern") }
        }
        return .valid
    }

    private func checkNumber(_ instance: JSONValue, _ kw: [String: JSONValue], path: String) -> Outcome {
        guard instance.isNumber else { return .valid }
        let violations: [(String, (ComparisonResult) -> Bool)] = [
            ("minimum", { $0 == .orderedAscending }), ("maximum", { $0 == .orderedDescending }),
            ("exclusiveMinimum", { $0 != .orderedDescending }), ("exclusiveMaximum", { $0 != .orderedAscending }),
        ]
        for (key, violated) in violations {
            guard let limit = kw[key] else { continue }
            guard limit.isNumber else { return .unsupported("\(key) must be a number") }
            // Not comparable exactly: fail closed rather than let it through.
            guard let order = JSONValue.compareNumbers(instance, limit) else { return .unsupported("cannot be compared exactly with \(key)") }
            if violated(order) { return .invalid(path: path, reason: "violates \(key)") }
        }
        return .valid
    }

    private func checkObject(_ instance: JSONValue, _ kw: [String: JSONValue], root: JSONValue, path: String, depth: Int, budget: Budget) -> Outcome {
        guard case .object(let members) = instance else { return .valid }
        if let req = kw["required"] {
            guard let names = req.arrayValue, names.allSatisfy({ $0.stringValue != nil }) else {
                return .unsupported("required must be an array of strings")
            }
            for name in names.compactMap(\.stringValue) where members[name] == nil {
                return .invalid(path: path, reason: "missing required member '\(name)'")
            }
        }
        var properties: [String: JSONValue] = [:]
        if let p = kw["properties"] {
            guard let obj = p.objectValue else { return .unsupported("properties must be an object") }
            properties = obj
        }
        for (name, sub) in properties {
            guard let value = members[name] else { continue }
            let outcome = validate(value, sub, root: root, path: path + "." + name, depth: depth + 1, budget: budget)
            if outcome != .valid { return outcome }
        }
        if let ap = kw["additionalProperties"] {
            for (name, value) in members where properties[name] == nil {
                switch ap {
                case .bool(false): return .invalid(path: path + "." + name, reason: "additional member not allowed")
                case .bool(true): continue
                default:
                    let outcome = validate(value, ap, root: root, path: path + "." + name, depth: depth + 1, budget: budget)
                    if outcome != .valid { return outcome }
                }
            }
        }
        return .valid
    }

    private func checkArray(_ instance: JSONValue, _ kw: [String: JSONValue], root: JSONValue, path: String, depth: Int, budget: Budget) -> Outcome {
        guard case .array(let items) = instance else { return .valid }
        if let m = kw["minItems"] {
            guard case .int(let n) = m else { return .unsupported("minItems must be an integer") }
            if Int64(items.count) < n { return .invalid(path: path, reason: "fewer than minItems") }
        }
        if let m = kw["maxItems"] {
            guard case .int(let n) = m else { return .unsupported("maxItems must be an integer") }
            if Int64(items.count) > n { return .invalid(path: path, reason: "more than maxItems") }
        }
        if let itemSchema = kw["items"] {
            for (index, item) in items.enumerated() {
                let outcome = validate(item, itemSchema, root: root, path: path + "[\(index)]", depth: depth + 1, budget: budget)
                if outcome != .valid { return outcome }
            }
        }
        return .valid
    }

    private func checkCombinators(_ instance: JSONValue, _ kw: [String: JSONValue], root: JSONValue, path: String, depth: Int, budget: Budget) -> Outcome {
        func subschemas(_ key: String) -> [JSONValue]? {
            guard let v = kw[key] else { return [] }
            return v.arrayValue
        }
        guard let all = subschemas("allOf"), let any = subschemas("anyOf"), let one = subschemas("oneOf") else {
            return .unsupported("allOf/anyOf/oneOf must be arrays")
        }
        for sub in all {
            let outcome = validate(instance, sub, root: root, path: path, depth: depth + 1, budget: budget)
            if outcome != .valid { return outcome }
        }
        if kw["anyOf"] != nil {
            var firstUnsupported: Outcome?
            var matched = false
            for sub in any {
                let outcome = validate(instance, sub, root: root, path: path, depth: depth + 1, budget: budget)
                if outcome == .valid { matched = true; break }
                if case .unsupported = outcome, firstUnsupported == nil { firstUnsupported = outcome }
            }
            if !matched { return firstUnsupported ?? .invalid(path: path, reason: "matches none of anyOf") }
        }
        if kw["oneOf"] != nil {
            var count = 0
            for sub in one {
                let outcome = validate(instance, sub, root: root, path: path, depth: depth + 1, budget: budget)
                if case .unsupported = outcome { return outcome }
                if outcome == .valid { count += 1 }
            }
            if count != 1 { return .invalid(path: path, reason: "does not match exactly one of oneOf") }
        }
        if let not = kw["not"] {
            let outcome = validate(instance, not, root: root, path: path, depth: depth + 1, budget: budget)
            if case .unsupported = outcome { return outcome }
            if outcome == .valid { return .invalid(path: path, reason: "matches a schema it must not match") }
        }
        return .valid
    }
}

/// A deliberately small, provably bounded subset of regular expressions for
/// schema `pattern`s, which come from an issuer-controlled document and run on
/// the wallet. `NSRegularExpression` has no time limit, so anything that can
/// backtrack badly is refused rather than run. Allowed: literals, escapes,
/// character classes, anchors and plain (capturing or `(?:`) groups that are
/// NOT quantified, with at most ONE unbounded quantifier (`+`, `*`, `{n,}`)
/// and at most six quantifiers in all. Refused: alternation, a quantified
/// group (`(a?){30}`, `(a+)+`), several unbounded repeats (`a*a*a*b`), too many
/// optional or repeated atoms (`a?a?a?...`), back-references, lookaround, and
/// over-long patterns. `^[A-Z]{3}$`, `^[a-z0-9._-]+$` and `^\d{4}-\d{2}$` pass.
enum RegexSafety {
    static let maxPatternLength = 256
    static let maxGroups = 8
    static let maxQuantifiers = 6
    static let maxInputBytes = 1024
    /// Variable-width quantifiers (`+ * ?`, `{n,m}`): adjacent overlapping ones backtrack polynomially (`a{0,64}` x6 on 384 chars did not finish), so only two are allowed. Fixed `{n}` is free.
    static let maxVariableQuantifiers = 2

    static func isSafe(_ pattern: String) -> Bool {
        guard pattern.utf8.count <= maxPatternLength else { return false }
        if pattern.contains("(?=") || pattern.contains("(?!") || pattern.contains("(?<=") || pattern.contains("(?<!") { return false }
        var scan = Scan(chars: Array(pattern))
        return scan.run()
    }

    /// One left-to-right pass over a pattern, counting what `isSafe` limits. Split into small steps.
    private struct Scan {
        let chars: [Character]
        var i = 0
        var inClass = false
        var lastWasGroupClose = false
        var openGroups = 0
        var groups = 0
        var quantifiers = 0
        var unbounded = 0
        var variable = 0

        init(chars: [Character]) { self.chars = chars }

        mutating func run() -> Bool {
            while i < chars.count {
                guard advance() else { return false }
            }
            return openGroups == 0 && !inClass && groups <= RegexSafety.maxGroups && quantifiers <= RegexSafety.maxQuantifiers
                && unbounded <= 1 && variable <= RegexSafety.maxVariableQuantifiers
        }

        private mutating func advance() -> Bool {
            let c = chars[i]
            if c == "\\" { return escape() }
            if inClass {
                if c == "]" { inClass = false }
                i += 1
                return true
            }
            guard let quantified = token(c) else { return false }
            if quantified && lastWasGroupClose { return false }
            lastWasGroupClose = c == ")"
            i += 1
            return true
        }

        private mutating func escape() -> Bool {
            guard i + 1 < chars.count else { return false }
            if chars[i + 1].isNumber && chars[i + 1] != "0" { return false }   // back-reference
            i += 2
            lastWasGroupClose = false
            return true
        }

        /// `nil` refuses the pattern; otherwise whether the token was a quantifier.
        private mutating func token(_ c: Character) -> Bool? {
            switch c {
            case "[": inClass = true
            case "|": return nil
            case "(", ")": return group(c) ? false : nil
            case "+", "*": count(unboundedRepeat: true); return true
            case "?": return optional()
            case "{": return braces()
            default: break
            }
            return false
        }

        private mutating func group(_ c: Character) -> Bool {
            if c == "(" { openGroups += 1; groups += 1; return true }
            guard openGroups > 0 else { return false }
            openGroups -= 1
            return true
        }

        private mutating func count(unboundedRepeat: Bool) {
            quantifiers += 1
            variable += 1
            if unboundedRepeat { unbounded += 1 }
        }

        /// `(?:` introduces a non-capturing group; a `?` after an atom is optional; `+?` / `*?` are lazy forms.
        private mutating func optional() -> Bool {
            let previous = i > 0 ? chars[i - 1] : " "
            if previous == "(" || previous == "+" || previous == "*" || previous == "?" { return false }
            count(unboundedRepeat: false)
            return true
        }

        /// `{n}`, `{n,m}`, `{n,}` with every bound at most 64. `nil` refuses the pattern.
        private mutating func braces() -> Bool? {
            guard let close = chars[i...].firstIndex(of: "}") else { return nil }
            let body = String(chars[(i + 1)..<close])
            let parts = body.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
            guard parts.count <= 2, let low = Int(parts[0]), low <= 64 else { return nil }
            quantifiers += 1
            if parts.count == 2 {
                if parts[1].isEmpty { unbounded += 1 } else {
                    guard let high = Int(parts[1]), high <= 64, high >= low else { return nil }
                }
                if parts[1].isEmpty || Int(parts[1]) != low { variable += 1 }
            }
            i = close
            return true
        }
    }
}
