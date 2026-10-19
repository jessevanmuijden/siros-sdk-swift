// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// What the rules may consult besides the plan itself. There is deliberately no
/// `verifier_id_type` registry: a request no longer carries the member (the wallet
/// picks the type itself) and one that still does is accepted and ignored.
public struct CircuitZkRuleEnv: Sendable {
    public let circuits: (any CircuitZkCircuitSource)?

    public init(circuits: (any CircuitZkCircuitSource)?) {
        self.circuits = circuits
    }
}

/// A rule over the whole plan: `holds` false makes the request unsatisfiable, reported as `id`.
public struct CircuitZkPlanRule: Sendable {
    public let id: String
    public let holds: @Sendable (CircuitZkPlan, CircuitZkRuleEnv) -> Bool

    public init(id: String, holds: @escaping @Sendable (CircuitZkPlan, CircuitZkRuleEnv) -> Bool) {
        self.id = id
        self.holds = holds
    }
}

/// A rule over one function item of the plan.
public struct CircuitZkFunctionRule: Sendable {
    public let id: String
    public let holds: @Sendable (CircuitZkFunction, CircuitZkRuleEnv) -> Bool

    public init(id: String, holds: @escaping @Sendable (CircuitZkFunction, CircuitZkRuleEnv) -> Bool) {
        self.id = id
        self.holds = holds
    }
}

/// The rules of one function id: at most `maxItems` items per request (nil =
/// unlimited, rule id `countRuleId`) and the `rules` each item must satisfy.
public struct CircuitZkFunctionRules: Sendable {
    public let maxItems: Int?
    public let countRuleId: String
    public let rules: [CircuitZkFunctionRule]

    public init(maxItems: Int?, countRuleId: String, rules: [CircuitZkFunctionRule]) {
        self.maxItems = maxItems
        self.countRuleId = countRuleId
        self.rules = rules
    }
}

/// A named, data-driven rule set. A function id that is a key of `functions` is a
/// known function; any other function id is unsatisfiable. New functions and
/// credential types add entries; the validator does not change.
public struct CircuitZkRuleSet: Sendable {
    public let planRules: [CircuitZkPlanRule]
    public let functions: [String: CircuitZkFunctionRules]

    public init(planRules: [CircuitZkPlanRule], functions: [String: CircuitZkFunctionRules]) {
        self.planRules = planRules
        self.functions = functions
    }

    /// This rule set plus the function `id` with `rules`.
    public func withFunction(_ id: String, _ rules: CircuitZkFunctionRules) -> CircuitZkRuleSet {
        var all = functions
        all[id] = rules
        return CircuitZkRuleSet(planRules: planRules, functions: all)
    }

    public static let pseudonym = "pseudonym-v1-sha256"
    public static let ageCheck = "age_check"

    /// How a pseudonym config uses `verifier_input` and `verifier_context` (rulebook v0.3).
    public struct PseudonymConfig: Sendable, Equatable {
        public let id: String
        public let usesVerifierInput: Bool
        public let requiresVerifierContext: Bool

        public init(id: String, usesVerifierInput: Bool, requiresVerifierContext: Bool) {
            self.id = id
            self.usesVerifierInput = usesVerifierInput
            self.requiresVerifierContext = requiresVerifierContext
        }
    }

    /// The four rulebook v0.3 configurations.
    public static let rulebookPseudonymConfigs: [PseudonymConfig] = [
        PseudonymConfig(id: "known-offender-matching-ssc", usesVerifierInput: true, requiresVerifierContext: false),
        PseudonymConfig(id: "known-offender-matching-psc", usesVerifierInput: true, requiresVerifierContext: false),
        PseudonymConfig(id: "account-recovery-ssc", usesVerifierInput: true, requiresVerifierContext: true),
        PseudonymConfig(id: "user-managed-pseudonym-xsite-ssc", usesVerifierInput: false, requiresVerifierContext: false),
    ]

    private static let minSpanDays = 365
    private static let maxContextBytes = 64

    /// The rules of rulebook v0.3. `pseudonymConfigs` is the set of configurations this wallet supports.
    public static func rulebookV03(pseudonymConfigs: [PseudonymConfig] = rulebookPseudonymConfigs) -> CircuitZkRuleSet {
        let byId = Dictionary(pseudonymConfigs.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        return CircuitZkRuleSet(
            planRules: [
                CircuitZkPlanRule(id: "meta-vct-values-reserved") { plan, _ in
                    plan.raw["meta"]?.objectValue?["vct_values"] == nil
                },
                CircuitZkPlanRule(id: "holder-binding-false") { plan, _ in
                    guard let value = plan.raw["require_cryptographic_holder_binding"] else { return true }
                    return value == .bool(true)
                },
                CircuitZkPlanRule(id: "function-not-declared") { plan, env in functionsDeclared(plan, env) },
            ],
            functions: [
                pseudonym: CircuitZkFunctionRules(maxItems: 1, countRuleId: "pseudonym-count", rules: [
                    CircuitZkFunctionRule(id: "pseudonym-config-unsupported") { function, _ in
                        string(function.params, "config").map { byId[$0] != nil } ?? false
                    },
                    CircuitZkFunctionRule(id: "verifier-context-required") { function, _ in
                        guard let config = string(function.params, "config").flatMap({ byId[$0] }) else { return true }
                        return !config.requiresVerifierContext || function.params["verifier_context"] != nil
                    },
                    CircuitZkFunctionRule(id: "verifier-context-forbidden") { function, _ in
                        guard let config = string(function.params, "config").flatMap({ byId[$0] }) else { return true }
                        return config.requiresVerifierContext || function.params["verifier_context"] == nil
                    },
                    CircuitZkFunctionRule(id: "verifier-context-length") { function, _ in
                        guard function.params["verifier_context"] != nil else { return true }
                        guard let bytes = string(function.params, "verifier_context")?.utf8.count else { return false }
                        return (1...maxContextBytes).contains(bytes)
                    },
                ]),
                ageCheck: CircuitZkFunctionRules(maxItems: 1, countRuleId: "age-check-count", rules: [
                    CircuitZkFunctionRule(id: "age-check-no-bounds") { function, _ in
                        function.params["ge"] != nil || function.params["le"] != nil
                    },
                    CircuitZkFunctionRule(id: "age-check-bad-date") { function, _ in
                        ["ge", "le"].allSatisfy { function.params[$0] == nil || date(function.params, $0) != nil }
                    },
                    CircuitZkFunctionRule(id: "age-check-le-before-ge") { function, _ in
                        guard let ge = date(function.params, "ge"), let le = date(function.params, "le") else { return true }
                        return le.daysSinceEpoch >= ge.daysSinceEpoch
                    },
                    CircuitZkFunctionRule(id: "age-check-span-short") { function, _ in
                        guard let ge = date(function.params, "ge"), let le = date(function.params, "le") else { return true }
                        // le - ge + 1, in calendar days.
                        return le.daysSinceEpoch - ge.daysSinceEpoch + 1 >= minSpanDays
                    },
                ]),
            ])
    }

    private static func string(_ params: [String: JSONValue], _ key: String) -> String? {
        params[key]?.stringValue
    }

    /// An RFC 3339 `full-date` (`YYYY-MM-DD`), or nil.
    private static func date(_ params: [String: JSONValue], _ key: String) -> CivilDate? {
        string(params, key).flatMap { CivilDate($0) }
    }

    /// When some circuit fits the plan's doctype and circuit list, at least one of them
    /// must support every function: it declares none (no function filtering) or declares
    /// all of them. A satisfiability rule shared with the other SDKs' vectors; whether a
    /// circuit declaring none is ever offered is decided by the matching code. A circuit
    /// constrained by the matcher is not subject to this legacy check.
    private static func functionsDeclared(_ plan: CircuitZkPlan, _ env: CircuitZkRuleEnv) -> Bool {
        guard let source = env.circuits else { return true }
        let doctype = plan.raw["meta"]?.objectValue?["doctype_value"]?.stringValue
        let relevant = source.circuits().filter { circuit in
            (doctype.map { circuit.docTypes.contains($0) } ?? true) && (plan.circuitFilter?.admits(circuit) ?? true)
        }
        if relevant.isEmpty { return true }
        return relevant.contains { circuit in
            circuit.constrainedByMatcher || circuit.functions == nil
                || plan.functions.allSatisfy { circuit.functions?.contains($0.id) ?? true }
        }
    }
}

/// The wallet-side satisfiability rules for a planned `circuit_zk` request: the
/// rulebook's data-independent MUST rules, as a ``CircuitZkRuleSet``. Whether a
/// predicate holds for the holder's `birth_date` is data-dependent and is checked
/// when proving, not here.
///
/// A `verifier_id_type` member in a pseudonym item is neither checked nor refused.
///
/// Every failure is ``CircuitZkVerdict/accessDenied(ruleId:)``; the rule id is for
/// local logs and tests and must never reach the verifier.
public struct RulebookCircuitZkValidator: CircuitZkRequestValidator {
    private let rules: CircuitZkRuleSet
    private let env: CircuitZkRuleEnv

    public init(rules: CircuitZkRuleSet = .rulebookV03(), circuits: (any CircuitZkCircuitSource)? = nil) {
        self.rules = rules
        self.env = CircuitZkRuleEnv(circuits: circuits)
    }

    public func validate(_ plan: CircuitZkPlan) -> CircuitZkVerdict {
        for rule in rules.planRules where !rule.holds(plan, env) {
            return .accessDenied(ruleId: rule.id)
        }
        for function in plan.functions where rules.functions[function.id] == nil {
            return .accessDenied(ruleId: "unknown-function")
        }
        // Dictionary iteration order is unspecified; sort so the reported rule id is stable.
        for (id, entry) in rules.functions.sorted(by: { $0.key < $1.key }) {
            let items = plan.functions.filter { $0.id == id }
            if let max = entry.maxItems, items.count > max { return .accessDenied(ruleId: entry.countRuleId) }
            for item in items {
                for rule in entry.rules where !rule.holds(item, env) {
                    return .accessDenied(ruleId: rule.id)
                }
            }
        }
        return .ok
    }
}
