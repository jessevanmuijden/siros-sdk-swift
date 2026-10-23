// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One credential query: the planned functions, the credential chosen for it and that
/// credential's own claim display labels (for predicate items).
public struct CircuitZkConsentQuery: Sendable {
    public let plan: [CircuitZkFunction]
    public let credential: PresentationConsentCredential
    public let claims: [PresentationConsentClaimRef]
    /// The credential's doctype namespace, when known: its claim metadata paths are `[namespace, element]`, so a
    /// predicate on `score` is labelled by the entry `[namespace, "score"]`, never by another namespace's `score`.
    public let namespace: String?

    public init(
        plan: [CircuitZkFunction], credential: PresentationConsentCredential, claims: [PresentationConsentClaimRef] = [],
        namespace: String? = nil
    ) {
        self.plan = plan
        self.credential = credential
        self.claims = claims
        self.namespace = namespace
    }
}

/// The trust decision about the verifier (all parts optional).
public struct CircuitZkConsentTrust: Sendable {
    public let entityName: String?
    public let framework: String?
    public let identifier: String?
    public let intermediaryRisk: Bool

    public init(entityName: String?, framework: String?, identifier: String?, intermediaryRisk: Bool = false) {
        self.entityName = entityName
        self.framework = framework
        self.identifier = identifier
        self.intermediaryRisk = intermediaryRisk
    }
}

public enum PresentationConsentBuilder {
    /// The consent request for a planned `circuit_zk` request, or nil when nothing can be asked
    /// and the request must be REFUSED: a function that is neither a pseudonym, the legacy
    /// disclosure nor in `functions` (we cannot say what it would disclose), a plan with no
    /// function, a pseudonym configuration that is not modelled (or has a `verifier_context`, or
    /// no `verifier_id`), or predicate params that are not valid for their function.
    ///
    /// Only the cases the shared vectors pin are decided here; the cross-query merge
    /// (``PredicateFunctions/combinedBoundsOk(plans:)``) and the local pre-check
    /// (``PredicateFunctions/precheck(functions:lookups:)``) are separate steps the wallet
    /// runs before this call.
    ///
    /// - Parameters:
    ///   - functions: the predicate registry; nothing else here knows a predicate function.
    ///   - verifiedClientIdDisplayName: the display name of the client id of a SIGNED request;
    ///     nil for an unsigned one (its client id is unauthenticated).
    ///   - verifierId: what the wallet resolved; used only for pseudonyms.
    ///   - requestSigned: the result of the request's signature verification. Required: it is
    ///     the authentication status hosts show, so it is never defaulted.
    ///   - today: `YYYY-MM-DD`, the date the age maths use.
    public static func build(
        queries: [CircuitZkConsentQuery],
        functions: PredicateFunctions = .default,
        trust: CircuitZkConsentTrust,
        verifiedClientIdDisplayName: String?,
        attestedOrigin: String,
        verifierId: String?,
        verifierIdType: String?,
        requestSigned: Bool,
        today: String
    ) -> PresentationConsentRequest? {
        // Nothing to ask: refused, never an empty consent.
        guard !queries.isEmpty, let todayDate = CivilDate(today) else { return nil }
        var entries: [PresentationConsentEntry] = []
        var wantsVerifierId = false
        for query in queries {
            guard let items = items(of: query, functions: functions, verifierId: verifierId, today: todayDate) else { return nil }
            entries.append(PresentationConsentEntry(credential: query.credential, items: items))
            for item in items {
                switch item {
                case .pseudonym, .legacyPseudonym: wantsVerifierId = true
                default: break
                }
            }
        }
        // A claim is also revealed when the age bounds on it meet at one day (`ge` == `le`, in one predicate, split across
        // two, or across two queries): the proof then identifies the exact birth date, so "not shared" would be untrue.
        // The model has no stable credential identity, so the bounds are combined over the WHOLE request, which only ever
        // errs towards stating every comparison.
        let revealed = revealedClaimPaths(entries).union(exactBirthDateClaims(entries.flatMap(\.items)))
        entries = entries.map { PresentationConsentEntry(credential: $0.credential, items: withoutAgeWordingWhereRevealed($0.items, revealed: revealed)) }
        let verifier = PresentationConsentVerifier(
            label: label(trust: trust, clientName: verifiedClientIdDisplayName, origin: attestedOrigin),
            trustFramework: trust.framework,
            trustIdentifier: trust.identifier,
            verifierId: wantsVerifierId ? verifierId : nil,
            verifierIdType: verifierIdType,
            intermediaryRisk: trust.intermediaryRisk
        )
        return PresentationConsentRequest(verifier: verifier, entries: entries, requestSigned: requestSigned)
    }

    private static let pseudonymConfigs: [String: (scope: PresentationConsentItem.PseudonymScope, remappable: Bool)] = [
        "known-offender-matching-ssc": (.perVerifier, true),
        "known-offender-matching-psc": (.perVerifier, false),
    ]

    private static let pseudonymFunction = "pseudonym"
    private static let legacyDisclosureFunction = "zk-claim-disclosure-v1"

    private static func items(
        of query: CircuitZkConsentQuery, functions: PredicateFunctions, verifierId: String?, today: CivilDate
    ) -> [PresentationConsentItem]? {
        var out: [PresentationConsentItem] = []
        for function in query.plan {
            switch function.id {
            case pseudonymFunction:
                guard let config = function.params["config"]?.stringValue, let entry = pseudonymConfigs[config] else { return nil }
                let context = function.params["verifier_context"]
                // Only per-verifier configurations are modelled; a context on one is refused (a JSON null is none).
                if entry.scope == .perVerifier, let context, context != .null { return nil }
                guard let verifierId, !verifierId.isEmpty else { return nil }
                out.append(.pseudonym(
                    config: config, scope: entry.scope, remappableByIssuer: entry.remappable,
                    crossSite: entry.scope == .crossSite, verifierId: verifierId, verifierContext: context?.stringValue))
            case legacyDisclosureFunction:
                guard let claims = function.params["claims"]?.arrayValue else { return nil }
                let names = claims.compactMap { $0.stringValue }
                guard names.count == claims.count else { return nil }
                out.append(contentsOf: names.map { .claim(name: $0) })
                if function.params["pseudonym"]?.boolValue == true {
                    out.append(.legacyPseudonym(verifierContext: function.params["verifier_context"]?.stringValue))
                }
            default:
                guard let registered = functions[function.id], let parsed = registered.parse(function) else { return nil }
                out.append(.predicate(predicate(registered, parsed, claims: query.claims, namespace: query.namespace, today: today)))
            }
        }
        return out.isEmpty ? nil : out
    }

    /// The age wording says the exact birth date is not shared. It is dropped (the generic wording states every
    /// comparison) for an age predicate whose claim the request reveals elsewhere: a disclosure of that claim
    /// (legacy `claims`), or another predicate on it that is not itself a ge/le age bound (an equality, a set).
    private static func withoutAgeWordingWhereRevealed(_ items: [PresentationConsentItem], revealed: Set<ClaimPathKey>) -> [PresentationConsentItem] {
        items.map { item in
            guard case .predicate(let predicate) = item, predicate.ageForm != nil, revealed.contains(ClaimPathKey(predicate.claim.path)) else { return item }
            return .predicate(PresentationConsentPredicate(
                functionId: predicate.functionId, claim: predicate.claim, valueType: predicate.valueType,
                conditions: predicate.conditions, ageForm: nil))
        }
    }

    /// The claims whose age bounds leave a single day: the greatest `ge` is not below the least `le`.
    private static func exactBirthDateClaims(_ items: [PresentationConsentItem]) -> Set<ClaimPathKey> {
        var lower: [ClaimPathKey: Int] = [:], upper: [ClaimPathKey: Int] = [:]
        for case .predicate(let predicate) in items where predicate.ageForm != nil {
            let key = ClaimPathKey(predicate.claim.path)
            for condition in predicate.conditions {
                guard let text = condition.values.first, let day = CivilDate(text)?.daysSinceEpoch else { continue }
                if condition.op == .ge { lower[key] = max(lower[key] ?? day, day) }
                if condition.op == .le { upper[key] = min(upper[key] ?? day, day) }
            }
        }
        return Set(lower.compactMap { key, low in upper[key].map { $0 <= low } == true ? key : nil })
    }

    /// The claim paths the whole request reveals other than through an age statement: a disclosure of the claim
    /// (legacy `claims`) or a predicate on it without age wording (an equality, a set). Collected ONCE, so the
    /// per-item check is a set lookup however many entries the request has.
    private static func revealedClaimPaths(_ entries: [PresentationConsentEntry]) -> Set<ClaimPathKey> {
        var paths = Set<ClaimPathKey>()
        for entry in entries {
            for item in entry.items {
                switch item {
                case .claim(let name): paths.insert(ClaimPathKey([name]))
                case .predicate(let predicate) where predicate.ageForm == nil: paths.insert(ClaimPathKey(predicate.claim.path))
                default: break
                }
            }
        }
        return paths
    }

    private static func predicate(
        _ registered: PredicateFunction, _ parsed: ParsedPredicate, claims: [PresentationConsentClaimRef], namespace: String?, today: CivilDate
    ) -> PresentationConsentPredicate {
        let metadataPath = (namespace.map { [$0] } ?? []) + parsed.path
        let wanted = ClaimPathKey(metadataPath)
        let label = claims.first { ClaimPathKey($0.path) == wanted }?.label
        let usable = label.flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0 }
        return PresentationConsentPredicate(
            functionId: registered.id, claim: PresentationConsentClaimRef(path: parsed.path, label: usable),
            valueType: registered.valueType, conditions: parsed.conditions,
            ageForm: registered.ageSpecialisation ? ageForm(parsed.conditions, today: today) : nil)
    }

    /// Both bounds -> between; only `le` -> at least; only `ge` -> at most (completed years, never below 0).
    private static func ageForm(_ conditions: [PredicateCondition], today: CivilDate) -> PredicateAgeForm? {
        // The age wording says only the birth date's range and that the exact date is not shared. It is used only
        // when EVERY condition is one `ge` and/or one `le` bound: any other comparison (an `eq` reveals the date)
        // falls back to the generic wording, which states every comparison.
        let ops = conditions.map(\.op)
        guard ops.allSatisfy({ $0 == .ge || $0 == .le }), Set(ops).count == ops.count else { return nil }
        let ge = conditions.first { $0.op == .ge }?.values.first
        let le = conditions.first { $0.op == .le }?.values.first
        let geDate = ge.flatMap { CivilDate($0) }, leDate = le.flatMap { CivilDate($0) }
        if let ge, let le, let geDate, let leDate {
            return .between(from: ge, to: le, minYears: leDate.years(until: today), maxYears: geDate.years(until: today))
        }
        if let leDate { return .atLeast(years: leDate.years(until: today)) }
        if let geDate { return .atMost(years: geDate.years(until: today)) }
        return nil
    }

    private static func label(trust: CircuitZkConsentTrust, clientName: String?, origin: String) -> String {
        for candidate in [trust.entityName, clientName] {
            if let candidate, !candidate.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return candidate }
        }
        return origin
    }
}
