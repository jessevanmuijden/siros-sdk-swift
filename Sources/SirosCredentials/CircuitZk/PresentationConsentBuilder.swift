// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One credential query: the planned functions, the credential chosen for it and that
/// credential's own claim display labels (for predicate items).
public struct CircuitZkConsentQuery: Sendable {
    public let plan: [CircuitZkFunction]
    public let credential: PresentationConsentCredential
    public let claims: [PresentationConsentClaimRef]

    public init(plan: [CircuitZkFunction], credential: PresentationConsentCredential, claims: [PresentationConsentClaimRef] = []) {
        self.plan = plan
        self.credential = credential
        self.claims = claims
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
    ///   - requestSigned: whether the request was signed.
    ///   - today: `YYYY-MM-DD`, the date the age maths use.
    public static func build(
        queries: [CircuitZkConsentQuery],
        functions: PredicateFunctions = .default,
        trust: CircuitZkConsentTrust,
        verifiedClientIdDisplayName: String?,
        attestedOrigin: String,
        verifierId: String?,
        verifierIdType: String?,
        requestSigned: Bool = true,
        today: String
    ) -> PresentationConsentRequest? {
        guard let todayDate = CivilDate(today) else { return nil }
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

    private static let pseudonymFunction = "pseudonym-v1-sha256"
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
                out.append(.predicate(predicate(registered, parsed, claims: query.claims, today: today)))
            }
        }
        return out.isEmpty ? nil : out
    }

    private static func predicate(
        _ registered: PredicateFunction, _ parsed: ParsedPredicate, claims: [PresentationConsentClaimRef], today: CivilDate
    ) -> PresentationConsentPredicate {
        let label = claims.first { $0.path == parsed.path }?.label
        let usable = label.flatMap { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0 }
        return PresentationConsentPredicate(
            functionId: registered.id, claim: PresentationConsentClaimRef(path: parsed.path, label: usable),
            valueType: registered.valueType, conditions: parsed.conditions,
            ageForm: registered.ageSpecialisation ? ageForm(parsed.conditions, today: today) : nil)
    }

    /// Both bounds -> between; only `le` -> at least; only `ge` -> at most (completed years, never below 0).
    private static func ageForm(_ conditions: [PredicateCondition], today: CivilDate) -> PredicateAgeForm? {
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
