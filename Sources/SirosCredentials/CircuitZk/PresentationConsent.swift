// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// The consent model for a `circuit_zk` presentation: what the user is asked to
// approve, in a LOCALE-FREE form, plus the host callback that asks them.
//
// Mirror of the Kotlin SDK's model, tested against the shared
// `circuit-zk-consent-vectors.json` (spec/circuit-zk-consent-vectors.md in
// siros-sdk-kotlin). The SDK owns the wording and generates it from these items;
// the trust framework and `verifier_id_type` are carried for hosts and tests and
// never appear in the default dialog text.

/// The type of the claim a predicate is about; operands are carried as text of this type.
public enum PredicateValueType: String, Sendable, Equatable {
    case date, number, string, bool
}

/// A comparison operator of a predicate condition.
public enum PredicateOp: String, Sendable, Equatable {
    case eq, ne, lt, le, gt, ge
    case `in`
}

/// One comparison a predicate makes on its claim; the claim satisfies ALL conditions of a predicate.
public struct PredicateCondition: Sendable, Equatable {
    public let op: PredicateOp
    /// The operand(s) as text of the claim's type; more than one only for `in`.
    public let values: [String]

    public init(op: PredicateOp, values: [String]) {
        self.op = op
        self.values = values
    }
}

/// The claim a predicate is about: its path and the credential's OWN display label for it, if
/// the credential declares one (a renderer falls back to the path, never an invented name).
public struct PresentationConsentClaimRef: Sendable, Equatable {
    public let path: [String]
    public let label: String?

    public init(path: [String], label: String?) {
        self.path = path
        self.label = label
    }
}

/// How an age statement reads, for a function declared as an age: the bounds are dates of birth.
public enum PredicateAgeForm: Sendable, Equatable {
    case between(from: String, to: String, minYears: Int, maxYears: Int)
    case atLeast(years: Int)
    case atMost(years: Int)
}

/// What the verifier LEARNS about a claim: that it satisfies every condition, never its value.
public struct PresentationConsentPredicate: Sendable, Equatable {
    public let functionId: String
    public let claim: PresentationConsentClaimRef
    public let valueType: PredicateValueType
    public let conditions: [PredicateCondition]
    /// Set only for a function the registry declares as an age (`ageSpecialisation`).
    public let ageForm: PredicateAgeForm?

    public init(
        functionId: String, claim: PresentationConsentClaimRef, valueType: PredicateValueType,
        conditions: [PredicateCondition], ageForm: PredicateAgeForm?
    ) {
        self.functionId = functionId
        self.claim = claim
        self.valueType = valueType
        self.conditions = conditions
        self.ageForm = ageForm
    }
}

/// One thing the user is asked to prove or release.
public enum PresentationConsentItem: Sendable, Equatable {
    /// A pseudonym. Only per-verifier configurations are modelled.
    case pseudonym(
        config: String,
        scope: PseudonymScope,
        remappableByIssuer: Bool,
        crossSite: Bool,
        verifierId: String,
        verifierContext: String?
    )
    /// A predicate over a claim (any claim: the function set is open-ended).
    case predicate(PresentationConsentPredicate)
    /// A claim disclosed by a legacy (non-`circuit_zk`-native) proof system.
    case claim(name: String)
    /// The legacy proof system's own pseudonym.
    case legacyPseudonym(verifierContext: String?)

    public enum PseudonymScope: String, Sendable, Equatable {
        case perVerifier = "per_verifier"
        case crossSite = "cross_site"
    }
}

/// The credential a set of items will be proved from; both parts may be unknown.
public struct PresentationConsentCredential: Sendable, Equatable {
    public let name: String?
    public let issuer: String?

    public init(name: String?, issuer: String?) {
        self.name = name
        self.issuer = issuer
    }
}

/// One credential and what is proved from it.
public struct PresentationConsentEntry: Sendable, Equatable {
    public let credential: PresentationConsentCredential
    public let items: [PresentationConsentItem]

    public init(credential: PresentationConsentCredential, items: [PresentationConsentItem]) {
        self.credential = credential
        self.items = items
    }
}

/// Who is asking. `trustFramework` and `verifierIdType` are technical detail for
/// hosts and tests; the default dialog text never shows them.
public struct PresentationConsentVerifier: Sendable, Equatable {
    /// The display name: the trust entity name, else the verified client-id
    /// display name, else the attested origin.
    public let label: String
    public let trustFramework: String?
    public let trustIdentifier: String?
    /// The identifier the pseudonym is derived for, verbatim; present only when a
    /// pseudonym is requested. Use ``PresentationConsentRequest/shortened(verifierId:)``
    /// to show it.
    public let verifierId: String?
    public let verifierIdType: String?
    public let intermediaryRisk: Bool

    public init(
        label: String, trustFramework: String?, trustIdentifier: String?,
        verifierId: String?, verifierIdType: String?, intermediaryRisk: Bool
    ) {
        self.label = label
        self.trustFramework = trustFramework
        self.trustIdentifier = trustIdentifier
        self.verifierId = verifierId
        self.verifierIdType = verifierIdType
        self.intermediaryRisk = intermediaryRisk
    }
}

/// Everything one consent call covers: all queries of the request, asked once,
/// before anything is signed or proved.
public struct PresentationConsentRequest: Sendable, Equatable {
    public let verifier: PresentationConsentVerifier
    public let entries: [PresentationConsentEntry]
    /// Whether the request itself was signed (the verifier's identity is then authenticated).
    public let requestSigned: Bool

    public init(verifier: PresentationConsentVerifier, entries: [PresentationConsentEntry], requestSigned: Bool) {
        self.verifier = verifier
        self.entries = entries
        self.requestSigned = requestSigned
    }

    /// A `verifier_id` as it is DISPLAYED: more than 40 code points keep the
    /// first and the last 18 joined by U+2026. The value used for hashing is
    /// never altered; show the full value on expand.
    public static func shortened(verifierId: String) -> String {
        let scalars = Array(verifierId.unicodeScalars)
        guard scalars.count > 40 else { return verifierId }
        var out = String.UnicodeScalarView()
        out.append(contentsOf: scalars.prefix(18))
        out.append("\u{2026}")
        out.append(contentsOf: scalars.suffix(18))
        return String(out)
    }
}

/// Implemented by the host app to show what a `circuit_zk` request will prove
/// and ask the user. A sibling of ``TransactionConsentHandler``, separate from it
/// and not tied to the transaction-data flag.
///
/// Returning `false`, throwing, or not answering within the SDK's time limit all
/// count as DECLINED, never as consent. With no handler a `circuit_zk` request is
/// refused: there is no silent consent.
public protocol PresentationConsentHandler: AnyObject, Sendable {
    func confirm(_ request: PresentationConsentRequest) async throws -> Bool
}

