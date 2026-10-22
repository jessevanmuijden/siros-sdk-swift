// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One payload parameter to show the user (TS12 v1.0.1 section 3.3.1).
public struct TransactionConsentField: Sendable, Equatable {
    /// Localised parameter name from the attestation's claim metadata.
    public let label: String
    /// The value exactly as the verifier sent it, rendered as text.
    public let value: String
    /// Visualisation level, 1 to 4 (section 3.3.1): 1 prominent on the main
    /// screen, 2 on the main screen, 3 on the main or a supplementary screen
    /// (the default when the metadata sets none), 4 may be omitted.
    public let level: Int
    /// The claim path below `payload` (`nil` selects every array element).
    public let path: [String?]

    public init(label: String, value: String, level: Int, path: [String?]) {
        self.label = label
        self.value = value
        self.level = level
        self.path = path
    }
}

/// One transaction to show (TS12 section 3.3). Fields are ordered by level,
/// then by the attestation's own claim order; the app places them.
public struct TransactionConsentEntry: Sendable, Equatable {
    /// `transaction_title` from the UI-element catalogue, when the
    /// attestation provides one (section 3.3.3); otherwise the app may choose.
    public let title: String?
    /// Human name of the transaction type ("Payment Confirmation", ...); the
    /// type URI itself for a custom type.
    public let typeName: String
    public let fields: [TransactionConsentField]
    /// `affirmative_action_label` (REQUIRED, at most 30 characters).
    public let affirmativeLabel: String
    /// `denial_action_label`; when `nil` the app defines the label.
    public let denialLabel: String?
    /// `security_hint`; when `nil` the app MUST NOT show one.
    public let securityHint: String?

    public init(title: String?, typeName: String, fields: [TransactionConsentField],
                affirmativeLabel: String, denialLabel: String?, securityHint: String?) {
        self.title = title
        self.typeName = typeName
        self.fields = fields
        self.affirmativeLabel = affirmativeLabel
        self.denialLabel = denialLabel
        self.securityHint = securityHint
    }
}

/// The attributes of one credential that will be disclosed with the
/// transaction (TS12 3.3.1: transactional data is shown "in conjunction with
/// the requested attributes").
public struct TransactionConsentAttributes: Sendable, Equatable {
    public let credentialName: String
    /// Claim names as requested; the SDK has no localised names for them here.
    public let claims: [String]

    public init(credentialName: String, claims: [String]) {
        self.credentialName = credentialName
        self.claims = claims
    }
}

/// Everything the host app needs to ask for consent to a transaction.
public struct TransactionConsentRequest: Sendable, Equatable {
    public let verifier: String
    public let credentialName: String
    public let entries: [TransactionConsentEntry]
    /// `false`: the authorization request is not signed, so the app MUST warn
    /// the user and require explicit confirmation (TS12 section 3.1). `nil`:
    /// the SDK does not know (the orchestrator pre-verifies).
    public let requestSigned: Bool?
    public let locale: String
    /// What will be disclosed alongside the transaction.
    public let attributes: [TransactionConsentAttributes]

    /// The affirmative label when every entry gives the same one; `nil`
    /// otherwise, in which case one button would consent to differently
    /// worded transactions and the app must use its own wording (for example
    /// "confirm all").
    public var commonAffirmativeLabel: String? {
        guard let first = entries.first?.affirmativeLabel, entries.allSatisfy({ $0.affirmativeLabel == first }) else { return nil }
        return first
    }

    /// The denial label when every entry gives the same one (including none
    /// at all, which is `nil` too); otherwise `nil`.
    public var commonDenialLabel: String? {
        guard let first = entries.first?.denialLabel, entries.allSatisfy({ $0.denialLabel == first }) else { return nil }
        return first
    }

    public init(verifier: String, credentialName: String, entries: [TransactionConsentEntry],
                requestSigned: Bool?, locale: String, attributes: [TransactionConsentAttributes] = []) {
        self.attributes = attributes
        self.verifier = verifier
        self.credentialName = credentialName
        self.entries = entries
        self.requestSigned = requestSigned
        self.locale = locale
    }
}

/// Implemented by the host app to show a transaction and ask the user.
///
/// Returning `false`, throwing, or not answering within the SDK's time limit
/// all count as DECLINED, never as consent.
public protocol TransactionConsentHandler: AnyObject, Sendable {
    func confirm(_ request: TransactionConsentRequest) async throws -> Bool
}
