// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosTransport

/// Why EC TS12 payment-SCA `transaction_data` was refused or declined.
///
/// One reason set shared with the Kotlin SDK (`TransactionDataError.Reason`),
/// so both SDKs answer the verifier and the user identically. The SDK
/// returns the reason; the host app words it in its own language.
public struct TransactionDataError: Error, Sendable, Equatable, CustomStringConvertible {
    public enum Reason: String, Sendable, Equatable, CaseIterable {
        /// TS12 handling is not effectively enabled (flag off, or no consent handler).
        case disabled
        /// An entry is not decodable, lacks `type`/`credential_ids`, or names an unrequested credential.
        case invalidEntry
        /// The orchestrator's decoded hint disagrees with the raw entry.
        case inconsistentWithOrchestrator
        /// The credential answering the query is not SD-JWT VC.
        case unsupportedFormat
        /// The credential's type metadata is not an SCA attestation (`category`).
        case notScaAttestation
        /// `type` is not offered by the credential's type metadata nor built in.
        case unsupportedType
        /// `payload` violates the type's JSON Schema.
        case schemaViolation
        /// Type metadata (or its schema / labels) could not be obtained.
        case metadataUnavailable
        /// None of the verifier's `transaction_data_hashes_alg` is supported.
        case unsupportedHashAlgorithm
        /// Fewer than two distinct authentication-factor categories for this operation.
        case insufficientAuthenticationFactors
        /// No consent handler is registered, so the transaction cannot be shown.
        case noConsentHandler
        /// The user declined.
        case declined
    }

    public let reason: Reason
    /// Developer-facing detail; never shown verbatim to the user and never
    /// carries payload contents.
    public let detail: String
    /// Set by the service for a refusal it already wrote to the transaction
    /// log, so a caller does not log it a second time.
    public var alreadyLogged = false

    public init(_ reason: Reason, detail: String = "") {
        self.reason = reason
        self.detail = detail
    }

    /// The OAuth/OpenID4VP error code to answer the verifier with:
    /// `access_denied` when the user declined, `invalid_transaction_data`
    /// for every refusal.
    public var verifierErrorCode: String {
        reason == .declined ? "access_denied" : "invalid_transaction_data"
    }

    /// Machine-readable code for app i18n (`SirosError.errorCode`).
    public var errorCode: String { "transaction_data_\(reason.rawValue)" }

    /// What may reach a user-visible error: the reason only. `detail` is
    /// developer-facing and is left to `description`.
    public var userFacingDescription: String { "transaction_data refused: \(reason.rawValue)" }

    public var description: String {
        detail.isEmpty ? "transaction_data refused: \(reason.rawValue)"
            : "transaction_data refused: \(reason.rawValue) (\(detail))"
    }
}

extension TransactionDataError: WmpErrorCodeProviding {
    public var wmpErrorCode: String? { verifierErrorCode }
}
