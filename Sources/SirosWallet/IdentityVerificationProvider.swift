// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Result of an identity verification session.
///
/// The primary output is a `credentialOfferURI` that can be passed directly to
/// ``SirosWallet/startIssuance(offerUri:)`` to accept the issued credential.
public struct IDVResult: Sendable, Equatable {
    /// OID4VCI credential offer URI (e.g. `openid-credential-offer://...`).
    public let credentialOfferURI: String

    /// Opaque transaction ID for audit/support purposes. Provider-specific.
    public let transactionId: String?

    public init(credentialOfferURI: String, transactionId: String? = nil) {
        self.credentialOfferURI = credentialOfferURI
        self.transactionId = transactionId
    }
}

/// Errors that can occur during identity verification.
///
/// Each case exposes an ``errorCode`` for i18n mapping.
public enum IDVError: Error, Sendable {
    /// The user cancelled the verification flow.
    case cancelled
    /// The provider is not available on this device (e.g. no camera).
    case unavailable(reason: String)
    /// Liveness check failed.
    case livenessFailed(message: String)
    /// Document scan or face-match failed.
    case verificationFailed(message: String)
    /// Network or backend error.
    case networkError(underlying: Error)
    /// The backend refused to issue because the document's NFC chip was not
    /// read and authenticated, which facetec-api requires for every credential
    /// (sirosfoundation/facetec-api#65). `reason` is the backend's `nfc_*` code
    /// and ``errorCode`` is `idv_<reason>`.
    ///
    /// Through ``RemoteIDVClient`` (facetec-api's `/v1/id-scan`) the reason is
    /// always `nfc_skipped`: that path only learns whether the chip was
    /// verified, not why it was not. facetec-api's `/process-request` flow
    /// distinguishes `nfc_not_requested`, `nfc_device_not_capable`,
    /// `nfc_chip_read_failed` and `nfc_not_authenticated` as well, and any
    /// `nfc_*` code a backend sends maps here.
    case documentChipNotVerified(reason: String, message: String)
    /// The backend refused to issue because the document's chip data could not
    /// be verified against a trusted document signer (facetec-api's
    /// `chip_untrusted`, from its trust PDP). Retrying with the same document
    /// will not help; the user needs another one.
    case chipUntrusted(message: String)
    /// The backend refused to issue because the face did not match the photo
    /// stored on the document's chip (facetec-api's `chip_photo_mismatch`, from
    /// FaceTec's `matchLevelNFCToFaceMap`), or could not be compared with it.
    /// Matching the photo printed on the document is not enough: only the chip
    /// photo ties the chip, and so the identity, to the person scanned.
    case chipPhotoMismatch(message: String)
    /// The backend refused to issue because the document has expired or its
    /// expiry date could not be read as unexpired (facetec-api's
    /// `document_expired`). The user needs a valid document.
    case documentExpired(message: String)
    /// The backend no longer has the verification session: it expired or was
    /// already used (facetec-api's `session_expired`). The user has to start
    /// the verification again.
    case sessionExpired(message: String)
    /// Provider-specific error.
    case providerError(code: String, message: String)

    /// Machine-readable error code for i18n mapping.
    public var errorCode: String {
        switch self {
        case .cancelled: return "idv_cancelled"
        case .unavailable: return "idv_unavailable"
        case .livenessFailed: return "idv_liveness_failed"
        case .verificationFailed: return "idv_verification_failed"
        case .networkError: return "idv_network_error"
        case .documentChipNotVerified(let reason, _): return "idv_\(reason)"
        case .chipUntrusted: return "idv_chip_untrusted"
        case .chipPhotoMismatch: return "idv_chip_photo_mismatch"
        case .documentExpired: return "idv_document_expired"
        case .sessionExpired: return "idv_session_expired"
        case .providerError(let code, _): return "idv_provider_\(code)"
        }
    }
}

extension IDVError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .cancelled: return "Identity verification cancelled by user"
        case .unavailable(let reason): return "IDV provider unavailable: \(reason)"
        case .livenessFailed(let message): return message
        case .verificationFailed(let message): return message
        case .networkError(let underlying): return "Network error during IDV: \(underlying.localizedDescription)"
        case .documentChipNotVerified(_, let message): return message
        case .chipUntrusted(let message): return message
        case .chipPhotoMismatch(let message): return message
        case .documentExpired(let message): return message
        case .sessionExpired(let message): return message
        case .providerError(let code, let message): return "[\(code)] \(message)"
        }
    }
}

/// Plugin protocol for identity verification (document + liveness).
///
/// Implement this for any IDV vendor (FaceTec, iProov, Regula, Onfido, etc.).
/// The implementation manages its own capture UI and backend communication.
///
/// ## Contract
///
/// - ``startVerification(presentingViewController:)`` must present vendor-specific
///   UI (camera, document capture) and drive the full verification flow.
/// - On success, return an ``IDVResult`` containing the credential offer URI that
///   the backend issued after successful identity proofing.
/// - On failure/cancellation, throw an appropriate ``IDVError``.
///
/// ## Example
///
/// ```swift
/// let provider = FaceTecIDVProvider(config: FaceTecIDVConfig(
///     processRequestUrl: URL(string: "https://idv.example.com/v1/process-request")!,
///     authToken: "Bearer \(token)",
///     deviceKeyIdentifier: "<from FaceTec>"
/// ))
/// try await wallet.verifyIdentityAndIssue(provider: provider, presentingViewController: viewController)
/// ```
///
/// ## Thread Safety
///
/// Implementations must be safe to call from any actor context. UI presentation
/// should be dispatched to the main actor internally.
public protocol IdentityVerificationProvider: AnyObject, Sendable {
    /// Human-readable name of the provider (e.g. "FaceTec", "iProov").
    var name: String { get }

    /// Whether this provider is available on the current device.
    ///
    /// Check for camera availability, SDK initialization status, etc.
    func isAvailable() async -> Bool

    /// Start the identity verification flow.
    ///
    /// The implementation should:
    /// 1. Present its own capture UI (face scan, document photos)
    /// 2. Communicate with its backend to perform liveness/document checks
    /// 3. Trigger credential issuance on the backend
    /// 4. Return the resulting credential offer URI
    ///
    /// - Parameter presentingViewController: The UIViewController to present from.
    ///   Implementations should cast to `UIViewController` internally.
    /// - Throws: ``IDVError`` on failure or cancellation.
    /// - Returns: An ``IDVResult`` containing the credential offer URI.
    func startVerification(presentingViewController: Any) async throws -> IDVResult
}

extension IDVError {
    /// Maps a refusal code from facetec-api (`credentialIssueErrorCode` from
    /// `/process-request`, or `error_code` of a legacy `/v1` 422) to an
    /// ``IDVError``. siros-sdk-kotlin maps the same way (`idvExceptionForCode`).
    ///
    /// - `nfc_*`: the document's chip was not read and authenticated
    ///   (``documentChipNotVerified(reason:message:)``).
    /// - `chip_untrusted`, `chip_photo_mismatch`, `document_expired`,
    ///   `session_expired`: ``chipUntrusted(message:)``,
    ///   ``chipPhotoMismatch(message:)``, ``documentExpired(message:)``,
    ///   ``sessionExpired(message:)``.
    /// - `liveness_failed`: ``livenessFailed(message:)``.
    /// - `match_failed`, `policy_rejected`, `document_unreadable`:
    ///   ``verificationFailed(message:)``.
    /// - Anything else, e.g. `issuance_failed`, `internal_error` or a code a
    ///   newer facetec-api adds: ``providerError(code:message:)``, which keeps
    ///   the code (`errorCode` = `idv_provider_<code>`) so an app can still
    ///   explain it.
    init(refusalCode code: String, message: String?) {
        let text = message ?? "No credential was issued (\(code))"
        switch code {
        case _ where code.hasPrefix("nfc_"):
            self = .documentChipNotVerified(reason: code, message: text)
        case "chip_untrusted":
            self = .chipUntrusted(message: text)
        case "chip_photo_mismatch":
            self = .chipPhotoMismatch(message: text)
        case "document_expired":
            self = .documentExpired(message: text)
        case "session_expired":
            self = .sessionExpired(message: text)
        case "liveness_failed":
            self = .livenessFailed(message: text)
        case "match_failed", "policy_rejected", "document_unreadable":
            self = .verificationFailed(message: text)
        default:
            self = .providerError(code: code, message: text)
        }
    }
}
