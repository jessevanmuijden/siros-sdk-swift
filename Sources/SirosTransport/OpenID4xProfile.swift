// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// MARK: - Flow Type Constants

/// The nested flows the orchestrator starts for the wallet (WMP openid4x section 3.1.5): each arrives as
/// `wmp.flow.start` on a CHILD flow id and is answered with `wmp.flow.complete` on that child flow.
public enum WmpSubFlowTypes {
    public static let sign = "sign"
    public static let match = "match"
}

public enum OID4FlowTypes {
    public static let oid4vci = "oid4vci"
    public static let oid4vp = "oid4vp"
}

// MARK: - OID4VCI Step Constants

public enum VCIStep {
    public static let parsingOffer = "parsing_offer"
    public static let resolvingMetadata = "resolving_metadata"
    public static let metadataFetched = "metadata_fetched"
    public static let evaluatingTrust = "evaluating_trust"
    public static let trustEvaluated = "trust_evaluated"
    public static let awaitingOfferAcceptance = "awaiting_offer_acceptance"
    public static let awaitingTxCode = "awaiting_tx_code"
    public static let authorizationPending = "authorization_pending"
    public static let generatingProof = "generating_proof"
    public static let requestingCredential = "requesting_credential"
    public static let credentialReceived = "credential_received"
}

// MARK: - OID4VP Step Constants

public enum VPStep {
    public static let parsingRequest = "parsing_request"
    public static let requestParsed = "request_parsed"
    public static let matchingCredentials = "matching_credentials"
    public static let awaitingConsent = "awaiting_consent"
    public static let generatingPresentation = "generating_presentation"
    public static let evaluatingVerifierTrust = "evaluating_verifier_trust"
}

// MARK: - Action Constants

public enum OID4Action {
    public static let acceptOffer = "accept_offer"
    public static let provideTxCode = "provide_tx_code"
    public static let authorize = "authorize"
    public static let selectCredentials = "select_credentials"
    public static let cancel = "cancel"
}

// MARK: - Credential Format Constants

public enum CredentialFormat {
    public static let vcSdJwt = "vc+sd-jwt"
    public static let dcSdJwt = "dc+sd-jwt"
    public static let msoMdoc = "mso_mdoc"
    public static let jwtVcJson = "jwt_vc_json"
}

// MARK: - Grant Type Constants

public enum GrantType {
    public static let authorizationCode = "authorization_code"
    public static let preAuthorizedCode = "pre-authorized_code"
}

// MARK: - Proof Type Constants

public enum ProofType {
    public static let jwt = "jwt"
    public static let attestation = "attestation"
    public static let cwt = "cwt"
}

// MARK: - OID4VCI §10 Credential Lifecycle Events

public enum CredentialEvent {
    public static let accepted = "credential_accepted"
    public static let failure = "credential_failure"
}

// MARK: - Typed Data Structures

public struct CredentialConfigurationSupported: Codable, Sendable {
    public var format: String
    public var scope: String?
    public var vct: String?
    public var doctype: String?
    public var proofTypesSupported: AnyCodable?
    public var display: [CredentialDisplay]?

    enum CodingKeys: String, CodingKey {
        case format, scope, vct, doctype, display
        case proofTypesSupported = "proof_types_supported"
    }
}

public struct CredentialDisplay: Codable, Sendable {
    public var name: String
    public var locale: String?
    public var description: String?
    public var logoUri: String?
    public var logoAltText: String?
    public var backgroundColor: String?
    public var textColor: String?

    enum CodingKeys: String, CodingKey {
        case name, locale, description
        case logoUri = "logo_uri"
        case logoAltText = "logo_alt_text"
        case backgroundColor = "background_color"
        case textColor = "text_color"
    }
}

// CredentialResult is defined in EngineTypes.swift

public struct VPTokenResult: Codable, Sendable {
    public var vpToken: String?
    public var presentationSubmission: AnyCodable?
    public var responseCode: String?

    enum CodingKeys: String, CodingKey {
        case vpToken = "vp_token"
        case presentationSubmission = "presentation_submission"
        case responseCode = "response_code"
    }
}

/// One `transaction_data` entry as the orchestrator relays it (legacy engine
/// `sign_request.params.transaction_data[]` and the WMP sign sub-flow; go-wmp
/// `openid4x.TransactionData`).
///
/// `raw` is the verifier's base64url string exactly as sent: the ONLY valid
/// hash input (OpenID4VP 1.0 Appendix B). Every other member is the
/// orchestrator's decoded hint and must never be trusted over `raw`.
public struct TransactionData: Codable, Sendable {
    public var type: String
    public var params: AnyCodable?
    public var credentialIds: [String]?
    public var hashAlgorithm: String?
    /// The base64url string exactly as the verifier sent it.
    public var raw: String?
    /// The decoded `payload` object (TS12 section 3.2 step 4).
    public var payload: AnyCodable?
    /// The request's `transaction_data_hashes_alg`: an array in OpenID4VP 1.0
    /// Appendix B; a bare string is tolerated on input.
    public var hashesAlg: [String]?

    enum CodingKeys: String, CodingKey {
        case type, params, raw, payload
        case credentialIds = "credential_ids"
        case hashAlgorithm = "hash_alg"
        case hashesAlg = "transaction_data_hashes_alg"
    }

    public init(
        type: String,
        params: AnyCodable? = nil,
        credentialIds: [String]? = nil,
        hashAlgorithm: String? = nil,
        raw: String? = nil,
        payload: AnyCodable? = nil,
        hashesAlg: [String]? = nil
    ) {
        self.type = type
        self.params = params
        self.credentialIds = credentialIds
        self.hashAlgorithm = hashAlgorithm
        self.raw = raw
        self.payload = payload
        self.hashesAlg = hashesAlg
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        type = try c.decode(String.self, forKey: .type)
        params = try c.decodeIfPresent(AnyCodable.self, forKey: .params)
        credentialIds = try c.decodeIfPresent([String].self, forKey: .credentialIds)
        hashAlgorithm = try c.decodeIfPresent(String.self, forKey: .hashAlgorithm)
        raw = try c.decodeIfPresent(String.self, forKey: .raw)
        payload = try c.decodeIfPresent(AnyCodable.self, forKey: .payload)
        if let list = try? c.decodeIfPresent([String].self, forKey: .hashesAlg) {
            hashesAlg = list
        } else if let single = try? c.decodeIfPresent(String.self, forKey: .hashesAlg) {
            hashesAlg = [single]
        } else {
            hashesAlg = nil
        }
    }
}

/// An error that names the WMP flow-error code it should be reported with
/// (for example `invalid_transaction_data`); any other error is `SIGN_ERROR`.
public protocol WmpErrorCodeProviding {
    var wmpErrorCode: String? { get }
}

/// The `transaction_data` member of a sign request with its PRESENCE kept: an
/// absent member, an explicit `null` and an empty array are different things,
/// and a request that names the member at all must never be answered as if it
/// did not.
public struct TransactionDataMember: Codable, Sendable {
    public var entries: [TransactionData]?
    /// The member was present and `null`.
    public var isExplicitNull: Bool
    /// The member was present but not an array of well-formed entries (a
    /// scalar, an object, an entry without `type`, ...). It must be REFUSED,
    /// never read as absent, and decoding must not throw: a request that failed
    /// to decode is dropped silently by the transport and the verifier would
    /// get no answer at all.
    public var isMalformed: Bool

    public init(entries: [TransactionData]? = nil, isExplicitNull: Bool = false, isMalformed: Bool = false) {
        self.entries = entries
        self.isExplicitNull = isExplicitNull
        self.isMalformed = isMalformed
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self.init(entries: nil, isExplicitNull: true)
        } else if let entries = try? c.decode([TransactionData].self) {
            self.init(entries: entries)
        } else {
            self.init(entries: nil, isMalformed: true)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        if let entries { try c.encode(entries) } else { try c.encodeNil() }
    }

    /// Whether a request carrying this member asks for TS12 handling:
    /// anything but absent or an empty array (explicit null and malformed included).
    public var requestsTransactionHandling: Bool { isExplicitNull || isMalformed || !(entries ?? []).isEmpty }
}

extension KeyedDecodingContainer {
    /// An absent key decodes as an absent member rather than an error.
    func decode(_: TransactionDataMember.Type, forKey key: Key) throws -> TransactionDataMember {
        guard contains(key) else { return TransactionDataMember() }
        return try TransactionDataMember(from: try superDecoder(forKey: key))
    }
}

extension KeyedEncodingContainer {
    /// An absent member is omitted, never written as `null`.
    mutating func encode(_ value: TransactionDataMember, forKey key: Key) throws {
        guard value.entries != nil || value.isExplicitNull || value.isMalformed else { return }
        try encodeValue(value, forKey: key)
    }

    private mutating func encodeValue(_ value: TransactionDataMember, forKey key: Key) throws {
        if let entries = value.entries { try encode(entries, forKey: key) } else { try encodeNil(forKey: key) }
    }
}

public struct SignSubFlowParams: Codable, Sendable {
    public var action: String
    public var nonce: String
    public var audience: String
    public var proofType: String?
    public var parentFlowId: String?
    public var count: Int?
    /// The member with its presence kept (see `TransactionDataMember`).
    public var transactionDataMember = TransactionDataMember()
    public var transactionData: [TransactionData]? {
        get { transactionDataMember.entries }
        set { transactionDataMember = TransactionDataMember(entries: newValue) }
    }
    /// OID4VP `response_mode` of the request (go-wmp `SignSubFlowParams`).
    public var responseMode: String?
    /// Which credential answers which DCQL query id (go-wmp v0.6.0).
    public var credentialsToInclude: [CredentialRef]?
    /// The verifier-assigned session id (go-wmp v0.6.0).
    public var verifierSessionId: String?
    /// PoP/proof `iss` (the flow's OAuth client_id) for `request_attestation`
    /// and `sign_client_auth`.
    public var issuer: String?
    /// `sign_client_auth` parameters (go-wallet-backend#317), same names and
    /// meaning as the legacy transport's `SignRequestParams`: `htm`/`htu` ask
    /// for a DPoP proof (with `dpopNonce` and `ath` claims), `keyId` names
    /// the key to sign with on a renewal. `audience` doubles as the
    /// attestation PoP aud when the request also needs client attestation.
    public var htm: String?
    public var htu: String?
    public var dpopNonce: String?
    public var ath: String?
    public var keyId: String?
    /// `generate_proof`: the response encryption the engine negotiated (see `SignRequestParams`).
    public var credentialResponseEncryption: CredentialResponseEncryptionRequest?
    /// `decrypt_credential_response`: the Credential Response JWE and whether it is a deferred one.
    public var jwe: String?
    public var deferred: Bool?
    /// `generate_proof` over WMP, when the peer sends it: an EMPTY object with
    /// `credential_response_encryption` means the request is for the key alone (no proofs).
    public var proofTypesSupported: [String: AnyCodable]?

    enum CodingKeys: String, CodingKey {
        case action, nonce, audience, count, issuer, htm, htu, ath, jwe, deferred
        case proofTypesSupported = "proof_types_supported"
        case credentialResponseEncryption = "credential_response_encryption"
        case proofType = "proof_type"
        case parentFlowId = "parent_flow_id"
        case transactionDataMember = "transaction_data"
        case responseMode = "response_mode"
        case credentialsToInclude = "credentials_to_include"
        case verifierSessionId = "verifier_session_id"
        case dpopNonce = "dpop_nonce"
        case keyId = "key_id"
    }

    public init(
        action: String,
        nonce: String = "",
        audience: String = "",
        proofType: String? = nil,
        parentFlowId: String? = nil,
        count: Int? = nil,
        transactionData: [TransactionData]? = nil,
        responseMode: String? = nil,
        credentialsToInclude: [CredentialRef]? = nil,
        verifierSessionId: String? = nil,
        issuer: String? = nil,
        htm: String? = nil,
        htu: String? = nil,
        dpopNonce: String? = nil,
        ath: String? = nil,
        keyId: String? = nil,
        credentialResponseEncryption: CredentialResponseEncryptionRequest? = nil,
        jwe: String? = nil,
        deferred: Bool? = nil,
        proofTypesSupported: [String: AnyCodable]? = nil
    ) {
        self.proofTypesSupported = proofTypesSupported
        self.credentialResponseEncryption = credentialResponseEncryption
        self.jwe = jwe
        self.deferred = deferred
        self.action = action
        self.nonce = nonce
        self.audience = audience
        self.proofType = proofType
        self.parentFlowId = parentFlowId
        self.count = count
        self.transactionDataMember = TransactionDataMember(entries: transactionData)
        self.responseMode = responseMode
        self.credentialsToInclude = credentialsToInclude
        self.verifierSessionId = verifierSessionId
        self.issuer = issuer
        self.htm = htm
        self.htu = htu
        self.dpopNonce = dpopNonce
        self.ath = ath
        self.keyId = keyId
    }

    /// `nonce` and `audience` stay non-optional for the `generate_proof` /
    /// `sign_presentation` callers that always have them, but a
    /// `sign_client_auth` request for a DPoP-only resource request carries
    /// no audience (and no c_nonce), and a peer may omit the members rather
    /// than send empty strings. Decode them as empty when absent instead of
    /// failing the whole sub-flow with INVALID_PARAMS.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        action = try c.decode(String.self, forKey: .action)
        nonce = try c.decodeIfPresent(String.self, forKey: .nonce) ?? ""
        audience = try c.decodeIfPresent(String.self, forKey: .audience) ?? ""
        proofType = try c.decodeIfPresent(String.self, forKey: .proofType)
        parentFlowId = try c.decodeIfPresent(String.self, forKey: .parentFlowId)
        count = try c.decodeIfPresent(Int.self, forKey: .count)
        transactionDataMember = try c.decode(TransactionDataMember.self, forKey: .transactionDataMember)
        responseMode = try c.decodeIfPresent(String.self, forKey: .responseMode)
        credentialsToInclude = try c.decodeIfPresent([CredentialRef].self, forKey: .credentialsToInclude)
        verifierSessionId = try c.decodeIfPresent(String.self, forKey: .verifierSessionId)
        issuer = try c.decodeIfPresent(String.self, forKey: .issuer)
        htm = try c.decodeIfPresent(String.self, forKey: .htm)
        htu = try c.decodeIfPresent(String.self, forKey: .htu)
        dpopNonce = try c.decodeIfPresent(String.self, forKey: .dpopNonce)
        ath = try c.decodeIfPresent(String.self, forKey: .ath)
        keyId = try c.decodeIfPresent(String.self, forKey: .keyId)
        credentialResponseEncryption = try c.decodeIfPresent(CredentialResponseEncryptionRequest.self, forKey: .credentialResponseEncryption)
        jwe = try c.decodeIfPresent(String.self, forKey: .jwe)
        deferred = try c.decodeIfPresent(Bool.self, forKey: .deferred)
        proofTypesSupported = try? c.decodeIfPresent([String: AnyCodable].self, forKey: .proofTypesSupported)
    }
}

// MARK: - Client Attestation (WIA)

/// Provider for OAuth client attestation (WIA + PoP).
public protocol ClientAttestationProvider: AnyObject {
    /// Obtain a client attestation for the given audience.
    func getAttestation(audience: String) async throws -> ClientAttestation
}

public struct ClientAttestation: Codable, Sendable {
    /// Wallet Instance Attestation JWT.
    public var clientAssertion: String
    /// Proof of Possession JWT.
    public var clientAssertionPop: String

    enum CodingKeys: String, CodingKey {
        case clientAssertion = "client_assertion"
        case clientAssertionPop = "client_assertion_pop"
    }

    public init(clientAssertion: String, clientAssertionPop: String) {
        self.clientAssertion = clientAssertion
        self.clientAssertionPop = clientAssertionPop
    }
}

// MARK: - Sub-flow Result Types

// ProofObject and CredentialMatch are defined in EngineTypes.swift

public struct SignSubFlowResult: Sendable {
    public var proofs: [ProofObject]?
    public var vpToken: String?
    /// Extra members for the OID4VCI credential request the backend is
    /// about to send on this wallet's behalf.
    ///
    /// Same field, same meaning and same reserved-name rule as the legacy
    /// protocol's `SignResponseMessage.credentialRequestExtras`. The two
    /// transports carry it identically on the wire so a backend can accept
    /// either without a second code path, and so a flow behaves the same
    /// whichever transport it runs over.
    public var credentialRequestExtras: [String: AnyCodable]?
    /// `request_attestation` / `sign_client_auth` results, carried on the
    /// wire under the same names as the legacy transport's
    /// `SignResponseMessage` (`client_attestation`, `client_attestation_pop`,
    /// `dpop_key_id`, `dpop_proof`) so a backend accepts either transport
    /// without a second code path.
    public var clientAttestation: String?
    public var clientAttestationPoP: String?
    public var dpopKeyId: String?
    public var dpopProof: String?
    /// `generate_proof`: the public JWK of this proof request's response-encryption key.
    public var credentialResponseEncryptionJwk: [String: String]?
    /// `decrypt_credential_response`: only the control fields of the decrypted response.
    public var credentialCount: Int?
    public var transactionId: String?
    public var interval: Int?

    public init(
        proofs: [ProofObject]? = nil,
        vpToken: String? = nil,
        credentialRequestExtras: [String: AnyCodable]? = nil,
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil,
        dpopKeyId: String? = nil,
        dpopProof: String? = nil,
        credentialResponseEncryptionJwk: [String: String]? = nil,
        transactionId: String? = nil,
        interval: Int? = nil,
        credentialCount: Int? = nil
    ) {
        self.credentialCount = credentialCount
        self.credentialResponseEncryptionJwk = credentialResponseEncryptionJwk
        self.transactionId = transactionId
        self.interval = interval
        self.proofs = proofs
        self.vpToken = vpToken
        self.credentialRequestExtras = credentialRequestExtras
        self.clientAttestation = clientAttestation
        self.clientAttestationPoP = clientAttestationPoP
        self.dpopKeyId = dpopKeyId
        self.dpopProof = dpopProof
    }
}

// CredentialMatch is defined in EngineTypes.swift

public struct MatchResult: Sendable {
    public var matches: [CredentialMatch]
    /// Why nothing matched, when `matches` is empty - forwarded as the
    /// `no_match_reason` member of the `match_response` flow action. The
    /// engine reports it back as the `no_match_reason` detail of the error
    /// that ends the flow, so it is the only explanation the app (or a log)
    /// ever gets of why the wallet came up empty.
    public var noMatchReason: String?

    public init(matches: [CredentialMatch], noMatchReason: String? = nil) {
        self.matches = matches
        self.noMatchReason = noMatchReason
    }
}

public struct TrustResult: Sendable {
    public var trusted: Bool
    public var framework: String?
    public var reason: String?

    public init(trusted: Bool, framework: String? = nil, reason: String? = nil) {
        self.trusted = trusted
        self.framework = framework
        self.reason = reason
    }
}

// MARK: - OpenID4x Profile Configuration

// @unchecked because the stored async closures are not automatically @Sendable,
// but the struct is immutable after construction and only called from async contexts.
public struct OpenID4xConfig: @unchecked Sendable {
    public var onProgress: ((String, String, AnyCodable?) async -> Void)?
    public var onSignRequest: ((String, SignSubFlowParams) async throws -> SignSubFlowResult)?
    public var onMatchRequest: ((String, AnyCodable?) async throws -> MatchResult)?
    public var onTrustEvaluation: ((String, AnyCodable?) async throws -> TrustResult)?
    public var onComplete: ((String, AnyCodable?) async -> Void)?
    public var onError: ((String, String?, String?) async -> Void)?
    /// The peer cancelled the flow (`wmp.flow.cancel`).
    /// A flow of its own was cancelled: its id and the flow type it was started as (nil when this profile never saw it start).
    public var onCancel: ((String, String?) async -> Void)?
    public var attestationProvider: ClientAttestationProvider?
    /// The profile was shut down (the session ended, or failed for good): called synchronously on each shutdown.
    public var onShutdown: (() -> Void)?
    /// Delays before the retries of a terminal answer whose send failed, for failures that bring no resume event (a
    /// failed POST on a healthy stream). After the last one the answer waits for the next resume.
    public var sendRetryDelaysMs: [Int]

    public init(
        onProgress: ((String, String, AnyCodable?) async -> Void)? = nil,
        onSignRequest: ((String, SignSubFlowParams) async throws -> SignSubFlowResult)? = nil,
        onMatchRequest: ((String, AnyCodable?) async throws -> MatchResult)? = nil,
        onTrustEvaluation: ((String, AnyCodable?) async throws -> TrustResult)? = nil,
        onComplete: ((String, AnyCodable?) async -> Void)? = nil,
        onCancel: ((String, String?) async -> Void)? = nil,
        onError: ((String, String?, String?) async -> Void)? = nil,
        attestationProvider: ClientAttestationProvider? = nil,
        onShutdown: (() -> Void)? = nil,
        sendRetryDelaysMs: [Int] = [1_000, 2_000, 4_000, 8_000]
    ) {
        self.onCancel = onCancel
        self.onShutdown = onShutdown
        self.sendRetryDelaysMs = sendRetryDelaysMs
        self.onProgress = onProgress
        self.onSignRequest = onSignRequest
        self.onMatchRequest = onMatchRequest
        self.onTrustEvaluation = onTrustEvaluation
        self.onComplete = onComplete
        self.onError = onError
        self.attestationProvider = attestationProvider
    }
}

// MARK: - OpenID4x Profile Implementation

/// The member the engine sets on a trust progress that wants an answer; its informational progress lacks it.
private let trustEvaluationRequired = "trust_evaluation_required"

/// OpenID4x WMP profile for OID4VCI and OID4VP flows.
///
/// Handles server-initiated flows: the backend engine starts flows and
/// the SDK responds to progress events, sign requests, match requests,
/// and trust evaluations.
public final class OpenID4xProfile: WmpProfile, WmpFlowHandler, WmpShutdownProfile, WmpResumeProfile, WmpLocalCancelProfile, @unchecked Sendable {
    public let name: String = "openid4x"
    public let capabilities: [String] = ["oid4vci", "oid4vp"]
    public let flowTypes: [String] = [OID4FlowTypes.oid4vci, OID4FlowTypes.oid4vp, WmpSubFlowTypes.sign, WmpSubFlowTypes.match]

    private let config: OpenID4xConfig
    private weak var peer: WmpPeerContext?
    // Running sign / match child flows: the task, and the parent flow it belongs to.
    private let childLock = NSLock()
    private var childTasks: [String: (task: Task<Void, Never>, parent: String, token: UUID)] = [:]
    /// Answers that could not be sent (the connection was down), kept until the session resumes. The handler is
    /// not run again for them.
    private var unsentAnswers: [String: (method: String, params: [String: AnyCodable], parent: String)] = [:]
    /// Children whose queued answer a replay has claimed and is sending: not queued, not running, and not to be
    /// started again by a redelivered start.
    private var replaying: [String: String] = [:]
    /// Bumped at each resume, so an answer queued by a send that began before the resume is retried at once.
    private var resumeGeneration = 0
    /// How many timed retries the current run of failures has used; reset by a delivered answer or a resume.
    private var retryAttempts: [String: Int] = [:]
    private var cancelledChildren: Set<String> = []
    // Set by `shutdown()`: no child may be registered or started afterwards, so a start still buffered in the
    // peer's dispatch loop cannot launch a handler during teardown.
    private var stopped = false
    // Parents that ended (cancelled, completed or failed) while their child start may still be on its way: a
    // start for one of them is dropped. Bounded: only the most recent are remembered.
    private var endedParents: [String] = []
    private let maxEndedParents = 256
    /// Children whose terminal answer was sent: a redelivered start for one runs nothing. Bounded, oldest dropped.
    /// The flow type each non-child flow was started as, for `onCancel` (an `oid4vp` parent's cancel must not reset an
    /// issuance's guards). Dropped when the flow completes, fails or is cancelled.
    private var parentFlowTypes: [String: String] = [:]
    private var completedChildren: Set<String> = []
    private var completedOrder: [String] = []
    private let maxCompletedChildren = 4096

    private func rememberCompletedLocked(_ childId: String) {
        guard completedChildren.insert(childId).inserted else { return }
        completedOrder.append(childId)
        if completedOrder.count > maxCompletedChildren {
            completedChildren.remove(completedOrder.removeFirst())
        }
    }

    public init(config: OpenID4xConfig = OpenID4xConfig()) {
        self.config = config
    }

    // MARK: - WmpProfile

    public func initialize(ctx: WmpPeerContext) {
        peer = ctx
    }

    // MARK: - WmpFlowHandler

    public func startFlow(params: FlowStartParams) async throws -> FlowStartResult {
        // A sign or match sub-flow is answered when the wallet has an answer (it may wait for the user),
        // not in the reply to the start request.
        if params.flowType == WmpSubFlowTypes.sign || params.flowType == WmpSubFlowTypes.match {
            let parent = params.params?.objectValue?["parent_flow_id"]?.stringValue ?? params.flowId
            // Registered under the lock the task's own `finishChild` takes, so a fast child cannot finish first.
            childLock.lock()
            // Not after shutdown, not for a parent that already ended, and never a second handler for a child that is
            // already running (a redelivered start must not replace the first task's tracking).
            // A cancelled child's own id is in the ended list too: its redelivered start does not run it again.
            let ended = stopped || endedParents.contains(parent) || endedParents.contains(params.flowId)
                || completedChildren.contains(params.flowId)
            let tracked = childTasks[params.flowId] != nil || unsentAnswers[params.flowId] != nil || replaying[params.flowId] != nil
            if !ended, !tracked {
                let token = UUID()
                childTasks[params.flowId] = (Task { [self] in await runChildFlow(params: params, token: token) }, parent, token)
            }
            childLock.unlock()
            // A start that is refused for good (its flow ended, or the profile stopped) has no task that would ever
            // release the route the peer registered for it; a duplicate of a tracked child keeps its own.
            if ended { peer?.releaseFlow(flowId: params.flowId) }
        } else {
            childLock.lock(); parentFlowTypes[params.flowId] = params.flowType; childLock.unlock()
        }
        return FlowStartResult(flowId: params.flowId, flowType: params.flowType)
    }

    /// Run one `sign` / `match` child flow to its answer: `wmp.flow.complete` on the CHILD flow with the
    /// response as `result`, or `wmp.flow.error` on the child flow with `data.reason` `rejected` when
    /// the wallet declines or fails. The handler is told the PARENT flow id (`parent_flow_id`), the
    /// issuance or presentation the request belongs to, which is what the wallet keys its state by.
    func runChildFlow(params: FlowStartParams, token: UUID = UUID()) async {
        let childId = params.flowId
        let payload = params.params
        let parentId = payload?.objectValue?["parent_flow_id"]?.stringValue ?? childId
        // Cancelled or shut down before it got going: no handler runs (Swift cancellation does not stop a task
        // that has not started, and a handler must not begin signing for a flow that has ended).
        guard !endedBeforeStart(childId, token) else { peer?.releaseFlow(flowId: childId); return }
        let method: String
        let answer: [String: AnyCodable]
        do {
            let members: [String: AnyCodable]
            if params.flowType == WmpSubFlowTypes.sign {
                guard let handler = config.onSignRequest, let payload else { throw ChildFlowFailure(code: "INVALID_PARAMS") }
                let signParams: SignSubFlowParams
                do {
                    signParams = try JSONDecoder().decode(SignSubFlowParams.self, from: try JSONEncoder().encode(payload))
                } catch {
                    throw ChildFlowFailure(code: "INVALID_PARAMS")
                }
                members = signResponseMembers(try await handler(parentId, signParams))
            } else {
                guard let handler = config.onMatchRequest else { throw ChildFlowFailure(code: "INVALID_PARAMS") }
                members = matchResponseMembers(try await handler(parentId, payload))
            }
            method = WmpMethods.flowComplete
            answer = ["flow_id": .string(childId), "result": .object_(members)]
        } catch {
            let fallback = params.flowType == WmpSubFlowTypes.match ? "MATCH_ERROR" : "SIGN_ERROR"
            let code = (error as? WmpErrorCodeProviding)?.wmpErrorCode ?? fallback
            method = WmpMethods.flowError
            answer = [
                "flow_id": .string(childId), "code": .int(FlowErrorParams.flowErrorCode), "message": .string(code),
                "data": .object_(["reason": .string("rejected"), "error_code": .string(code)]),
            ]
        }
        // A flow that was cancelled gets no reply, whether its handler ignored the cancellation, threw
        // `CancellationError` or returned normally. The child stays tracked until its answer is out, so a
        // redelivered start cannot run a second handler beside it, and only this execution forgets it.
        guard mayAnswer(childId) else { forgetChild(childId, token); peer?.releaseFlow(flowId: childId); return }
        childLock.lock(); let sendGeneration = resumeGeneration; childLock.unlock()
        do {
            try await peer?.notify(method: method, params: answer)
        } catch {
            keepUnsent(childId, method: method, params: answer, parent: parentId, token: token, sendStartedAt: sendGeneration)
            return
        }
        forgetChild(childId, token, completed: true)
        peer?.releaseFlow(flowId: childId)
    }

    /// The session came back after a loss: the answers that could not be sent go out now.
    public func sessionResumed() {
        childLock.lock(); resumeGeneration += 1; retryAttempts.removeAll(); childLock.unlock()
        drainUnsent()
    }

    /// Sends the queued answers. Each is CLAIMED under the lock before its send is awaited, so a second drain (another
    /// resume while this send is suspended) cannot send it again; a failed send puts it back unless its flow has ended.
    ///
    /// - Parameter only: a timed retry drains just its OWNING child (revalidated: still queued, budget not spent by
    ///   anyone else); only a resume drains the whole queue.
    /// - Parameter onlyIfGeneration: a timer's resume generation: a timer scheduled before a resume (which reset the
    ///   budgets and replayed the queue) is stale, and is validated under the same lock that claims the answer.
    private func drainUnsent(only childId: String? = nil, onlyIfGeneration timerGeneration: Int? = nil) {
        childLock.lock()
        let pending = childId.map { unsentAnswers[$0] != nil ? [$0] : [] } ?? Array(unsentAnswers.keys)
        childLock.unlock()
        guard !pending.isEmpty else { return }
        Task { [self] in
            for childId in pending {
                childLock.lock()
                // Revalidated at each step: a parent that ended or a shutdown while an earlier send was suspended has
                // already dropped the entry (or stopped the profile), and its answer must not go out now.
                guard !stopped, timerGeneration == nil || timerGeneration == resumeGeneration,
                      let answer = unsentAnswers.removeValue(forKey: childId) else { childLock.unlock(); continue }
                replaying[childId] = answer.parent
                let claimedAt = resumeGeneration
                childLock.unlock()
                let sent = (try? await peer?.notify(method: answer.method, params: answer.params)) != nil
                childLock.lock()
                replaying.removeValue(forKey: childId)
                // The cancellation marker of a replaying child lives until its send finishes, independently of the
                // bounded ended-flow list (which later events can evict).
                // Removed unconditionally (then tested), so a cancelled replay never leaves its marker behind.
                let wasCancelled = cancelledChildren.remove(childId) != nil
                let ended = stopped || endedParents.contains(answer.parent) || endedParents.contains(childId) || wasCancelled
                if sent || ended { retryAttempts.removeValue(forKey: childId) }
                if sent { rememberCompletedLocked(childId) }
                if !sent, !ended { unsentAnswers[childId] = answer }
                // A resume that happened while this send was suspended found the answer claimed and could not send it.
                let resumedMeanwhile = !sent && !ended && resumeGeneration != claimedAt
                childLock.unlock()
                if sent || ended { peer?.releaseFlow(flowId: childId) }
                if resumedMeanwhile { drainUnsent(only: childId) } else if !sent, !ended { scheduleRetry(childId) }
            }
        }
    }

    /// The answer could not be sent: keep it for the resume (unless the flow ended or the profile stopped meanwhile).
    private func keepUnsent(_ childId: String, method: String, params: [String: AnyCodable], parent: String, token: UUID, sendStartedAt generation: Int) {
        childLock.lock()
        let ended = stopped || endedParents.contains(parent) || endedParents.contains(childId) || cancelledChildren.contains(childId)
        if !ended { unsentAnswers[childId] = (method, params, parent) }
        // The owning task and its cancellation state go in the SAME critical section that queues the answer: a replay
        // can claim the answer only after this lock is released, and then finds neither a task nor a stale marker
        // that this execution would clear after a cancel marked the replay.
        if let entry = childTasks[childId], entry.token == token {
            childTasks.removeValue(forKey: childId)
            cancelledChildren.remove(childId)
        } else if childTasks[childId] == nil {
            cancelledChildren.remove(childId)
        }
        // A resume that happened while this send was suspended has already drained an empty queue: retry now.
        let resumedMeanwhile = !ended && resumeGeneration != generation
        childLock.unlock()
        if ended { peer?.releaseFlow(flowId: childId) }
        if resumedMeanwhile { drainUnsent(only: childId) } else if !ended { scheduleRetry(childId) }
    }

    /// A failed send brings no resume event when the connection itself is healthy (a failed POST on a live stream):
    /// the queue is drained again after a bounded backoff. Cancellation and duplicate suppression are the queue's own.
    ///
    /// The budget belongs to the ANSWER (`childId`): one that used its retries up cannot starve the next, and neither a
    /// cancellation nor another child's success changes it. It is cleared when the answer is sent or ends, and by a resume.
    private func scheduleRetry(_ childId: String) {
        childLock.lock()
        let used = retryAttempts[childId] ?? 0
        guard !stopped, unsentAnswers[childId] != nil, used < config.sendRetryDelaysMs.count else { childLock.unlock(); return }
        let delay = config.sendRetryDelaysMs[used]
        retryAttempts[childId] = used + 1
        let scheduledAt = resumeGeneration
        childLock.unlock()
        Task { [self] in
            try? await Task.sleep(nanoseconds: UInt64(max(delay, 0)) * 1_000_000)
            drainUnsent(only: childId, onlyIfGeneration: scheduledAt)
        }
    }

    /// Pending cancellation markers (for tests: they must not accumulate).
    var cancellationMarkerCount: Int { childLock.lock(); defer { childLock.unlock() }; return cancelledChildren.count }

    /// Whether this child was cancelled, or the profile shut down, before its handler was entered. Forgets it if so.
    private func endedBeforeStart(_ childId: String, _ token: UUID) -> Bool {
        childLock.lock(); defer { childLock.unlock() }
        guard stopped || cancelledChildren.contains(childId) else { return false }
        if childTasks[childId]?.token == token || childTasks[childId] == nil {
            childTasks.removeValue(forKey: childId)
            cancelledChildren.remove(childId)
        }
        return true
    }

    /// Whether this child may still answer.
    private func mayAnswer(_ childId: String) -> Bool {
        childLock.lock(); defer { childLock.unlock() }
        return !cancelledChildren.contains(childId)
    }

    /// Forgets the child, but only the execution that owns the tracking entry may (a direct run owns none).
    ///
    /// - Parameter completed: the terminal answer went out. That is recorded in the same critical section as the
    ///   removal, so no redelivered start can slip between the two and run the handler again.
    private func forgetChild(_ childId: String, _ token: UUID, completed: Bool = false) {
        childLock.lock(); defer { childLock.unlock() }
        if completed { rememberCompletedLocked(childId) }
        guard let entry = childTasks[childId] else { cancelledChildren.remove(childId); return }
        guard entry.token == token else { return }
        childTasks.removeValue(forKey: childId)
        cancelledChildren.remove(childId)
    }

    private struct ChildFlowFailure: Error, WmpErrorCodeProviding {
        let code: String
        var wmpErrorCode: String? { code }
    }

    public func handleProgress(params: FlowProgressParams) async {
        let flowId = params.flowId
        let step = params.step
        let payload = params.payload

        // Signing and matching arrive as child flows (`startFlow`), not as progress. Trust is the one progress the
        // wallet answers, and only when the engine marks it: issuer trust is `evaluating_trust`, verifier trust
        // `evaluating_verifier_trust`, and both also send informational progress under the same step, which must
        // not be answered (an early answer could satisfy the engine's later wait).
        if wantsTrustAnswer(payload), step == VCIStep.evaluatingTrust || step == VPStep.evaluatingVerifierTrust {
            await handleTrustEvaluation(flowId: flowId, payload: payload)
        } else {
            await config.onProgress?(flowId, step, payload)
        }
    }

    public func handleAction(params: FlowActionParams) async throws -> FlowActionResult {
        return FlowActionResult(flowId: params.flowId, accepted: true)
    }

    /// Cancels the child flows that belong to `flowId` (or are `flowId`): a flow that has ended gets no more
    /// answers from handlers still suspended for it. True when `flowId` itself is a child flow.
    @discardableResult
    private func cancelChildren(of flowId: String) -> Bool {
        childLock.lock()
        var running: [Task<Void, Never>] = []
        var ids: [String] = []
        // A child whose answer is queued for the resume is still a child, though it no longer has a task.
        let wasChild = childTasks[flowId] != nil || unsentAnswers[flowId] != nil || replaying[flowId] != nil
            || completedChildren.contains(flowId)
        endedParents.append(flowId)
        if endedParents.count > maxEndedParents { endedParents.removeFirst(endedParents.count - maxEndedParents) }
        for (childId, answer) in unsentAnswers where childId == flowId || answer.parent == flowId {
            unsentAnswers.removeValue(forKey: childId)
            retryAttempts.removeValue(forKey: childId)
            ids.append(childId)
        }
        // A child whose answer a replay has claimed and is sending: marked, so a failing send is not requeued, and its
        // route is released with the rest.
        for (childId, parent) in replaying where childId == flowId || parent == flowId {
            cancelledChildren.insert(childId)
            ids.append(childId)
        }
        for (childId, child) in childTasks where childId == flowId || child.parent == flowId {
            cancelledChildren.insert(childId)
            running.append(child.task)
            ids.append(childId)
        }
        childLock.unlock()
        for task in running { task.cancel() }
        // The peer forgets only the flow that ended; its children are released here, without waiting for a
        // suspended handler to return (which may be never).
        for id in ids { peer?.releaseFlow(flowId: id) }
        return wasChild
    }

    public func cancelLocally(flowId: String) {
        cancelChildren(of: flowId)
    }

    public func shutdown() {
        childLock.lock()
        // Once: a session is shut down by its teardown, its close and its terminal hook, and the application's
        // callback must not run again after a replacement session has begun.
        guard !stopped else { childLock.unlock(); return }
        stopped = true
        // Children whose answers were queued have no task left to find: their routing entries are released too.
        var running: [Task<Void, Never>] = []
        var ids: [String] = Array(unsentAnswers.keys) + Array(replaying.keys)
        unsentAnswers.removeAll()
        for (childId, child) in childTasks {
            cancelledChildren.insert(childId)
            running.append(child.task)
            ids.append(childId)
        }
        childLock.unlock()
        for task in running { task.cancel() }
        for id in ids { peer?.releaseFlow(flowId: id) }
        // The application hears of it last, once no child can start or answer: what it holds for these flows
        // (keys, opened responses) goes with them.
        config.onShutdown?()
    }

    public func handleComplete(params: FlowCompleteParams) async {
        childLock.lock(); parentFlowTypes.removeValue(forKey: params.flowId); childLock.unlock()
        cancelChildren(of: params.flowId)
        await config.onComplete?(params.flowId, params.result)
    }

    public func handleError(params: FlowErrorParams) async {
        childLock.lock(); parentFlowTypes.removeValue(forKey: params.flowId); childLock.unlock()
        cancelChildren(of: params.flowId)
        await config.onError?(params.flowId, params.code, params.message)
    }

    public func handleCancel(params: FlowCancelParams) async {
        // A cancelled child answers nothing, even if its handler ignores the cancellation. Cancelling a child
        // stops that operation; only a flow of its own is cleaned up by the wallet.
        let wasChild = cancelChildren(of: params.flowId)
        childLock.lock(); let flowType = parentFlowTypes.removeValue(forKey: params.flowId); childLock.unlock()
        if !wasChild { await config.onCancel?(params.flowId, flowType) }
    }

    // MARK: - Sub-flow Handlers

    private func wantsTrustAnswer(_ payload: AnyCodable?) -> Bool {
        guard case .object_(let members)? = payload, case .bool(true)? = members[trustEvaluationRequired] else { return false }
        return true
    }

    private func handleTrustEvaluation(flowId: String, payload: AnyCodable?) async {
        guard let handler = config.onTrustEvaluation else { return }

        do {
            let result = try await handler(flowId, payload)
            await sendTrustResult(flowId: flowId, result: result)
        } catch {
            await sendTrustResult(flowId: flowId, result: TrustResult(trusted: false, reason: error.localizedDescription))
        }
    }

    // MARK: - Response Helpers

    /// The members of a sign answer, under the names the legacy `sign_response` uses, so one backend path
    /// reads them whichever route they arrive on.
    private func signResponseMembers(_ result: SignSubFlowResult) -> [String: AnyCodable] {
        var params: [String: AnyCodable] = [:]
        if let proofs = result.proofs {
            let encoded = proofs.map { proof -> [String: AnyCodable] in
                var dict: [String: AnyCodable] = ["proof_type": .string(proof.proofType)]
                if let jwt = proof.jwt { dict["jwt"] = .string(jwt) }
                // Key-attestation proofs carry their payload here, not in
                // `jwt`; the legacy transport's Codable encoding includes it
                // and this hand-rolled one must too, or an `attestation`
                // proof arrives at the backend with no proof in it.
                if let attestation = proof.attestation { dict["attestation"] = .string(attestation) }
                return dict
            }
            params["proofs"] = .array(encoded.map { .object_($0) })
        }
        if let vpToken = result.vpToken {
            params["vp_token"] = .string(vpToken)
        }
        if let extras = result.credentialRequestExtras {
            params["credential_request_extras"] = .object_(extras)
        }
        if let wia = result.clientAttestation { params["client_attestation"] = .string(wia) }
        if let pop = result.clientAttestationPoP { params["client_attestation_pop"] = .string(pop) }
        if let keyId = result.dpopKeyId { params["dpop_key_id"] = .string(keyId) }
        if let proof = result.dpopProof { params["dpop_proof"] = .string(proof) }
        if let jwk = result.credentialResponseEncryptionJwk {
            params["credential_response_encryption_jwk"] = .object_(jwk.mapValues { .string($0) })
        }
        if let count = result.credentialCount { params["credential_count"] = .int(count) }
        if let transactionId = result.transactionId { params["transaction_id"] = .string(transactionId) }
        if let interval = result.interval { params["interval"] = .int(interval) }
        return params
    }

    private func matchResponseMembers(_ result: MatchResult) -> [String: AnyCodable] {
        let matchArray = result.matches.map { match -> [String: AnyCodable] in
            var dict: [String: AnyCodable] = [
                "credential_id": .string(match.credentialId),
                "format": .string(match.format),
            ]
            if let qid = match.credentialQueryId { dict["credential_query_id"] = .string(qid) }
            if let vct = match.vct { dict["vct"] = .string(vct) }
            if let claims = match.availableClaims { dict["available_claims"] = .array(claims.map { .string($0) }) }
            return dict
        }
        var params: [String: AnyCodable] = ["matches": .array(matchArray.map { AnyCodable.object_($0) })]
        // Without this an empty match set arrives as a bare "nothing matched"
        // and the reason - the only thing that can tell the user *which*
        // credential they are missing - is lost on this transport.
        if let reason = result.noMatchReason { params["no_match_reason"] = .string(reason) }
        return params
    }

    private func sendTrustResult(flowId: String, result: TrustResult) async {
        guard let peer else { return }
        // go-wmp reads the action's members under `params`, not next to `action`.
        var members: [String: AnyCodable] = ["trusted": .bool(result.trusted)]
        if let framework = result.framework { members["framework"] = .string(framework) }
        if let reason = result.reason { members["reason"] = .string(reason) }
        try? await peer.notify(method: WmpMethods.flowAction, params: [
            "flow_id": .string(flowId), "action": .string("trust_result"), "params": .object_(members),
        ])
    }
}
