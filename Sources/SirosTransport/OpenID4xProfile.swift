// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// MARK: - Flow Type Constants

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

    enum CodingKeys: String, CodingKey {
        case action, nonce, audience, count, issuer, htm, htu, ath
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
        keyId: String? = nil
    ) {
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

    public init(
        proofs: [ProofObject]? = nil,
        vpToken: String? = nil,
        credentialRequestExtras: [String: AnyCodable]? = nil,
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil,
        dpopKeyId: String? = nil,
        dpopProof: String? = nil
    ) {
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
    public var attestationProvider: ClientAttestationProvider?

    public init(
        onProgress: ((String, String, AnyCodable?) async -> Void)? = nil,
        onSignRequest: ((String, SignSubFlowParams) async throws -> SignSubFlowResult)? = nil,
        onMatchRequest: ((String, AnyCodable?) async throws -> MatchResult)? = nil,
        onTrustEvaluation: ((String, AnyCodable?) async throws -> TrustResult)? = nil,
        onComplete: ((String, AnyCodable?) async -> Void)? = nil,
        onError: ((String, String?, String?) async -> Void)? = nil,
        attestationProvider: ClientAttestationProvider? = nil
    ) {
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

private let stepSignRequest = "sign_request"
private let stepMatchRequest = "match_request"
private let stepTrustEvaluation = "trust_evaluation_required"

/// OpenID4x WMP profile for OID4VCI and OID4VP flows.
///
/// Handles server-initiated flows: the backend engine starts flows and
/// the SDK responds to progress events, sign requests, match requests,
/// and trust evaluations.
public final class OpenID4xProfile: WmpProfile, WmpFlowHandler, @unchecked Sendable {
    public let name: String = "openid4x"
    public let capabilities: [String] = ["oid4vci", "oid4vp"]
    public let flowTypes: [String] = [OID4FlowTypes.oid4vci, OID4FlowTypes.oid4vp]

    private let config: OpenID4xConfig
    private weak var peer: WmpPeerContext?

    public init(config: OpenID4xConfig = OpenID4xConfig()) {
        self.config = config
    }

    // MARK: - WmpProfile

    public func initialize(ctx: WmpPeerContext) {
        peer = ctx
    }

    // MARK: - WmpFlowHandler

    public func startFlow(params: FlowStartParams) async throws -> FlowStartResult {
        return FlowStartResult(flowId: params.flowId, flowType: params.flowType)
    }

    public func handleProgress(params: FlowProgressParams) async {
        let flowId = params.flowId
        let step = params.step
        let payload = params.payload

        switch step {
        case stepSignRequest, VCIStep.generatingProof:
            await handleSignRequest(flowId: flowId, payload: payload)
        case stepMatchRequest, VPStep.matchingCredentials:
            await handleMatchRequest(flowId: flowId, payload: payload)
        case stepTrustEvaluation, VCIStep.evaluatingTrust:
            await handleTrustEvaluation(flowId: flowId, payload: payload)
        default:
            await config.onProgress?(flowId, step, payload)
        }
    }

    public func handleAction(params: FlowActionParams) async throws -> FlowActionResult {
        return FlowActionResult(flowId: params.flowId, accepted: true)
    }

    public func handleComplete(params: FlowCompleteParams) async {
        await config.onComplete?(params.flowId, params.result)
    }

    public func handleError(params: FlowErrorParams) async {
        await config.onError?(params.flowId, params.code, params.message)
    }

    public func handleCancel(params: FlowCancelParams) async {
        // No-op for now
    }

    // MARK: - Sub-flow Handlers

    private func handleSignRequest(flowId: String, payload: AnyCodable?) async {
        guard let handler = config.onSignRequest else { return }

        guard let payload else {
            await sendFlowError(flowId: flowId, code: "INVALID_PARAMS", message: "sign_request missing payload")
            return
        }
        let signParams: SignSubFlowParams
        do {
            let data = try JSONEncoder().encode(payload)
            signParams = try JSONDecoder().decode(SignSubFlowParams.self, from: data)
        } catch {
            await sendFlowError(flowId: flowId, code: "INVALID_PARAMS", message: "sign_request payload decode failed: \(error.localizedDescription)")
            return
        }

        do {
            let result = try await handler(flowId, signParams)
            await sendSignResponse(flowId: flowId, result: result)
        } catch {
            // An error that names its code is reported with that code and nothing
            // else: no developer text goes to the peer.
            if let code = (error as? WmpErrorCodeProviding)?.wmpErrorCode {
                await sendFlowError(flowId: flowId, code: code, message: code)
            } else {
                await sendFlowError(flowId: flowId, code: "SIGN_ERROR", message: error.localizedDescription)
            }
        }
    }

    private func handleMatchRequest(flowId: String, payload: AnyCodable?) async {
        guard let handler = config.onMatchRequest else { return }

        do {
            let result = try await handler(flowId, payload)
            await sendMatchResponse(flowId: flowId, result: result)
        } catch {
            await sendFlowError(flowId: flowId, code: "MATCH_ERROR", message: error.localizedDescription)
        }
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

    private func sendSignResponse(flowId: String, result: SignSubFlowResult) async {
        guard let peer else { return }
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "action": .string("sign_response"),
        ]
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
        try? await peer.notify(method: WmpMethods.flowAction, params: params)
    }

    private func sendMatchResponse(flowId: String, result: MatchResult) async {
        guard let peer else { return }
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
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "action": .string("match_response"),
            "matches": .array(matchArray.map { AnyCodable.object_($0) }),
        ]
        // Without this an empty match set arrives as a bare "nothing matched"
        // and the reason - the only thing that can tell the user *which*
        // credential they are missing - is lost on this transport.
        if let reason = result.noMatchReason { params["no_match_reason"] = .string(reason) }
        try? await peer.notify(method: WmpMethods.flowAction, params: params)
    }

    private func sendTrustResult(flowId: String, result: TrustResult) async {
        guard let peer else { return }
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "action": .string("trust_result"),
            "trusted": .bool(result.trusted),
        ]
        if let framework = result.framework { params["framework"] = .string(framework) }
        if let reason = result.reason { params["reason"] = .string(reason) }
        try? await peer.notify(method: WmpMethods.flowAction, params: params)
    }

    private func sendFlowError(flowId: String, code: String, message: String?) async {
        guard let peer else { return }
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "code": .string(code),
        ]
        if let message { params["message"] = .string(message) }
        try? await peer.notify(method: WmpMethods.flowError, params: params)
    }
}
