// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One OID4VCI `authorization_details` entry (1.0 §5.1.1).
///
/// Only the `credential_configuration_id` form is carried: DIIP requires that
/// one, and it is what the `format`-based alternative was replaced by.
///
/// Declared here rather than in `SirosCredentials/Interop`, where the rest of
/// the interop types live, because `FlowStartMessage` carries it and this
/// module deliberately has no dependencies of its own. The *policy* for when
/// to send it is still in `Interop`, as `AuthorizationDetails.build`.
public struct AuthorizationDetail: Codable, Sendable, Equatable {
    public let type: String
    public let credentialConfigurationID: String

    public init(type: String = "openid_credential", credentialConfigurationID: String) {
        self.type = type
        self.credentialConfigurationID = credentialConfigurationID
    }

    enum CodingKeys: String, CodingKey {
        case type
        case credentialConfigurationID = "credential_configuration_id"
    }
}

/// Message types used in the wallet backend engine WebSocket protocol.
public enum MessageTypes {
    // Client → Server
    public static let handshake = "handshake"
    public static let flowStart = "flow_start"
    public static let flowAction = "flow_action"
    public static let signResponse = "sign_response"
    public static let matchResponse = "match_response"
    /// OID4VCI §10 credential lifecycle notification reported to the backend
    /// for forwarding to the issuer.
    public static let credentialNotification = "credential_notification"

    // Server → Client
    public static let handshakeComplete = "handshake_complete"
    public static let flowProgress = "flow_progress"
    public static let flowComplete = "flow_complete"
    public static let flowError = "flow_error"
    public static let signRequest = "sign_request"
    public static let matchRequest = "match_request"
    public static let push = "push"
    public static let error = "error"
    /// Acknowledgement of a credential_notification from the backend.
    public static let notificationAck = "notification_ack"
}

/// Error codes carried in a `flow_error` message's `error.code`. Only the ones
/// this SDK reacts to are named here; every other code is surfaced to the app
/// verbatim.
public enum EngineErrorCodes {
    /// The wallet reported an empty match set for the verifier's query, so the
    /// engine ended the flow rather than waiting for a consent that could
    /// never come. `error.details` carries `requested_types` (the credential
    /// types the DCQL query asked for) and the wallet's own `no_match_reason`.
    public static let noMatchingCredential = "NO_MATCHING_CREDENTIAL"
    /// An action or sign response named a flow the engine does not know (finished,
    /// or from an earlier socket). Not a reply to a `flow_start`.
    public static let unknownFlow = "UNKNOWN_FLOW"
    /// The engine's action or sign channel was full. Not a reply to a `flow_start`.
    public static let tooManyRequests = "TOO_MANY_REQUESTS"
}

/// Base envelope — every engine message carries at least a type.
public struct EngineMessage: Codable, Sendable, Equatable {
    public var type: String
    public var flowId: String?
    public var messageId: String?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, timestamp
        case flowId = "flow_id"
        case messageId = "message_id"
    }
}

// MARK: - Client → Server

public struct HandshakeMessage: Codable, Sendable {
    public var type: String
    public var appToken: String

    public init(type: String = MessageTypes.handshake, appToken: String) {
        self.type = type
        self.appToken = appToken
    }

    enum CodingKeys: String, CodingKey {
        case type
        case appToken = "app_token"
    }
}

public struct FlowStartMessage: Codable, Sendable {
    public var type: String
    public var `protocol`: String
    public var offer: String?
    public var credentialOfferUri: String?
    public var requestUri: String?
    public var requestUriRef: String?
    public var vct: String?
    public var redirectUri: String?
    public var authCode: String?
    public var codeVerifier: String?
    /// OAuth Client Attestation (draft-ietf-oauth-attestation-based-client-auth-04
    /// §3.1): a Wallet Instance Attestation JWT (`typ: oauth-client-attestation+jwt`)
    /// obtained from this wallet's own backend (`/wallet-provider/wia/generate`).
    /// Forwarded by go-wallet-backend as the `OAuth-Client-Attestation` HTTP
    /// header on PAR/token requests to the credential issuer.
    ///
    /// Supplying it here is the legacy, client-discovers-everything path and
    /// is deprecated on `WalletEngineSession`: when absent, the engine asks
    /// for it with a `request_attestation` sign request once it knows the
    /// issuer's authorization server (`SignResponseMessage.clientAttestation`).
    public var clientAttestation: String?
    /// The matching PoP JWT (`typ: oauth-client-attestation-pop+jwt`), freshly
    /// signed per flow with `aud` = the credential issuer's own authorization
    /// server, proving possession of the instance key the WIA above is bound
    /// to (`cnf.jwk`/`cnf.jkt`). Forwarded as `OAuth-Client-Attestation-PoP`.
    public var clientAttestationPoP: String?
    /// Renewal fields (credential re-issuance/renewal plan, Phase 1 Slice 2
    /// - see go-wallet-backend's `internal/engine/oid4vci.go` `Execute`).
    /// When `refreshToken` is set, this is a renewal request rather than a
    /// fresh issuance: `offer`/`credentialOfferUri` are unused, and
    /// `credentialIssuer`/`selectedCredentialConfigurationId` are required
    /// instead (the client already knows both from the credential being
    /// renewed).
    public var refreshToken: String?
    public var credentialIssuer: String?
    public var selectedCredentialConfigurationId: String?
    /// When set, asks the server to request a `generate_proof` signature
    /// using this existing kid instead of a fresh one - same-wallet-unit
    /// continuity evidence for a renewal. Optional even on a renewal
    /// request.
    public var reissuanceKid: String?
    /// On a renewal request, the private DPoP JWK previously captured from
    /// `FlowCompleteMessage.dpopJwk` for this same refresh_token. The
    /// issuer's refresh_token grant binds the token to the exact DPoP key
    /// used at initial issuance (RFC 9449/ARF ISSU_65 §6.6.6.2.2), so the
    /// backend must reuse this key rather than generate a fresh one. Never
    /// persisted by the SDK itself beyond whatever the caller does with it
    /// (privatedata, Phase 2).
    public var dpopJwk: String?
    /// On a renewal request, the `dpop_key_id` this wallet returned at
    /// `FlowCompleteMessage.dpopKeyId` for this same refresh_token: the
    /// client-held key the token is bound to (go-wallet-backend#317). The
    /// engine passes it back as `SignRequestParams.keyId` on every
    /// `sign_client_auth` of the renewal so this wallet signs with that same
    /// key. Takes precedence over `dpopJwk`.
    public var dpopKeyId: String?
    /// Optional protocol features this client supports for this flow, e.g.
    /// `["transaction_data.v1"]` (EC TS12 payment SCA). Omitted entirely
    /// unless non-empty: the backend refuses `transaction_data` for a client
    /// that did not declare support.
    public var features: [String]?
    public var timestamp: String?
    /// OID4VCI `authorization_details` for the Authorization Request. DIIP
    /// requires a Wallet to be able to ask for a credential configuration this
    /// way as well as by `scope`.
    ///
    /// The engine builds the Authorization Request, so the wallet cannot add
    /// the parameter itself - it states the intent here and the engine
    /// forwards it. Nil omits the field entirely, which the engine reads as
    /// "do not ask this way", leaving the `scope` path unchanged. Wire name
    /// and shape match go-wallet-backend's
    /// `FlowStartMessage.AuthorizationDetails` and wallet-frontend's
    /// `flow_start` exactly.
    ///
    /// Appended after every pre-existing field, `timestamp` included - this
    /// type is `public`, and a parameter inserted before an existing one
    /// shifts every positional argument after it for any external caller
    /// that constructs this message listing its existing arguments in
    /// declaration order without yet naming this new one (review finding).
    public var authorizationDetails: [AuthorizationDetail]?

    public init(
        type: String = MessageTypes.flowStart,
        protocol: String,
        offer: String? = nil,
        credentialOfferUri: String? = nil,
        requestUri: String? = nil,
        requestUriRef: String? = nil,
        vct: String? = nil,
        redirectUri: String? = nil,
        authCode: String? = nil,
        codeVerifier: String? = nil,
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil,
        refreshToken: String? = nil,
        credentialIssuer: String? = nil,
        selectedCredentialConfigurationId: String? = nil,
        reissuanceKid: String? = nil,
        dpopJwk: String? = nil,
        dpopKeyId: String? = nil,
        timestamp: String? = nil,
        authorizationDetails: [AuthorizationDetail]? = nil,
        features: [String]? = nil
    ) {
        self.type = type
        self.protocol = `protocol`
        self.offer = offer
        self.credentialOfferUri = credentialOfferUri
        self.requestUri = requestUri
        self.requestUriRef = requestUriRef
        self.vct = vct
        self.redirectUri = redirectUri
        self.authCode = authCode
        self.codeVerifier = codeVerifier
        self.clientAttestation = clientAttestation
        self.clientAttestationPoP = clientAttestationPoP
        self.refreshToken = refreshToken
        self.credentialIssuer = credentialIssuer
        self.selectedCredentialConfigurationId = selectedCredentialConfigurationId
        self.reissuanceKid = reissuanceKid
        self.dpopJwk = dpopJwk
        self.dpopKeyId = dpopKeyId
        self.authorizationDetails = authorizationDetails
        self.features = (features?.isEmpty ?? true) ? nil : features
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, `protocol`, offer, vct, timestamp
        case features
        case credentialOfferUri = "credential_offer_uri"
        case requestUri = "request_uri"
        case requestUriRef = "request_uri_ref"
        case redirectUri = "redirect_uri"
        case authCode = "auth_code"
        case codeVerifier = "code_verifier"
        case clientAttestation = "client_attestation"
        case clientAttestationPoP = "client_attestation_pop"
        case refreshToken = "refresh_token"
        case credentialIssuer = "credential_issuer"
        case selectedCredentialConfigurationId = "selected_credential_configuration_id"
        case reissuanceKid = "reissuance_kid"
        case authorizationDetails = "authorization_details"
        case dpopJwk = "dpop_jwk"
        case dpopKeyId = "dpop_key_id"
    }
}

public struct FlowActionMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var action: String
    public var payload: [String: AnyCodable]?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.flowAction,
        flowId: String,
        action: String,
        payload: [String: AnyCodable]? = nil,
        timestamp: String? = nil
    ) {
        self.type = type
        self.flowId = flowId
        self.action = action
        self.payload = payload
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, action, payload, timestamp
        case flowId = "flow_id"
    }
}

public struct SignResponseMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var messageId: String?
    public var proofJwt: String?
    public var vpToken: String?
    public var proofs: [ProofObject]?
    /// Extra members for the OID4VCI credential request the backend is
    /// about to send on this wallet's behalf.
    ///
    /// The wallet, not the backend, holds the state some credential formats
    /// need at issuance: blind BBS requires a commitment the holder computed
    /// locally, and the issuer will not sign without it. The backend builds
    /// the credential request, so that value has to travel here.
    ///
    /// Deliberately a generic bag rather than named BBS fields. It mirrors
    /// `ZkIssuancePreparation.credentialRequestFields`, so a future proof
    /// system needing its own request members costs a registry entry rather
    /// than another protocol change - the same argument as
    /// privatedata-spec's `S.extensions`.
    ///
    /// The backend MUST refuse members that collide with ones it sets
    /// itself (`credential_configuration_id`, `proofs`,
    /// `credential_response_encryption`). A wallet cannot be allowed to
    /// redirect or reshape the request through this field.
    ///
    /// Absent on every flow that does not need it, which is all of them
    /// today except blind BBS issuance.
    public var credentialRequestExtras: [String: AnyCodable]?
    /// Response to a `request_attestation` sign request (go-wallet-backend's
    /// `SignActionRequestAttestation`): the Wallet Instance Attestation JWT
    /// (`typ: oauth-client-attestation+jwt`) and the per-flow PoP JWT
    /// (`typ: oauth-client-attestation-pop+jwt`) the client signed with its
    /// instance key, with `aud`/`iss` taken from the request's
    /// `SignRequestParams.audience`/`.issuer`. Both nil means the client has
    /// no attestation to offer - the engine then proceeds without wallet
    /// attestation rather than waiting for one.
    public var clientAttestation: String?
    public var clientAttestationPoP: String?
    /// Response to a `sign_client_auth` sign request (go-wallet-backend#317):
    /// `dpopKeyId` is this wallet's identifier for the key that is both its
    /// WIA `cnf` key and its DPoP key, set whenever the action is understood
    /// even when no proof was asked for (its absence tells the engine to fall
    /// back to an engine-held DPoP key). `dpopProof` is the RFC 9449 DPoP
    /// proof when `htm`/`htu` were given; the attestation fields above carry
    /// the WIA and a freshly signed PoP when `audience` was given.
    public var dpopKeyId: String?
    public var dpopProof: String?
    /// Answer to `generate_proof` when the engine sent `credential_response_encryption`: the
    /// PUBLIC JWK (`kty` EC, `crv` P-256, `x`, `y`, `use` enc, `alg`) of a key the wallet
    /// generated for this proof request, so the issuer's response is encrypted to a key only the
    /// wallet holds. Absent means declined.
    public var credentialResponseEncryptionJwk: [String: String]?
    /// Answer to `decrypt_credential_response`: ONLY the control fields of the decrypted
    /// response. The credentials, `credential_metadata` and `notification_id` stay in the wallet.
    /// `decrypt_credential_response` answers exactly ONE of: `credentialCount` (credentials were
    /// issued, 1 to 256), `transactionId` with `interval` (deferred), or `error`.
    public var credentialCount: Int?
    public var transactionId: String?
    public var interval: Int?
    /// Set when the wallet could not do what the request asked (for example a response it could
    /// not decrypt). `errorCode` is a short machine-readable code; neither carries any plaintext.
    public var error: String?
    public var errorCode: String?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.signResponse,
        flowId: String,
        messageId: String? = nil,
        proofJwt: String? = nil,
        vpToken: String? = nil,
        proofs: [ProofObject]? = nil,
        credentialRequestExtras: [String: AnyCodable]? = nil,
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil,
        dpopKeyId: String? = nil,
        dpopProof: String? = nil,
        credentialResponseEncryptionJwk: [String: String]? = nil,
        credentialCount: Int? = nil,
        transactionId: String? = nil,
        interval: Int? = nil,
        error: String? = nil,
        errorCode: String? = nil,
        timestamp: String? = nil
    ) {
        self.credentialCount = credentialCount
        self.type = type
        self.flowId = flowId
        self.messageId = messageId
        self.proofJwt = proofJwt
        self.vpToken = vpToken
        self.proofs = proofs
        self.credentialRequestExtras = credentialRequestExtras
        self.clientAttestation = clientAttestation
        self.clientAttestationPoP = clientAttestationPoP
        self.dpopKeyId = dpopKeyId
        self.dpopProof = dpopProof
        self.credentialResponseEncryptionJwk = credentialResponseEncryptionJwk
        self.transactionId = transactionId
        self.interval = interval
        self.error = error
        self.errorCode = errorCode
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, proofs, timestamp, interval, error
        case transactionId = "transaction_id"
        case credentialCount = "credential_count"
        case errorCode = "error_code"
        case credentialResponseEncryptionJwk = "credential_response_encryption_jwk"
        case flowId = "flow_id"
        case messageId = "message_id"
        case proofJwt = "proof_jwt"
        case vpToken = "vp_token"
        case credentialRequestExtras = "credential_request_extras"
        case clientAttestation = "client_attestation"
        case clientAttestationPoP = "client_attestation_pop"
        case dpopKeyId = "dpop_key_id"
        case dpopProof = "dpop_proof"
    }
}

public struct ProofObject: Codable, Sendable {
    public var proofType: String
    public var jwt: String?
    public var attestation: String?

    public init(proofType: String, jwt: String? = nil, attestation: String? = nil) {
        self.proofType = proofType
        self.jwt = jwt
        self.attestation = attestation
    }

    enum CodingKeys: String, CodingKey {
        case jwt, attestation
        case proofType = "proof_type"
    }
}

public struct MatchResponseMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var matches: [CredentialMatch]
    public var noMatchReason: String?
    public var error: String?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.matchResponse,
        flowId: String,
        matches: [CredentialMatch],
        noMatchReason: String? = nil,
        error: String? = nil,
        timestamp: String? = nil
    ) {
        self.type = type
        self.flowId = flowId
        self.matches = matches
        self.noMatchReason = noMatchReason
        self.error = error
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, matches, error, timestamp
        case flowId = "flow_id"
        case noMatchReason = "no_match_reason"
    }
}

public struct CredentialMatch: Codable, Sendable {
    public var credentialQueryId: String?
    public var credentialId: String
    public var format: String
    public var vct: String?
    public var availableClaims: [String]?

    public init(
        credentialQueryId: String? = nil,
        credentialId: String,
        format: String,
        vct: String? = nil,
        availableClaims: [String]? = nil
    ) {
        self.credentialQueryId = credentialQueryId
        self.credentialId = credentialId
        self.format = format
        self.vct = vct
        self.availableClaims = availableClaims
    }

    enum CodingKeys: String, CodingKey {
        case format, vct
        case credentialQueryId = "credential_query_id"
        case credentialId = "credential_id"
        case availableClaims = "available_claims"
    }
}

// MARK: - Server → Client

public struct HandshakeCompleteMessage: Codable, Sendable {
    public var type: String
    public var sessionId: String
    public var capabilities: [String]?
    public var timestamp: String?
    /// Server-controlled tunables this client should adopt - see
    /// ``SessionConfig``'s own doc comment. Optional so this decodes cleanly
    /// against an older server that predates this field entirely, not just
    /// one that sends it empty.
    public var config: SessionConfig?

    enum CodingKeys: String, CodingKey {
        case type, capabilities, timestamp, config
        case sessionId = "session_id"
    }
}

/// Server-controlled tunables delivered via ``HandshakeCompleteMessage``
/// right after authentication succeeds. Deliberately the seed of a general
/// post-auth config/capability handshake rather than a one-off field:
/// anywhere the client would otherwise have to hardcode a value that only
/// works if it happens to match what the server independently assumes, that
/// value belongs here instead - `pingIntervalMs` is just the first case (see
/// its own doc comment for why it specifically had to stop being
/// independently guessed by each side). Add new fields as optional so an
/// older client ignores fields it doesn't understand yet, and a client
/// talking to an older server that never sends a given field falls back to
/// its own hardcoded default.
public struct SessionConfig: Codable, Sendable {
    /// How often THIS client should send its own WebSocket ping frames, in
    /// milliseconds - mirrors the server's own keepalive cadence
    /// (go-wallet-backend's `config.ServerConfig.EngineWSPingInterval`) so
    /// neither side has to independently guess a value low enough to
    /// satisfy whatever intermediary (Fly.io's edge proxy, in production -
    /// confirmed empirically to close an idle connection after ~5-6s,
    /// nowhere near the 30s this used to be hardcoded to on both sides)
    /// would otherwise consider the connection idle and close it. Nil (the
    /// server hasn't said) means: use ``WalletEngineSession``'s own
    /// hardcoded default rather than treat it as "no ping at all".
    public var pingIntervalMs: Int64?

    enum CodingKeys: String, CodingKey {
        case pingIntervalMs = "ping_interval_ms"
    }

    public init(pingIntervalMs: Int64? = nil) {
        self.pingIntervalMs = pingIntervalMs
    }
}

public struct FlowProgressMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var step: String
    public var payload: AnyCodable?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, step, payload, timestamp
        case flowId = "flow_id"
    }
}

/// What the engine reported about the issuer's trust for one issuance flow, from
/// its `trust_evaluated` progress step (`issuer_trust_evaluated: true`).
public struct IssuerTrustReport: Sendable, Equatable {
    public var issuer: String?
    public var trusted: Bool
    public var framework: String?
    public var reason: String?

    public init(issuer: String?, trusted: Bool, framework: String? = nil, reason: String? = nil) {
        self.issuer = issuer
        self.trusted = trusted
        self.framework = framework
        self.reason = reason
    }
}

public struct FlowCompleteMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var credentials: [CredentialResult]?
    public var redirectUri: String?
    public var typeMetadata: AnyCodable?
    public var credentialIssuer: String?
    public var selectedCredentialConfigurationId: String?
    /// OAuth refresh_token the issuer's token endpoint returned alongside
    /// this batch, if any (OID4VCI issuance only). Captured durably into
    /// `privatedata` (`S.credentialRefreshTokens`) by
    /// `SirosWallet+Notifications.swift`'s `handleFlowComplete` so
    /// `SirosWallet.renewCredential(batchId:)` can use it later.
    public var refreshToken: String?
    /// The private JWK of the ephemeral DPoP key this flow used for its
    /// token exchange, present only alongside `refreshToken`. Must be
    /// presented back as `FlowStartMessage.dpopJwk` on a renewal request.
    public var dpopJwk: String?
    /// Identifier of the client-held key this flow used for DPoP via
    /// `sign_client_auth` (go-wallet-backend#317), present only alongside
    /// `refreshToken` and only when this wallet signed the DPoP proofs
    /// itself (then `dpopJwk` is absent: the engine never had the key).
    /// Persisted with the refresh token and presented back as
    /// `FlowStartMessage.dpopKeyId` on renewal.
    public var dpopKeyId: String?
    /// True when the issuer's response was encrypted to this wallet's key: the entries of
    /// `credentials` then carry no `credential` value, and entry i belongs to the i-th credential
    /// the wallet decrypted for this flow (`decrypt_credential_response`).
    public var credentialResponseEncrypted: Bool?
    /// Display-only response-level `credential_metadata` of a PLAIN issuer response, when the engine
    /// relays it: only `display` and `claims`. Every other member is dropped at decoding, so an
    /// extension member such as `org.siros.secret_seed` can never arrive this way: those come only
    /// from the wallet's own decryption of an encrypted response.
    public var credentialMetadata: CredentialDisplayMetadata?
    public var timestamp: String?
    /// The engine's own issuer trust evaluation for this flow (the
    /// `trust_evaluated` progress step), attached by `WalletEngineSession`
    /// when the flow completes; nil when the engine sent none (its permissive
    /// no-PDP mode emits none). Not part of the wire message.
    public var issuerTrust: IssuerTrustReport?
    /// The tag `WalletEngineSession.startTagProvider` returned when THIS flow's
    /// `flow_start` was sent (the wallet's issuance epoch then), attached when the
    /// flow completes; nil if the flow was not started by this session or its
    /// first progress was never seen. Not part of the wire message.
    public var startTag: Int?

    enum CodingKeys: String, CodingKey {
        case type, credentials, timestamp
        case credentialMetadata = "credential_metadata"
        case credentialResponseEncrypted = "credential_response_encrypted"
        case flowId = "flow_id"
        case redirectUri = "redirect_uri"
        case typeMetadata = "type_metadata"
        case credentialIssuer = "credential_issuer"
        case selectedCredentialConfigurationId = "selected_credential_configuration_id"
        case refreshToken = "refresh_token"
        case dpopJwk = "dpop_jwk"
        case dpopKeyId = "dpop_key_id"
    }
}

/// The display-only part of a response-level `credential_metadata` object: `display` and `claims`,
/// kept as received. Decoding looks at those two members and nothing else, so no other member (a
/// delivered secret, an unknown extension) is ever held in this type, logged from it or re-encoded
/// from it. Anything that is not an object decodes to an empty value.
public struct CredentialDisplayMetadata: Codable, Sendable, Equatable {
    public var display: AnyCodable?
    public var claims: AnyCodable?

    enum CodingKeys: String, CodingKey { case display, claims }

    public init(display: AnyCodable? = nil, claims: AnyCodable? = nil) {
        self.display = display
        self.claims = claims
    }

    public init(from decoder: Decoder) throws {
        guard let container = try? decoder.container(keyedBy: CodingKeys.self) else {
            self.init()
            return
        }
        // A member of the wrong shape is ignored, not an error: display metadata must never fail a flow.
        self.init(
            display: try? container.decodeIfPresent(AnyCodable.self, forKey: .display),
            claims: try? container.decodeIfPresent(AnyCodable.self, forKey: .claims)
        )
    }
}

public struct CredentialResult: Codable, Sendable {
    public var format: String
    /// Absent when the issuer's response was encrypted to the wallet's own key
    /// (`FlowCompleteMessage.credentialResponseEncrypted`): the wallet has the credential, the
    /// engine never did.
    public var credential: String?
    public var vct: String?
    public var typeMetadata: AnyCodable?
    /// OID4VCI §10 notification identifier for this credential, if the issuer
    /// returned one. Persisted client-side and echoed back when a lifecycle
    /// event occurs.
    public var notificationId: String?

    public init(
        format: String, credential: String?, vct: String? = nil,
        typeMetadata: AnyCodable? = nil, notificationId: String? = nil
    ) {
        self.format = format
        self.credential = credential
        self.vct = vct
        self.typeMetadata = typeMetadata
        self.notificationId = notificationId
    }

    enum CodingKeys: String, CodingKey {
        case format, credential, vct
        case typeMetadata = "type_metadata"
        case notificationId = "notification_id"
    }
}

/// The engine's `credential_response_encryption` parameter of a `generate_proof` sign request:
/// the `alg`/`enc` pair it negotiated from the issuer's metadata, and whether the issuer
/// requires response encryption. The wallet answers with a public JWK for that pair (or declines).
public struct CredentialResponseEncryptionRequest: Codable, Sendable, Equatable {
    public var alg: String
    public var enc: String
    public var required: Bool?

    public init(alg: String, enc: String, required: Bool? = nil) {
        self.alg = alg
        self.enc = enc
        self.required = required
    }
}

/// Outgoing OID4VCI §10 credential lifecycle notification. The client supplies
/// the notification_id obtained at issuance; the backend supplies the issuer
/// endpoint and access token from ephemeral flow state.
public struct CredentialNotificationMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var notificationId: String
    public var event: String
    public var eventDescription: String?
    public var timestamp: String?

    public init(
        type: String = MessageTypes.credentialNotification,
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String? = nil,
        timestamp: String? = nil
    ) {
        self.type = type
        self.flowId = flowId
        self.notificationId = notificationId
        self.event = event
        self.eventDescription = eventDescription
        self.timestamp = timestamp
    }

    enum CodingKeys: String, CodingKey {
        case type, event, timestamp
        case flowId = "flow_id"
        case notificationId = "notification_id"
        case eventDescription = "event_description"
    }
}

/// Incoming acknowledgement for a credential_notification.
public struct NotificationAckMessage: Codable, Sendable {
    public var type: String
    public var flowId: String?
    public var notificationId: String?
    public var status: String
    public var error: String?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, status, error, timestamp
        case flowId = "flow_id"
        case notificationId = "notification_id"
    }
}

/// OID4VCI §10 credential lifecycle event identifiers reportable to the backend.
public enum CredentialNotificationEvent {
    public static let accepted = "credential_accepted"
    public static let failure = "credential_failure"
}

public struct FlowErrorMessage: Codable, Sendable {
    public var type: String
    public var flowId: String?
    public var step: String?
    public var error: FlowError
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, step, error, timestamp
        case flowId = "flow_id"
    }
}

public struct FlowError: Codable, Sendable {
    public var code: String
    public var message: String
    public var details: [String: AnyCodable]?
}

public struct SignRequestMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var messageId: String?
    public var action: String
    public var params: SignRequestParams
    public var timestamp: String?
    /// The engine session's socket generation when this request was received (set by the session, never on the
    /// wire). A request that was buffered across a reconnect carries the old generation, so the wallet can refuse it
    /// before it allocates anything for a flow that ran on the replaced socket.
    public var socketGeneration: Int = 0
    /// The session's request epoch when this request was received; see `WalletEngineSession.invalidateBufferedRequests()`.
    public var requestEpoch: Int = 0

    enum CodingKeys: String, CodingKey {
        case type, action, params, timestamp
        case flowId = "flow_id"
        case messageId = "message_id"
    }
}

public struct SignRequestParams: Codable, Sendable {
    public var audience: String?
    public var nonce: String?
    public var issuer: String?
    public var proofType: String?
    public var proofTypesSupported: [String: AnyCodable]?
    public var count: Int?
    public var credentialsToInclude: [CredentialRef]?
    public var responseUri: String?
    public var verifierJwkThumbprint: String?
    /// OID4VP `transaction_data` entries (EC TS12) as the engine relays them:
    /// each carries `raw`, the verifier's base64url string, which is the only
    /// valid hash input. Absent for requests without transaction data.
    /// The member with its presence kept (see `TransactionDataMember`).
    public var transactionDataMember = TransactionDataMember()
    public var transactionData: [TransactionData]? {
        get { transactionDataMember.entries }
        set { transactionDataMember = TransactionDataMember(entries: newValue) }
    }
    /// OID4VP `response_mode` of the request; echoed in the KB-JWT of an SCA
    /// presentation (TS12 section 3.6).
    public var responseMode: String?
    /// When set (a renewal's continuity proof), the client should sign the
    /// `generate_proof` response with this existing kid instead of a fresh
    /// key - see `FlowStartMessage.reissuanceKid`'s doc comment.
    public var reissuanceKid: String?
    /// The verifier-assigned session id for this specific presentation -
    /// go-wallet-backend parses this from the `request_uri`'s `?sessionId=`
    /// query parameter (the only hop that ever sees the raw request_uri) and
    /// forwards it here so a ZK/PPID proof's `verifier_context` can bind to
    /// the actual presentation SESSION, not just the verifier's static
    /// identity - see `VerifierIdentity.sessionId`'s doc comment.
    public var verifierSessionId: String?
    /// `sign_client_auth` parameters (go-wallet-backend#317). `htm` and `htu`,
    /// when set, ask for an RFC 9449 DPoP proof over that HTTP method and
    /// URL, with `dpopNonce` as the server-provided `nonce` claim and `ath`
    /// as the base64url(SHA-256(access_token)) claim for resource requests
    /// (absent at the token endpoint). `keyId`, when set (a renewal), names
    /// the key this wallet reported as `dpop_key_id` at the original issuance
    /// and must sign with again. `audience`/`issuer` double as the
    /// attestation PoP aud/iss when the same request also needs client
    /// attestation.
    public var htm: String?
    public var htu: String?
    public var dpopNonce: String?
    public var ath: String?
    public var keyId: String?
    /// `generate_proof`: the response encryption the engine negotiated, when the issuer supports it.
    public var credentialResponseEncryption: CredentialResponseEncryptionRequest?
    /// `decrypt_credential_response`: the issuer's Credential Response as a compact JWE, and whether
    /// it answers a deferred request.
    public var jwe: String?
    public var deferred: Bool?

    enum CodingKeys: String, CodingKey {
        case audience, nonce, issuer, count, htm, htu, ath, jwe, deferred
        case credentialResponseEncryption = "credential_response_encryption"
        case proofType = "proof_type"
        case proofTypesSupported = "proof_types_supported"
        case credentialsToInclude = "credentials_to_include"
        case responseUri = "response_uri"
        case verifierJwkThumbprint = "verifier_jwk_thumbprint"
        case transactionDataMember = "transaction_data"
        case responseMode = "response_mode"
        case reissuanceKid = "reissuance_kid"
        case verifierSessionId = "verifier_session_id"
        case dpopNonce = "dpop_nonce"
        case keyId = "key_id"
    }
}

public struct CredentialRef: Codable, Sendable {
    public var credentialQueryId: String?
    public var credentialId: String
    public var disclosedClaims: [String]?

    enum CodingKeys: String, CodingKey {
        case credentialId = "credential_id"
        case credentialQueryId = "credential_query_id"
        case disclosedClaims = "disclosed_claims"
    }
}

public struct MatchRequestMessage: Codable, Sendable {
    public var type: String
    public var flowId: String
    public var dcqlQuery: AnyCodable?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, timestamp
        case flowId = "flow_id"
        case dcqlQuery = "dcql_query"
    }
}

public struct PushMessage: Codable, Sendable {
    public var type: String
    public var pushType: String
    public var credentials: [CredentialResult]?
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, credentials, timestamp
        case pushType = "push_type"
    }
}

public struct ErrorMessage: Codable, Sendable {
    public var type: String
    public var code: String
    public var details: String
    public var timestamp: String?

    enum CodingKeys: String, CodingKey {
        case type, code, timestamp
        case details = "message"
    }
}
