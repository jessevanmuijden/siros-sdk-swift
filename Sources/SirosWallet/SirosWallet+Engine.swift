// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosTransport
import SirosAuth
import SirosKeystore
import SirosFlow
@preconcurrency import SwiftCBOR

#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

/// The one engine capability `SirosWallet.handleSignRequest` needs: sending a
/// `sign_response`. `WalletEngineSession` is a `final class` bound to a real
/// `URLSessionWebSocketTask`, so this seam is what lets the sign-request
/// dispatcher be unit-tested with a recording fake (see
/// `SirosWalletSignRequestTests`) without a reachable backend.
protocol SignResponseSender {
    /// Send one `sign_response`. The message carries every optional member
    /// (proof, vp_token, attestation, DPoP) so the seam has a single
    /// requirement rather than one positional parameter per member.
    func sendSignResponse(_ message: SignResponseMessage)
}

extension SignResponseSender {
    /// Keyword convenience used by the dispatcher; every member defaults to
    /// absent so a call names only what it carries.
    func sendSignResponse(
        flowId: String,
        proofJwt: String? = nil,
        vpToken: String? = nil,
        proofs: [ProofObject]? = nil,
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil,
        dpopKeyId: String? = nil,
        dpopProof: String? = nil,
        credentialResponseEncryptionJwk: [String: String]? = nil, credentialCount: Int? = nil,
        transactionId: String? = nil, interval: Int? = nil, error: String? = nil, errorCode: String? = nil,
        messageId: String? = nil
    ) {
        sendSignResponse(SignResponseMessage(
            flowId: flowId,
            messageId: messageId,
            proofJwt: proofJwt,
            vpToken: vpToken,
            proofs: proofs,
            clientAttestation: clientAttestation,
            clientAttestationPoP: clientAttestationPoP,
            dpopKeyId: dpopKeyId,
            dpopProof: dpopProof,
            credentialResponseEncryptionJwk: credentialResponseEncryptionJwk, credentialCount: credentialCount,
            transactionId: transactionId, interval: interval, error: error, errorCode: errorCode
        ))
    }
}

extension WalletEngineSession: SignResponseSender {
    func sendSignResponse(_ message: SignResponseMessage) {
        sendSignResponse(
            flowId: message.flowId,
            proofJwt: message.proofJwt,
            vpToken: message.vpToken,
            proofs: message.proofs,
            clientAttestation: message.clientAttestation,
            clientAttestationPoP: message.clientAttestationPoP,
            dpopKeyId: message.dpopKeyId,
            dpopProof: message.dpopProof,
            credentialResponseEncryptionJwk: message.credentialResponseEncryptionJwk, credentialCount: message.credentialCount,
            transactionId: message.transactionId, interval: message.interval, error: message.error, errorCode: message.errorCode,
            messageId: message.messageId
        )
    }
}

extension SirosWallet {
    // MARK: - Engine connection

    /// Connect engine using a backend token from the AS. The anonymous token
    /// is scoped to `tac="rl"` for registry-style reads only - the engine
    /// session needs `insert` for OID4VCI issuance, so it must use the
    /// fully-scoped backend token, not the anonymous one
    /// (go-wallet-backend#264 made the missing `insert` scope a hard
    /// server-side rejection for `oid4vci` flow_start, not just a
    /// documentation note).
    // Not `private`: called from `SirosWallet.swift`'s `register`/`login`/
    // `resumeSession` (this function now lives in `SirosWallet+Engine.swift`)
    // - same cross-file-extension-access reason as `keystore` above.
    func connectEngineWithToken(_ tokens: AuthTokens) async throws {
        let token = try await tokens.ensureBackendToken()
        if config.useWmpProtocol {
            try await connectViaWmp(appToken: token.raw)
        } else {
            try await connectEngine(appToken: token.raw)
        }
    }

    // MARK: - WMP Protocol Path

    func connectViaWmp(appToken: String) async throws {
        markSessionEnded(false)
        // Resolve engine base URL
        let engineBase: String
        if !config.engineUrl.isEmpty {
            engineBase = config.engineUrl
        } else if let discovered = await WalletConfig.discoverEngineUrl(backendUrl: config.backendUrl) {
            engineBase = discovered
        } else {
            engineBase = config.backendUrl
        }

        let wsUrl = engineBase.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            .replacingOccurrences(of: "http://", with: "ws://")
            .replacingOccurrences(of: "https://", with: "wss://")
            + "/api/v2/wallet?tenant_id=\(config.tenantId)"

        let transport = WmpWebSocketTransport(url: URL(string: wsUrl)!)
        let session = WmpSession(transport: transport)
        let peer = WmpPeer(session: session)

        let profile = OpenID4xProfile(config: OpenID4xConfig(
            onSignRequest: { [weak self] flowId, params in
                guard let self else { throw SirosError.auth(message: "Wallet deallocated") }
                return try await self.handleWmpSignRequest(flowId: flowId, params: params)
            },
            onMatchRequest: { [weak self] flowId, payload in
                guard let self else { throw SirosError.auth(message: "Wallet deallocated") }
                return await self.handleWmpMatchRequest(flowId: flowId, payload: payload)
            },
            onTrustEvaluation: { [weak self] flowId, payload in
                guard let self else { return SirosTransport.TrustResult(trusted: false, reason: "Wallet deallocated") }
                return await self.handleWmpTrustEvaluation(flowId: flowId, payload: payload)
            },
            onComplete: { [weak self] flowId, result in
                await self?.handleWmpFlowComplete(flowId: flowId, result: result)
            },
            onCancel: { [weak self] flowId, flowType in
                self?.handleWmpFlowCancel(flowId: flowId, flowType: flowType)
            },
            onError: { [weak self] flowId, code, message in
                self?.resetIssuanceGuards()
                self?.cancelTransactionTasks(flowId: flowId)
                self?.eventListener?.onFlowError(flowId: flowId, errorMessage: "\(code ?? ""): \(message ?? "")", redirectUri: nil)
            },
            onShutdown: { [weak self] in
                // The WMP session ended (closed, or failed for good): what blind issuance holds goes with it.
                self?.clearBlindIssuanceState()
                self?.resetIssuanceGuards()
            }
        ))
        peer.use(profile)
        // Offered per session: a flag flip applies from the next session.
        let offerTransactionData = snapshotWmpSessionEnablement()
        try await peer.connect(
            authToken: appToken,
            capabilitiesOffered: TransactionDataDeclaration.wmpCapabilitiesOffered(enabled: offerTransactionData)
        )
        lock.lock(); wmpPeer = peer; credentialNotifier = WmpCredentialNotifier(peer: peer); lock.unlock()

        #if canImport(os)
        logger.info("Connected via WMP protocol to \(wsUrl)")
        #endif
    }

    /// Ask go-wallet-backend's real, x5c-chained Key Attestation endpoint
    /// (`POST /wallet-provider/key-attestation/generate`) to attest freshly
    /// generated keys, instead of `KeystoreManager.generateKeyAttestation`'s
    /// self-signed fallback (a bare `jwk` header - cryptographically valid
    /// but no trust anchor a real issuer can validate against).
    ///
    /// Private keys never leave the device: only the public JWKs (from
    /// `KeystoreManager.generateKeypairs`) and security properties are sent -
    /// the backend signs an attestation *over* them with its own,
    /// operator-provisioned x5c-chained key.
    ///
    /// Returns a `nil` result (caller falls back to the self-signed path,
    /// via the `keystore` also returned here - see below) when there's no
    /// backend session, the keystore can't produce raw keypairs, or the
    /// backend doesn't support/expose the endpoint.
    ///
    /// - Returns: the attestation result (`nil` on any failure - see above),
    ///   ALONGSIDE the `KeystoreManager` this call actually resolved and
    ///   used for key generation (`self.keystore` unless
    ///   `WscdSelectionPolicy` picked a different registered plugin for
    ///   this credential type). The caller's self-signed fallback on a
    ///   `nil` result must use THIS keystore, not `self.keystore` again -
    ///   otherwise a resolved higher-tier plugin would be silently bypassed
    ///   on fallback, generating a lower-tier self-signed attestation
    ///   instead.
    /// - Throws: `WscdSelectionError.noEligiblePlugin` or
    ///   `.ambiguousChoiceNotMade` when `config.availableKeystores` is set
    ///   but selection couldn't produce a plugin ID to use - unlike every
    ///   other failure here, these must NOT be swallowed into a nil/
    ///   self-signed fallback, since that fallback would just use an
    ///   equally (or more) insufficient plugin (see `WscdSelectionPolicy`'s
    ///   doc comment).
    // Internal (not private) so `@testable import` can exercise the WSCD
    // plugin-selection wiring directly (see `SirosWalletWscdSelectionTests`),
    // matching this file's existing precedent for other testable internals.
    func requestBackendKeyAttestation(audience: String, nonce: String, count: Int) async throws -> (result: BackendAttestationResult?, keystore: KeystoreManager) {
        lock.lock(); let client = apiClient; lock.unlock()

        // Pick which registered keystore backs this batch's key generation -
        // a no-op (stays `self.keystore`) unless the host app opted in via
        // `config.availableKeystores`. This can throw `noEligiblePlugin`/
        // `.ambiguousChoiceNotMade`; that's allowed to propagate past this
        // function's own catch-all below (see the doc comment above).
        // Resolved BEFORE the `client` guard so a `nil` "no backend session"
        // return still carries the correctly-resolved keystore for the
        // caller's fallback, rather than always `self.keystore`.
        var effectiveKeystore = keystore
        if let availableKeystores = config.availableKeystores {
            lock.lock()
            let credentialType = activeVctm?.vct ?? activeMddlSchema?.doctype ?? activeOffer?.credentialConfigurationId ?? ""
            let requiredTier = activeVctm?.requiredKeyStorage ?? activeMddlSchema?.requiredKeyStorage
            lock.unlock()
            if let pluginId = try await wscdSelectionPolicy.resolve(
                issuer: audience,
                credentialType: credentialType,
                requiredTier: requiredTier,
                availablePluginIds: Array(availableKeystores.keys)
            ), let picked = availableKeystores[pluginId] {
                effectiveKeystore = picked
            }
        }

        guard let client else { return (nil, effectiveKeystore) }

        do {
            let keypairs = try await effectiveKeystore.generateKeypairs(count: count)
            await registerFido2AttestationsForBatch(keypairs: keypairs, client: client, keystore: effectiveKeystore)
            var secDict: [String: Any]?
            if let keyId = keypairs.first?.keyId, let props = await effectiveKeystore.securityProperties(keyId: keyId) {
                secDict = [
                    "key_storage": props.keyStorage,
                    "user_authentication": props.userAuthentication,
                    "certification": props.certification.toJsonValue(),
                ]
            }
            let jwt = try await client.requestKeyAttestation(
                jwks: keypairs.map { $0.publicKeyJWK },
                nonce: nonce,
                securityProperties: secDict,
                credentialIssuer: audience.isEmpty ? nil : audience,
                walletInstanceId: currentWalletInstanceId()
            )
            // keypairs[i]'s key is exactly attested_keys[i] in the JWT just
            // built (jwks preserves list order) - the issuer is expected to
            // mint credential i in the eventual batch response bound to
            // attested_keys[i], so this ordering IS the instanceId -> kid
            // mapping the credential-storage handler needs later.
            return (BackendAttestationResult(jwt: jwt, keyIds: keypairs.map { $0.keyId }), effectiveKeystore)
        } catch {
            return (nil, effectiveKeystore)
        }
    }

    /// Register each freshly-generated credential key's FIDO2/CTAP2 hardware
    /// attestation with the backend, keyed by that specific key - NOT the
    /// wallet's own identity key (see go-wallet-backend's `KeyAttestationStore`
    /// doc for why this must be per-credential-key: the identity key and
    /// credential-issuance keys are separate keys, not guaranteed to share a
    /// WSCD plugin, so registering only the identity key's attestation would
    /// incorrectly leave the actual credential keys - the ones a KA request's
    /// `attested_keys`/`security_properties` claim is really about -
    /// unattested).
    ///
    /// A no-op per key when `keystore`'s active plugin isn't hardware-backed
    /// (`attestationChain` returns nil for those - most commonly the whole
    /// batch, since `generateKeypairs` uses whichever single plugin is
    /// currently active for every key in one call). Best-effort per key: a
    /// registration failure for one key must never block the others, or the
    /// overall KA request that follows - it's simply retried the next time a
    /// fresh batch happens to reuse the same plugin (there's no "already
    /// registered" dedup here, unlike the old identity-key path: these keys
    /// are one-shot, used once for this batch, so there's nothing to dedupe
    /// against).
    ///
    /// Requires a cached WIA to supply `wallet_instance_id` for the
    /// registration record's auditing/scoping - peeks `cachedWia` directly
    /// (any `attestation_source`, not gated to native platform attestation
    /// like `currentWalletInstanceId` - that gate is specifically about the
    /// KA security_properties clamp-lift, unrelated to this). No cached WIA
    /// means nothing to register against, so this is a no-op entirely.
    /// - Parameter keystore: the keystore that actually generated
    ///   `keypairs` - `requestBackendKeyAttestation` may have swapped in a
    ///   registered plugin other than `self.keystore` for this batch (see
    ///   `WscdSelectionPolicy`), so this must NOT assume `self.keystore`.
    private func registerFido2AttestationsForBatch(keypairs: [KeypairInfo], client: BackendApiClient, keystore: KeystoreManager) async {
        let now = Int(Date().timeIntervalSince1970)
        lock.lock(); let wia = cachedWia; let expiresAt = cachedWiaExpiresAt; lock.unlock()
        guard let wia, expiresAt - now > 60,
              let cnf = CredentialUtils.parseJwtPayload(wia)?["cnf"] as? [String: Any],
              let walletInstanceId = cnf["jkt"] as? String else { return }
        for kp in keypairs {
            guard let chain = try? await keystore.attestationChain(keyId: kp.keyId),
                  let attestationObject = chain.certificates.first else { continue }
            do {
                try await client.registerFido2Attestation(
                    walletInstanceId: walletInstanceId,
                    attestationObject: attestationObject,
                    clientDataHash: chain.clientDataHash
                )
            } catch {
                #if canImport(os)
                logger.warning("FIDO2 attestation registration failed for key \(kp.keyId), continuing: \(error.localizedDescription)")
                #endif
            }
        }
    }

    // Not `private`: the test target drives it directly.
    func handleWmpSignRequest(flowId: String, params: SignSubFlowParams) async throws -> SignSubFlowResult {
        switch params.action {
        case "generate_proof":
            return try await wmpGenerateProof(flowId: flowId, params: params)

        case "decrypt_credential_response":
            return try await wmpDecryptCredentialResponse(flowId: flowId, params: params)

        case "sign_presentation":
            // Same defense-in-depth audience check as the legacy engine
            // transport's handleSignRequest - this transport previously
            // skipped it entirely, so a WMP-relayed sign_presentation was
            // never checked against the trust result computed for this flow.
            let evaluated = try validateAudience(flowId: flowId, audience: params.audience)
            if params.transactionDataMember.requestsTransactionHandling {
                // Tracked per flow: a flow error, logout or peer teardown cancels it. The verifier
                // shown and logged is the evaluated identity, not the protocol audience.
                let verifier = Self.transactionVerifierLabel(trust: evaluated, fallback: params.audience)
                return try await trackedTransaction(flowId: flowId) { try await self.wmpTransactionPresentation(flowId: flowId, params: params, verifier: verifier) }
            }
            // NOTE (pre-existing, separate gap - not addressed by this
            // change): unlike the legacy engine transport's
            // SignRequestParams, WMP's SignSubFlowParams carries no
            // credentials_to_include equivalent at all, so there is no way
            // for this handler to know which credential(s)
            // handleWmpMatchRequest matched/the user selected, or to build a
            // real per-credential vp_token (mso_mdoc/SD-JWT/ZK) for this
            // transport - it always falls back to the credential-less
            // legacy signPresentation path below. Fixing this needs a wire
            // protocol change to SignSubFlowParams, out of scope here.
            let vpToken = try await keystore.signPresentation(
                nonce: params.nonce,
                audience: params.audience,
                credentialIds: [],
                kid: nil
            )
            return SignSubFlowResult(vpToken: vpToken)

        // Client authentication, same semantics as the legacy transport's
        // request_attestation / sign_client_auth cases in handleSignRequest:
        // the WMP sign sub-flow carries the same params and the result goes
        // back under the same member names.
        case "request_attestation":
            let material = await buildClientAuth(
                flowId: flowId,
                keyIdHint: nil,
                audience: params.audience,
                issuer: params.issuer,
                htm: nil,
                htu: nil,
                dpopNonce: nil,
                ath: nil
            )
            return SignSubFlowResult(clientAttestation: material.wia, clientAttestationPoP: material.pop)

        case "sign_client_auth":
            let material = await buildClientAuth(
                flowId: flowId,
                keyIdHint: params.keyId,
                audience: params.audience,
                issuer: params.issuer,
                htm: params.htm,
                htu: params.htu,
                dpopNonce: params.dpopNonce,
                ath: params.ath
            )
            return SignSubFlowResult(
                clientAttestation: material.wia,
                clientAttestationPoP: material.pop,
                dpopKeyId: material.keyId,
                dpopProof: material.dpopProof
            )

        default:
            throw SirosError.auth(message: "Unknown sign action: \(params.action)")
        }
    }

    private func handleWmpMatchRequest(flowId: String, payload: AnyCodable?) async -> MatchResult {
        let allCreds = await credentialStore.getAll()
        // WMP's "matching_credentials"/"match_request" progress step carries
        // the same payload shape as the legacy engine's "credential_selection"
        // step (a "dcql_query" object, optionally alongside "verifier" info) -
        // filter against it instead of unconditionally offering every
        // eligible credential regardless of what the verifier actually asked
        // for.
        let dcqlQuery = payload?.objectValue?["dcql_query"]?.objectValue.map { anyCodableDictToAny($0) }
        let dcqlOutput: CredentialMatcher.DcqlMatchOutput
        if let dcqlQuery {
            dcqlOutput = CredentialMatcher.matchDcql(dcqlQuery: dcqlQuery, credentials: allCreds)
        } else {
            dcqlOutput = CredentialMatcher.DcqlMatchOutput(
                queryResults: [CredentialMatcher.MatchResult(
                    queryId: "_default", format: nil, candidates: allCreds, requestedClaims: []
                )],
                credentialSets: nil,
                satisfiableOptions: []
            )
        }
        let matchResults = dcqlOutput.queryResults
        var seenIds = Set<Int64>()
        let candidates = matchResults.flatMap { $0.candidates }.filter { seenIds.insert($0.id).inserted }

        // Only offer instances the active consumption policy still considers
        // usable - mirrors the legacy engine path's handleMatchRequest (and
        // Kotlin's matchRequests() collector) so a credential exhausted under
        // CONSUME_ALL/CONSUME_NON_ZKP can't be matched into a new
        // presentation via this transport either. Same first-match ZK rule
        // as the other two selection paths (see `Self.zkRequestedIds`).
        let zkRequestedIds = Self.zkRequestedIds(
            matchResultByCredentialId: Self.firstMatchByCredentialId(candidates: candidates, matchResults: matchResults)
        )
        let eligibleCreds = eligibleInstances(from: candidates, isZkPresentation: { zkRequestedIds.contains($0.id) })

        // Cache for the later sign_presentation step, mirroring
        // handleCredentialSelection/handleMatchRequest - see
        // pendingMatchResultsByFlow's doc comment. NOTE: handleWmpSignRequest
        // does not currently read this map or accept any
        // credentials_to_include equivalent at all (see its own doc
        // comment on the "sign_presentation" case) - this is currently
        // write-only for the WMP transport, kept for parity/consistency
        // with the other two call sites and so it's ready once that
        // separate gap is closed.
        lock.lock(); pendingMatchResultsByFlow[flowId] = matchResults; lock.unlock()

        let matches = eligibleCreds.map { cred -> CredentialMatch in
            let queryId = matchResults.first(where: { result in result.candidates.contains(where: { $0.id == cred.id }) })?.queryId
            // credentialId is the WMP wire-protocol identifier - a separate,
            // unverified backend contract distinct from privatedata-spec's
            // numeric StoredCredential.id, so it deliberately stays String.
            return CredentialMatch(
                credentialQueryId: queryId,
                credentialId: String(cred.id),
                format: cred.format,
                vct: CredentialUtils.vctOf(cred),
                availableClaims: nil
            )
        }
        // An empty match set with no reason tells the other end nothing at all
        // - see `noMatchReason`.
        let reason = matches.isEmpty ? Self.noMatchReason(dcqlQuery: dcqlQuery, candidateCount: candidates.count) : nil
        return MatchResult(matches: matches, noMatchReason: reason)
    }

    // internal, not private: testable directly (see
    // SirosWalletTrustResolutionTests), matching handleTrustEvaluation's own
    // access level for the same reason.
    func handleWmpTrustEvaluation(flowId: String, payload: AnyCodable?) async -> SirosTransport.TrustResult {
        // Extract subject_id from the payload
        guard case .object_(let payloadDict) = payload,
              case .object_(let request) = payloadDict["request"],
              case .string(let subjectId) = request["subject_id"],
              !subjectId.isEmpty else {
            return SirosTransport.TrustResult(trusted: false, reason: "Missing subject_id")
        }

        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else {
            return SirosTransport.TrustResult(trusted: false, reason: "No API client")
        }

        // WMP carries both issuance (generate_proof) and presentation
        // (sign_presentation) sign requests over the same profile - the
        // action name must follow subject_type like the legacy engine path's
        // handleTrustEvaluation does, not be hardcoded to "credential-issuer"
        // for every subject (a real bug: a verifier evaluated over WMP was
        // being checked against the issuer trust policy instead of the
        // verifier one).
        var subjectType: String?
        if case .string(let t) = request["subject_type"] {
            subjectType = t
        }
        let actionName = subjectType == "credential_verifier" ? "credential-verifier" : "credential-issuer"

        do {
            var keyMaterial: [String: AnyCodable]?
            if case .object_(let km) = request["key_material"] {
                keyMaterial = km
            }

            // requires_resolution/request_jwt/resolution_subject_id
            // (go-wallet-backend#396/#401, this SDK's #168) - the same
            // did:-scheme frontend-fallback support the legacy engine path's
            // handleTrustEvaluation has, shared via resolveDidKeyMaterial.
            // Without this, a did:-scheme verifier trust evaluation routed
            // over WMP (WalletConfig.useWmpProtocol) silently ignored these
            // fields and evaluated with no key material at all (review
            // finding).
            var resolvedJwk: [String: Any]?
            var resolvedIssuerJwks: [[String: Any]]?
            if case .bool(true) = request["requires_resolution"] {
                guard case .string(let resolutionSubjectId) = request["resolution_subject_id"], !resolutionSubjectId.isEmpty else {
                    return SirosTransport.TrustResult(trusted: false, reason: "Trust evaluation requires resolution but no resolution_subject_id was supplied")
                }
                var requestJwt: String?
                if case .string(let jwt) = request["request_jwt"], !jwt.isEmpty {
                    requestJwt = jwt
                }
                do {
                    if actionName == "credential-verifier" {
                        // A verifier's request_jwt is what resolution is
                        // FOR - there's a signed authorization request to
                        // verify against, so requiring one here is correct
                        // (unlike the issuer branch below).
                        guard let requestJwt else {
                            return SirosTransport.TrustResult(trusted: false, reason: "Trust evaluation requires resolution but no request_jwt was supplied")
                        }
                        resolvedJwk = try await resolveDidKeyMaterial(client: client, resolutionSubjectId: resolutionSubjectId, requestJwt: requestJwt)
                    } else {
                        // OID4VCI issuance has no signed request object to
                        // verify request_jwt against - the backend never
                        // sends one for a DID issuer, unlike a verifier
                        // (review finding, #168 follow-up).
                        resolvedIssuerJwks = try await resolveIssuerDidKeyMaterial(client: client, resolutionSubjectId: resolutionSubjectId)
                    }
                } catch {
                    return SirosTransport.TrustResult(trusted: false, reason: error.localizedDescription)
                }
            }

            let kmType = (resolvedJwk != nil || resolvedIssuerJwks != nil) ? "jwk" : (keyMaterial?["type"]?.stringValue ?? "x5c")

            // Include the actual key material (x5c/jwk), not just its type -
            // matching the legacy engine path's `handleTrustEvaluation` and
            // the direct-call `evaluateTrustDirect`. Omitting this let the
            // backend evaluate trust based on the subject identifier alone,
            // with no cryptographic binding to the key actually presented.
            var resource: [String: Any] = ["type": kmType, "id": subjectId]
            if let resolvedJwk {
                resource["key"] = [resolvedJwk]
            } else if let resolvedIssuerJwks {
                resource["key"] = resolvedIssuerJwks
            } else if let x5c = keyMaterial?["x5c"] {
                resource["key"] = anyCodableToAny(x5c)
            } else if let jwk = keyMaterial?["jwk"] {
                resource["key"] = [anyCodableToAny(jwk)]
            }

            let evaluationRequest: [String: Any] = [
                "subject": ["type": "key", "id": subjectId],
                "resource": resource,
                "action": ["name": actionName],
            ]
            let response = try await evaluateTrustCached(client, evaluationRequest)
            let decision = response["decision"] as? Bool ?? false
            let context = response["context"] as? [String: Any]

            // Store for the later sign_presentation step's validateAudience
            // check, mirroring handleTrustEvaluation - without this, WMP
            // presentations had no audience-binding defense-in-depth at all.
            lock.lock()
            lastTrustResults[flowId] = TrustResult(
                trusted: decision,
                framework: context?["framework"] as? String,
                reason: (context?["reason"] as? String) ?? (context?["message"] as? String),
                entityName: context?["entity_name"] as? String,
                entityLogo: context?["logo_uri"] as? String,
                identifier: subjectId
            )
            lock.unlock()

            return SirosTransport.TrustResult(trusted: decision)
        } catch {
            return SirosTransport.TrustResult(trusted: false, reason: error.localizedDescription)
        }
    }

    // MARK: - Legacy Engine Path

    func connectEngine(appToken: String) async throws {
        markSessionEnded(false)
        // Resolve engine base URL: explicit config > discovery > same as backend
        let engineBase: String
        if !config.engineUrl.isEmpty {
            engineBase = config.engineUrl
        } else if let discovered = await WalletConfig.discoverEngineUrl(backendUrl: config.backendUrl) {
            engineBase = discovered
        } else {
            engineBase = config.backendUrl
        }
        let engine = Self.createEngineSession(engineBase, config.tenantId)
        lock.lock(); engineSession = engine; credentialNotifier = engine; lock.unlock()
        // A replaced socket ends the flows that ran on the old one: their response keys and opened responses go too.
        installSocketReplacedHook(on: engine)
        engine.connect(appToken: appToken, tokenProvider: { [weak self] in
            guard let tokens = self?.authTokens else {
                throw SirosError.wallet(message: "Not connected")
            }
            return try await tokens.ensureBackendToken().raw
        }, onTokenRejected: { [weak self] error in
            // See `WalletEngineSession.onTokenRejected`'s doc comment: this
            // is the reconnect path's counterpart to
            // `BackendApiClient.request`'s 401 handling - both must feed
            // `AuthTokens.registerTokenRejection` so repeated rejections
            // (from either transport) actually accumulate toward the same
            // forced-logout threshold, instead of only being visible to
            // whichever path happened to notice first. Only a genuine 401
            // counts, mirroring `BackendApiClient.request`'s exact check -
            // `ensureBackendToken()` can also fail for reasons that aren't a
            // real rejection (e.g. a transient network error reaching the
            // auth server), and those must not accumulate toward the
            // forced-logout threshold the same way an actual rejection does.
            guard case let SirosError.backendApi(code, _, _) = error, code == 401 else { return }
            self?.authTokens?.registerTokenRejection(AuthTokens.tokenBackend)
        })
        try await engine.awaitConnected()

        // Catches WalletEngineSession.State.reauthRequired transitions from
        // the automatic background reconnect loop, which never goes through
        // awaitConnected - cancelled alongside every other engine task on
        // logout (see cancelEngineTasks).
        let reauthTask = Task { [weak self] in
            for await state in engine.stateStream where state == .reauthRequired {
                self?.handleReauthenticationRequired()
            }
        }

        // Sign requests → auto-sign with keystore
        let signTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.signRequests() {
                if msg.action == "sign_presentation", msg.params.transactionDataMember.requestsTransactionHandling {
                    // A transaction waits for the user. That must not hold up the
                    // engine's other requests (issuance proofs, client auth,
                    // attestation), which are handled in order on this loop.
                    // The lock is held across creation AND registration, so the task's own
                    // removal (it takes the same lock) can never run before it is registered.
                    //
                    // The flow's start record is claimed HERE, on this serial collector, so
                    // records are consumed in message-arrival order whatever order the
                    // spawned tasks happen to run in.
                    // A collector cancelled by a teardown does not go on to start work for the old request,
                    // and the registration below is checked against the teardown epoch captured first.
                    guard !Task.isCancelled else { break }
                    let epoch = self.currentTaskEpoch()
                    _ = self.transactionDataActive(forFlow: msg.flowId, viaWmp: false)
                    let id = UUID()
                    self.lock.lock()
                    let task = Task { [weak self] in
                        await self?.handleSignRequest(engine: engine, msg: msg)
                        self?.lock.lock(); self?.transactionTasks.removeValue(forKey: id); self?.lock.unlock()
                    }
                    if self.transactionTaskEpoch == epoch { self.transactionTasks[id] = (flowId: msg.flowId, cancel: { task.cancel() }) } else { task.cancel() }
                    // A flow that ended between the claim above and this registration has had its record
                    // removed by the terminal handler (which found nothing to cancel): cancel the task now.
                    if self.legacyFlowSnapshots[msg.flowId] == nil { task.cancel() }
                    self.lock.unlock()
                } else {
                    await self.handleSignRequest(engine: engine, msg: msg)
                }
            }
        }
        // Match requests → credential matching
        let matchTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.matchRequests() {
                await self.handleMatchRequest(engine: engine, msg: msg)
            }
        }
        // Flow progress
        let progressTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.flowProgress() {
                await self.handleFlowProgress(engine: engine, msg: msg)
            }
        }
        // Flow complete
        let completeTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.flowComplete() {
                await self.handleFlowComplete(msg: msg)
            }
        }
        // Flow errors
        let errorTask = Task { [weak self] in
            guard let self else { return }
            for await msg in engine.flowErrors() {
                self.handleFlowError(msg: msg)
            }
        }
        engineTasks = [signTask, matchTask, progressTask, completeTask, errorTask, reauthTask]
    }

    // Not `private`: the test target drives it with a recording
    // `SignResponseSender` (there is no transport seam in
    // `WalletEngineSession` itself to fake a live engine at).
    func handleSignRequest(engine: any SignResponseSender, msg: SignRequestMessage) async {
        do {
            switch msg.action {
            case "generate_proof":
                try await answerGenerateProof(engine: engine, msg: msg)

            case "decrypt_credential_response":
                await answerDecryptCredentialResponse(engine: engine, msg: msg)

            case "sign_presentation":
                // Claim this flow's enablement record whether or not it carries a
                // transaction, so a plain presentation does not leave it behind.
                _ = transactionDataActive(forFlow: msg.flowId, viaWmp: false)
                let nonce = msg.params.nonce ?? ""
                let audience = msg.params.audience ?? ""
                let credsToInclude = msg.params.credentialsToInclude

                // Validate audience matches trusted verifier identity
                let evaluated = try validateAudience(flowId: msg.flowId, audience: audience)

                let allCredsForTransaction = await credentialStore.getAll()
                // Empty for every request without `transaction_data`; refuses
                // before anything is signed when the request carries it but
                // cannot be honoured.
                let scaPlan = try await orchestratedTransactionPlan(
                    transactionData: msg.params.transactionDataMember, responseMode: msg.params.responseMode,
                    refs: credsToInclude, allCreds: allCredsForTransaction,
                    flowId: msg.flowId, viaWmp: false,
                    context: ScaRequestContext(
                        verifier: Self.transactionVerifierLabel(trust: evaluated, fallback: audience), nonce: nonce, audience: audience
                    )
                )

                if let credsToInclude, !credsToInclude.isEmpty {
                    let allCreds = allCredsForTransaction
                    // Cached by handleCredentialSelection ("credential_selection"
                    // step - the real, live path for redirect-flow/haip-vp://
                    // presentations) or handleMatchRequest (legacy match_request
                    // path) - consumed (removed) here, at the point this batch's
                    // tokens are actually built, mirroring Kotlin's identical
                    // `pendingMatchResultsByFlow.remove(msg.flowId)`.
                    lock.lock()
                    let storedMatchResults = pendingMatchResultsByFlow.removeValue(forKey: msg.flowId)
                    lock.unlock()
                    var vpParts: [String] = []
                    do {
                    for ref in credsToInclude {
                        // A flow that ended (or a logout) while the user decided must not sign.
                        try Task.checkCancellation()
                        // ref.credentialId is the WMP wire-protocol identifier
                        // (String) - parse it back to the numeric
                        // StoredCredential.id it refers to.
                        guard let cred = allCreds.first(where: { $0.id == Int64(ref.credentialId) }) else { continue }
                        let matchResult = storedMatchResults?.first(where: { result in
                            result.queryId == ref.credentialQueryId || result.candidates.contains(where: { $0.id == cred.id })
                        })
                        vpParts.append(try await buildSignPresentationVpPart(
                            cred: cred,
                            ref: ref,
                            matchResult: matchResult,
                            nonce: nonce,
                            audience: audience,
                            msg: msg,
                            transactionData: ref.credentialQueryId.flatMap { scaPlan?.bindings[$0] },
                            transactionKid: scaPlan?.kid(for: ref.credentialQueryId, fallback: nil)
                        ))
                    }
                    // A signer need not observe cancellation: recheck after the FINAL signing await,
                    // so an ended flow's token is never sent and its consent never recorded.
                    try Task.checkCancellation()
                    } catch {
                        // A cancelled request is not a signing failure and is not logged as one.
                        if !Task.isCancelled && !(error is CancellationError) { await Self.shielded { await scaPlan?.plan.complete(failedWith: error) } }
                        throw error
                    }
                    let vpToken = vpParts.joined(separator: "\n")
                    engine.sendSignResponse(flowId: msg.flowId, vpToken: vpToken, messageId: msg.messageId)
                    // The record of a presentation that was sent must be written even if the flow's
                    // completion cancels this task meanwhile.
                    await Self.shielded { await scaPlan?.plan.complete(signed: true) }
                } else {
                    let vpToken = try await keystore.signPresentation(
                        nonce: nonce, audience: audience, credentialIds: [], kid: nil
                    )
                    engine.sendSignResponse(flowId: msg.flowId, vpToken: vpToken, messageId: msg.messageId)
                }

            case "request_attestation":
                // Engine-requested Wallet Instance Attestation (go-wallet-backend
                // `SignActionRequestAttestation`). A nil pair is a deliberate
                // decline: the empty response below lets the engine continue
                // without wallet attestation right away instead of sitting on
                // its 30 s sign timeout. Never throws (see the helper's doc).
                let pair = await clientAttestation(forEngineRequest: msg.params)
                engine.sendSignResponse(
                    flowId: msg.flowId,
                    clientAttestation: pair?.0,
                    clientAttestationPoP: pair?.1,
                    messageId: msg.messageId
                )

            case "sign_client_auth":
                // Engine-requested client authentication for one outbound
                // request (go-wallet-backend#317): a DPoP proof and/or a
                // fresh attestation PoP, both signed with the instance key.
                // Never throws; whatever could not be produced is absent
                // and the engine decides what that means (see
                // `buildClientAuth`).
                let material = await buildClientAuth(flowId: msg.flowId, params: msg.params)
                engine.sendSignResponse(
                    flowId: msg.flowId,
                    clientAttestation: material.wia,
                    clientAttestationPoP: material.pop,
                    dpopKeyId: material.keyId,
                    dpopProof: material.dpopProof,
                    messageId: msg.messageId
                )

            default:
                // An action this SDK build doesn't know. The engine has no
                // separate "sign error" message - `RequestSign` only unblocks
                // on a `sign_response` with a matching `message_id` - so
                // answer with an empty one: the engine then fails fast on the
                // missing payload (and reports a flow_error we handle as
                // usual) instead of stalling for the full sign timeout, which
                // is what silently ignoring the request used to cause.
                #if canImport(os)
                logger.warning("Unknown sign action \(msg.action, privacy: .public); sending empty sign_response")
                #endif
                engine.sendSignResponse(flowId: msg.flowId, messageId: msg.messageId)
            }
        } catch {
            // Cancelled by logout/destroy or because the flow already ended: the
            // owner of the cancellation has reset the state, so reporting a
            // failure here would race a teardown or re-login.
            if Task.isCancelled || error is CancellationError { return }
            #if canImport(os)
            logger.error("Error handling sign request: \(error.localizedDescription)")
            #endif
            if case SirosError.transactionData(let refusal) = error {
                // Answer at once rather than leave the engine waiting out its
                // sign timeout; an empty response makes it fail the flow. The
                // engine protocol has no field for `invalid_transaction_data`
                // / `access_denied`, so only the code reaches the app, and the
                // user's own decline is not presented to it as an error.
                engine.sendSignResponse(flowId: msg.flowId, messageId: msg.messageId)
                reportSignFailure(flowId: msg.flowId, message: refusal.verifierErrorCode, notifyError: refusal.reason != .declined)
            } else {
                reportSignFailure(flowId: msg.flowId, message: error.localizedDescription)
            }
        }
    }

    /// Builds a single credential's VP-token part - ZK-wrapped mdoc, plain
    /// mdoc `DeviceResponse`, or SD-JWT VP+KB-JWT - for the
    /// `"sign_presentation"` `sign_request` action handled by
    /// `handleSignRequest`. Factored out of that function purely to keep its
    /// body under SwiftLint's `function_body_length` limit; behavior is
    /// unchanged from the inline version. `matchResult` is the originating
    /// DCQL query's cached match info (`format`/`zkSystemTypes`/`ppidContext`)
    /// looked up by `handleSignRequest` via `pendingMatchResultsByFlow`, or
    /// `nil` if none was cached for this credential (falls back to
    /// `cred.format` alone to decide the branch, same as before this was
    /// extracted).
    private func buildSignPresentationVpPart(
        cred: StoredCredential,
        ref: CredentialRef,
        matchResult: CredentialMatcher.MatchResult?,
        nonce: String,
        audience: String,
        msg: SignRequestMessage,
        transactionData: TransactionDataBinding? = nil,
        transactionKid: String? = nil
    ) async throws -> String {
        if transactionData != nil, cred.format == "mso_mdoc" || matchResult?.format.map(CredentialUtils.isZkpFormat) == true {
            // The pipeline refuses non-SD-JWT credentials before this point.
            throw SirosError.transactionData(TransactionDataError(.unsupportedFormat))
        }
        if let format = matchResult?.format, CredentialUtils.isZkpFormat(format) {
            // ZK-wrapped mDoc presentation - see handleDCAPIRequest's
            // identical branch, which this mirrors for the WS-engine/
            // redirect-flow transport instead of DC API.
            guard let credBytes = Self.b64UrlDecode(cred.raw) else {
                throw SirosError.wallet(message: "Credential \(cred.id) has malformed base64url raw data")
            }
            // cred.kid is commonly nil for a softkey-issued credential with
            // no explicit per-credential key binding - see the identical
            // fallback in handleDCAPIRequest.
            guard let kid = cred.kid ?? keystore.listKeys().first?.keyId else {
                throw SirosError.wallet(message: "No signing key available for credential \(cred.id) - cannot generate a ZK proof for it")
            }
            let mdocDocument = try MdocCbor.parseStoredCredential([UInt8](credBytes))
            let docType = mdocDocument.docType
            // See handleDCAPIRequest's identical comment: a circuit is
            // compiled for a fixed attribute count, so matching must account
            // for how many claims are actually being disclosed here.
            guard let (system, spec) = zkProofSystemRegistry.resolve(
                credentialType: CredentialTypeRef(format: .msoMdoc, typeId: docType),
                requestedSpecs: matchResult?.zkSystemTypes ?? [],
                numAttributes: ref.disclosedClaims?.count ?? 0
            ) else {
                throw SirosError.wallet(message: "No registered ZK proof system satisfies the verifier's zk_system_type for \(docType)")
            }
            // Only bind a pseudonym when actually disclosed for this query -
            // see handleDCAPIRequest's identical comment.
            let wantsPseudonym = ref.disclosedClaims?.contains(zkPseudonymClaim) == true
            let verifierIdentity: VerifierIdentity? = wantsPseudonym
                ? VerifierIdentity(
                    clientId: audience,
                    ppidContext: matchResult?.ppidContext,
                    // The verifier-assigned presentation session id (see
                    // VerifierIdentity.sessionId's doc comment) - the real
                    // verifier_context binding input for the WS-engine
                    // transport, where (unlike DC API) go-wallet-backend
                    // forwards it from the original request_uri.
                    sessionId: msg.params.verifierSessionId
                )
                : nil
            let sessionTranscript = MdocDeviceResponseBuilder.buildOpenID4VPSessionTranscript(
                clientId: audience,
                nonce: nonce,
                responseUri: msg.params.responseUri ?? "",
                verifierJwkThumbprint: msg.params.verifierJwkThumbprint
            )
            let result = try await system.generateProof(
                spec: spec,
                document: .mdoc([UInt8](credBytes)),
                sessionTranscript: sessionTranscript,
                requestedClaims: ref.disclosedClaims ?? [],
                verifierIdentity: verifierIdentity,
                signer: { algorithm, data in
                    // The signer carries an algorithm so a system needing a
                    // key this keystore cannot produce fails here rather
                    // than getting a signature over the wrong curve.
                    guard algorithm == coseAlgES256 else {
                        throw SirosError.wallet(message: "This keystore signs ES256 only, proof system asked for COSE alg \(algorithm)")
                    }
                    return [UInt8](try await self.keystore.sign(keyId: kid, payload: Data(data), algorithm: "ES256"))
                },
                priorState: nil
            )
            let zkDeviceResponse = try buildZkPresentationToken(
                credBytes: [UInt8](credBytes),
                docType: docType,
                spec: spec,
                disclosedClaimNames: ref.disclosedClaims ?? [],
                result: result
            )
            return Self.b64UrlEncode(zkDeviceResponse)
        } else if cred.format == "mso_mdoc" {
            // mDoc DeviceResponse (ISO 18013-5)
            guard let credBytes = Self.b64UrlDecode(cred.raw) else {
                throw SirosError.wallet(message: "Credential \(cred.id) has malformed base64url raw data")
            }
            let deviceResponse = try await keystore.signMdocPresentation(
                credentialBytes: credBytes,
                disclosedClaims: ref.disclosedClaims,
                nonce: nonce,
                audience: audience,
                responseUri: msg.params.responseUri ?? "",
                verifierJwkThumbprint: msg.params.verifierJwkThumbprint,
                kid: cred.kid
            )
            return deviceResponse.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        } else {
            // SD-JWT VP token with KB-JWT
            if let transactionData {
                return try await signTransactionVpToken(
                    credential: cred.raw,
                    disclosedClaims: ref.disclosedClaims,
                    nonce: nonce,
                    audience: audience,
                    transactionData: transactionData,
                    kid: transactionKid ?? cred.kid
                )
            }
            return try await keystore.signVpToken(
                credential: cred.raw,
                disclosedClaims: ref.disclosedClaims,
                nonce: nonce,
                audience: audience,
                kid: cred.kid
            )
        }
    }

    /// Handle the `"credential_selection"` flow_progress step - the actual,
    /// live code path exercised by the redirect-flow (haip-vp://) protocol
    /// for credential matching + consent (confirmed empirically in the
    /// Kotlin SDK: its `matchRequests()`/`handleMatchRequest` collector never
    /// fires for this flow type - only this step does). The backend sends a
    /// DCQL query and verifier info in the flow_progress payload; this
    /// matches credentials locally, shows a consent UI via `eventListener`,
    /// caches the match results for the later `sign_presentation` step's ZK
    /// branch (see `pendingMatchResultsByFlow`'s doc comment), and responds
    /// with a `"consent"` or `"decline"` flow action. Mirrors Kotlin's
    /// `handleCredentialSelection` exactly.
    private func handleCredentialSelection(
        engine: WalletEngineSession,
        flowId: String,
        payload: [String: AnyCodable]?
    ) async {
        do {
            let dcqlQuery = payload?["dcql_query"]?.objectValue.map { anyCodableDictToAny($0) }

            let allCreds = await credentialStore.getAll()
            // Read only - do NOT remove. The later `sign_presentation` step
            // (`handleSignRequest` -> `validateAudience`) still needs this
            // entry - see `handleMatchRequest`'s identical comment.
            lock.lock(); let trustResult = lastTrustResults[flowId]; lock.unlock()

            // Deliberately not the raw payload's verifier.name/client_id
            // (an earlier version of this fix parsed that through
            // ClientIdScheme.parse(...).displayName instead): that raw
            // field is whatever the verifier itself claimed, unvalidated -
            // exactly what go-wallet-backend#401 stopped trusting/caching
            // for the consent screen. Only trustResult?.entityName is a
            // PDP-validated name; nil here lets PresentationConsentView's
            // labeled "Verified identity" fallback (trustResult.identifier)
            // render instead, matching handleMatchRequest's identical fix
            // (#167 review finding).
            let verifierName = trustResult?.entityName

            let selection = await matchAndSelectCredentials(
                dcqlQuery: dcqlQuery,
                allCreds: allCreds,
                verifierName: verifierName,
                trustResult: trustResult
            )
            let matchResults = selection.matchResults
            let selectedIds = selection.selectedIds

            // This (not handleMatchRequest's match_request collector) is the
            // code path actually exercised by the redirect-flow/haip-vp://
            // protocol this backend uses for the "credential_selection"
            // progress step - confirmed live in the Kotlin SDK: matchRequests()
            // never fires for this flow type. sign_presentation's ZK branch
            // needs this cached so it knows the originating query's
            // format/zkSystemTypes/ppidContext.
            lock.lock(); pendingMatchResultsByFlow[flowId] = matchResults; lock.unlock()

            // Nothing to present - because nothing matched, or because what
            // was selected can no longer be presented (the app is trusted to
            // return only ids it was offered, but shouldn't be the only thing
            // enforcing consumption - defense in depth). Only a user who was
            // shown a presentable credential and chose it not is a decline;
            // see `unpresentableAnswer`.
            if let answer = Self.unpresentableAnswer(dcqlQuery: dcqlQuery, selection: selection) {
                switch answer {
                case .noMatch(let reason):
                    engine.sendCredentialsMatched(flowId: flowId, matches: [], noMatchReason: reason)
                case .declined:
                    engine.sendFlowAction(flowId: flowId, action: "decline", payload: ["reason": .string("user_declined")])
                }
                return
            }

            var seenClaims = Set<String>()
            let requestedClaims = matchResults.flatMap { $0.requestedClaims.flatMap { $0 } }.filter { seenClaims.insert($0).inserted }
            await recordPresentation(PresentationRecord(
                id: randomUint32Id(),
                flowId: flowId,
                verifierName: verifierName,
                credentialIds: selectedIds,
                credentialNames: selectedIds.compactMap { id in allCreds.first(where: { $0.id == id })?.metadata?.name },
                requestedClaims: requestedClaims,
                timestamp: Int64(Date().timeIntervalSince1970 * 1000),
                zkProof: selection.zkProof
            ))

            let consentPayload = Self.buildConsentPayload(matchResults: matchResults, selectedIds: selectedIds, allCreds: allCreds)
            engine.sendFlowAction(flowId: flowId, action: "consent", payload: consentPayload)
        } catch {
            engine.sendFlowAction(
                flowId: flowId,
                action: "decline",
                payload: ["reason": .string("error: \(error.localizedDescription)")]
            )
        }
    }

    private func handleMatchRequest(engine: WalletEngineSession, msg: MatchRequestMessage) async {
        let allCreds = await credentialStore.getAll()
        lock.lock()
        // Read only - do NOT remove. The later `sign_presentation` step
        // (`handleSignRequest` -> `validateAudience`) still needs this
        // entry; credential selection (this handler) always runs before
        // signing in the engine's own step ordering, so removing it here
        // silently defeated `validateAudience`'s defense-in-depth check for
        // every presentation - it always saw a nil trust result and
        // no-op'd. `validateAudience` itself removes the entry once it's
        // actually consumed.
        let trustResult = lastTrustResults[msg.flowId]
        lock.unlock()

        // Deliberately NOT falling back to trustResult?.parsedScheme?.displayName
        // here (an earlier version of this fix did): verifierName must stay
        // nil when there's no PDP-validated display name, so the consent
        // screen can render its own labeled "Verified identity" fallback
        // (PresentationConsentView's verifiedIdentity) instead of silently
        // presenting a bare identifier as if it were a friendly declared
        // name - substituting it here made that UI branch unreachable in
        // practice, since trustResult.identifier (and so parsedScheme) is
        // set whenever a trust evaluation ran at all (#167 review finding).
        let verifierName = trustResult?.entityName

        // msg.dcqlQuery IS the DCQL query object directly (not nested under
        // its own "dcql_query" key) - a separate wire shape from
        // "credential_selection"'s flow_progress payload, which wraps it.
        let dcqlQuery = msg.dcqlQuery?.objectValue.map { anyCodableDictToAny($0) }
        let selection = await matchAndSelectCredentials(
            dcqlQuery: dcqlQuery,
            allCreds: allCreds,
            verifierName: verifierName,
            trustResult: trustResult
        )
        let matchResults = selection.matchResults
        let candidates = selection.candidates
        let selectedIds = selection.selectedIds

        // Cache for the later sign_presentation step's ZK branch - mirrors
        // handleCredentialSelection and Kotlin's matchRequests() collector,
        // which populates the same map for this transport's equivalent step.
        lock.lock(); pendingMatchResultsByFlow[msg.flowId] = matchResults; lock.unlock()

        // The app is trusted to only return IDs it was offered, but shouldn't
        // be the only thing enforcing consumption - re-validate here too
        // (defense in depth).
        guard selection.allSelectedEligible else {
            #if canImport(os)
            logger.error("Selected credential has no eligible copies remaining")
            #endif
            // Still answer: the engine's RequestMatch blocks on a match
            // response, so returning silently left it waiting for one that was
            // never coming.
            engine.sendMatchResponse(flowId: msg.flowId, matches: [], noMatchReason: Self.ineligibleSelectionReason)
            return
        }

        var seenClaims = Set<String>()
        let requestedClaims = matchResults.flatMap { $0.requestedClaims.flatMap { $0 } }.filter { seenClaims.insert($0).inserted }
        await recordPresentation(PresentationRecord(
            id: randomUint32Id(),
            flowId: msg.flowId,
            credentialIds: selectedIds,
            credentialNames: selectedIds.compactMap { id in
                candidates.first(where: { $0.id == id })?.metadata?.name
            },
            requestedClaims: requestedClaims,
            timestamp: Int64(Date().timeIntervalSince1970 * 1000),
            zkProof: selection.zkProof
        ))

        let matches: [CredentialMatch] = selectedIds.compactMap { id in
            guard let cred = candidates.first(where: { $0.id == id }) else { return nil }
            let queryId = matchResults.first(where: { result in result.candidates.contains(where: { $0.id == id }) })?.queryId
            // credentialId is the legacy engine wire-protocol identifier - a
            // separate, unverified backend contract distinct from
            // privatedata-spec's numeric StoredCredential.id, so it
            // deliberately stays String.
            return CredentialMatch(
                credentialQueryId: queryId,
                credentialId: String(cred.id),
                format: cred.format,
                vct: CredentialUtils.vctOf(cred)
            )
        }
        let noMatchReason = matches.isEmpty ? Self.answerForEmptySelection(dcqlQuery: dcqlQuery, selection: selection).reason : nil
        engine.sendMatchResponse(flowId: msg.flowId, matches: matches, noMatchReason: noMatchReason)
    }

    private func handleFlowProgress(engine: WalletEngineSession, msg: FlowProgressMessage) async {
        let payloadDict = msg.payload?.objectValue

        // Handle trust evaluation
        if msg.step == "evaluating_trust" || msg.step == "evaluating_verifier_trust" {
            if let payloadDict,
               payloadDict["trust_evaluation_required"]?.boolValue == true {
                let payload = anyCodableDictToAny(payloadDict)
                await handleTrustEvaluation(engine: engine, flowId: msg.flowId, payload: payload)
            }
        }

        // The engine's server-side issuer trust result (step="trust_evaluated",
        // payload.issuer_trust_evaluated=true) needs no response, and is no
        // longer cached here: nothing may stand in for an evaluation later (see
        // `TrustDecisionCache`). `WalletEngineSession` keeps it for the flow.

        // Handle credential selection — verifier wants credentials, user
        // must consent. This is the actual, live code path exercised by the
        // redirect-flow (haip-vp://) protocol - see
        // handleCredentialSelection's doc comment.
        if msg.step == "credential_selection" {
            await handleCredentialSelection(engine: engine, flowId: msg.flowId, payload: payloadDict)
        }

        // Handle authorization required
        if msg.step == "authorization_required" {
            if let payloadDict {
                let payloadType = payloadDict["type"]?.stringValue
                if payloadType == "tx_code" {
                    lock.lock(); let listener = eventListener; lock.unlock()
                    if let txCode = listener?.onTxCodeRequired(
                        flowId: msg.flowId,
                        description: payloadDict["message"]?.stringValue
                    ) {
                        engine.sendFlowAction(
                            flowId: msg.flowId,
                            action: "provide_pin",
                            payload: ["tx_code": .string(txCode)]
                        )
                    }
                } else {
                    if let authUrl = payloadDict["authorization_url"]?.stringValue {
                        let redirectUri = payloadDict["expected_redirect_uri"]?.stringValue ?? ""
                        let effectiveState = payloadDict["state"]?.stringValue
                            ?? URLComponents(string: authUrl)?.queryItems?.first(where: { $0.name == "state" })?.value
                            ?? ""

                        // Capture enough context to resume issuance via a fresh
                        // flow_start once the OAuth redirect returns - the
                        // original flow_id's WebSocket context may not survive
                        // the browser round-trip. See completeAuthorization.
                        let pending = PendingAuthorization(
                            offer: payloadDict["credential_offer"]?.stringValue,
                            credentialOfferUri: payloadDict["credential_offer_uri"]?.stringValue,
                            redirectUri: redirectUri,
                            codeVerifier: payloadDict["code_verifier"]?.stringValue,
                            state: effectiveState,
                            startEpoch: engine.startTag(forFlow: msg.flowId)
                        )
                        lock.lock()
                        pendingAuthorizations[msg.flowId] = pending
                        lock.unlock()

                        let rewrittenUrl = config.urlRewriter?(authUrl) ?? authUrl
                        lock.lock(); let listener = eventListener; lock.unlock()
                        listener?.onAuthorizationRequired(
                            flowId: msg.flowId,
                            authorizationUrl: rewrittenUrl,
                            redirectUri: redirectUri,
                            state: effectiveState
                        )
                    }
                }
            }
        }

        // Transition to FlowActive state
        let current = state
        switch current {
        case .ready(let userId, let displayName, let creds, _),
             .flowActive(let userId, let displayName, _, _, _, let creds):
            setState(.flowActive(
                userId: userId,
                displayName: displayName,
                flowId: msg.flowId,
                flowType: current.flowTypeForEngineProgress(flowId: msg.flowId, step: msg.step),
                status: msg.step,
                credentials: creds
            ))
        default:
            break
        }
    }

    /// Validates that the audience for VP signing matches the trusted verifier identity.
    ///
    /// Throws (rather than merely logging) on mismatch - confirmed the same
    /// gap exists in the Kotlin SDK's own validateAudience, found via code
    /// review: a mismatch was only ever printed as a warning, so
    /// handleSignRequest proceeded to sign and send the VP token regardless,
    /// defeating the audience-binding protection this function's name
    /// implies it provides.
    @discardableResult
    private func validateAudience(flowId: String, audience: String) throws -> TrustResult? {
        lock.lock()
        // Consume (remove) the entry here, at actual point of use, instead
        // of at credential-selection time - see `handleMatchRequest`'s
        // comment for why removing it earlier defeated this check entirely.
        let trustResult = lastTrustResults.removeValue(forKey: flowId)
        lock.unlock()

        guard let trustResult, let expectedId = trustResult.identifier else { return trustResult }
        if !audience.isEmpty && !expectedId.isEmpty && audience != expectedId {
            throw SirosError.wallet(message: "Audience mismatch for flow \(flowId): sign_request audience='\(audience)' != trusted identifier='\(expectedId)'")
        }
        return trustResult
    }

    /// Report a flow-terminating failure immediately (e.g. a keystore/WSCD
    /// exception, or an audience-mismatch, raised while handling a sign
    /// request) instead of leaving the flow to die silently until the
    /// engine's own reply timeout fires.
    ///
    /// Mirrors the Kotlin SDK's reportSignFailure, added after the same real
    /// FIDO2 CTAP2_ERR_PIN_INVALID bug was found via live hardware testing:
    /// handleSignRequest's catch block previously only logged
    /// (logger.error), so the engine waited indefinitely for a sign_response
    /// that would never arrive.
    func reportSignFailure(flowId: String, message: String, notifyError: Bool = true) {
        lock.lock()
        let listener = eventListener
        // The flow ends here: a buffered request for it is refused and a previously captured generation is stale.
        flowEndSeq[flowId, default: 0] += 1
        pendingMatchResultsByFlow.removeValue(forKey: flowId)
        legacyFlowSnapshots.removeValue(forKey: flowId)
        credentialResponseKeys.removeValue(forKey: flowId)
        decryptedCredentialResponses.removeValue(forKey: flowId)
        offeredResponseKeyFlows.remove(flowId)
        wmpFlowIssuanceEpochs.removeValue(forKey: flowId)
        lock.unlock()
        if notifyError { listener?.onFlowError(flowId: flowId, errorMessage: message, redirectUri: nil) }

        // A terminal path for whatever issuance may have been in flight - a
        // no-op for a presentation sign-request failure, which never sets
        // these fields in the first place. See `resetIssuanceGuards()`.
        resetIssuanceGuards()

        switch state {
        case .flowActive(let userId, let displayName, _, _, _, _),
             .ready(let userId, let displayName, _, _):
            Task {
                let creds = await credentialStore.getAll()
                setState(.ready(userId: userId, displayName: displayName, credentials: creds))
            }
        default:
            break
        }
    }

    /// A transaction waiting for the user belongs to its flow: once the flow
    /// has ended (error or completion) it must not go on to sign or record a
    /// consented outcome for a flow that no longer exists.
    func cancelTransactionTasks(flowId: String) {
        lock.lock()
        flowEndSeq[flowId, default: 0] += 1      // a task for this flow still being registered sees that it ended
        let doomed = transactionTasks.filter { $0.value.flowId == flowId }
        for key in doomed.keys { transactionTasks.removeValue(forKey: key) }
        // The flow's response key and anything decrypted with it end with the flow.
        credentialResponseKeys.removeValue(forKey: flowId)
        decryptedCredentialResponses.removeValue(forKey: flowId)
        offeredResponseKeyFlows.remove(flowId)
        wmpFlowIssuanceEpochs.removeValue(forKey: flowId)
        lock.unlock()
        for entry in doomed.values { entry.cancel() }
    }

    func handleFlowError(msg: FlowErrorMessage) {
        let fid = msg.flowId ?? "unknown"
        cancelTransactionTasks(flowId: fid)
        lock.lock()
        let listener = eventListener
        pendingMatchResultsByFlow.removeValue(forKey: fid)
        legacyFlowSnapshots.removeValue(forKey: fid)
        lock.unlock()
        let redirectUri = msg.error.details?["redirect_uri"]?.stringValue
        // This one error's details name the credential the user is missing, so
        // they reach the app structured rather than only inside `message`.
        // `onNoMatchingCredential` fires alongside, not instead of,
        // `onFlowError` - see its doc comment.
        if msg.error.code == EngineErrorCodes.noMatchingCredential {
            let details = Self.noMatchingCredentialDetails(error: msg.error)
            listener?.onNoMatchingCredential(flowId: fid, requestedTypes: details.requestedTypes, reason: details.reason, redirectUri: redirectUri)
        }
        listener?.onFlowError(flowId: fid, errorMessage: msg.error.message, redirectUri: redirectUri)

        // Terminal path for whatever issuance may have been in flight -
        // a no-op for a presentation flow error, which never sets these
        // fields. See `resetIssuanceGuards()`.
        resetIssuanceGuards()

        switch state {
        case .flowActive(let userId, let displayName, _, _, _, _),
             .ready(let userId, let displayName, _, _):
            Task {
                let creds = await credentialStore.getAll()
                setState(.ready(userId: userId, displayName: displayName, credentials: creds))
            }
        default:
            break
        }
    }

    // MARK: - Base64 helpers

    /// Convert AnyCodable dict to [String: Any] for internal use.
    private func anyCodableDictToAny(_ dict: [String: AnyCodable]?) -> [String: Any] {
        guard let dict else { return [:] }
        var result: [String: Any] = [:]
        for (k, v) in dict { result[k] = anyCodableToAny(v) }
        return result
    }

    private func anyCodableToAny(_ value: AnyCodable) -> Any {
        switch value {
        case .string(let s): return s
        case .int(let i): return i
        case .double(let d): return d
        case .bool(let b): return b
        case .object_(let obj): return anyCodableDictToAny(obj)
        case .array(let arr): return arr.map { anyCodableToAny($0) }
        case .null_: return NSNull()
        }
    }

    static func randomBytes(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBuffer(&bytes, count)
        return Data(bytes)
    }

    static func b64Encode(_ data: Data) -> String {
        data.base64EncodedString()
    }

    static func b64Decode(_ string: String) -> Data? {
        Data(base64Encoded: string)
    }

    static func b64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func b64UrlDecode(_ string: String) -> Data? {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }

    /// Cross-platform secure random bytes.
    // swiftlint:disable:next identifier_name
    private static func SecRandomCopyBuffer(_ buffer: inout [UInt8], _ count: Int) -> Int32 {
        #if canImport(Security)
        return SecRandomCopyBytes(kSecRandomDefault, count, &buffer)
        #else
        // Linux fallback
        guard let f = fopen("/dev/urandom", "r") else { return -1 }
        let read = fread(&buffer, 1, count, f)
        fclose(f)
        return read == count ? 0 : -1
        #endif
    }
}

extension SirosWallet {
    /// `wmp.flow.cancel` from the peer for a flow of its own: the flow's own cleanup, and the issuance guards only when
    /// the flow can be the issuance. An `oid4vp` parent being cancelled must not reset the guards, offer and attested key
    /// ids of an unrelated issuance that is in progress.
    func handleWmpFlowCancel(flowId: String, flowType: String?) {
        cancelTransactionTasks(flowId: flowId)
        discardCredentialResponseState(flowId: flowId)
        if flowType != "oid4vp" { resetIssuanceGuards() }
    }

    /// What the engine session reports when its connection is lost or replaced. The cleanup runs on its own task, never
    /// inside the callback: `forceReconnect` is called while the wallet holds its lock (the issuance start's commit), and
    /// the cleanup takes that lock. It is scoped to the engine that reported and to the keys that engine's earlier sockets
    /// created, so a key a replacement socket's request already advertised is left alone, and a late report from an
    /// engine that logout and a new login have replaced touches nothing.
    func installSocketReplacedHook(on engine: WalletEngineSession) {
        engine.onSocketReplaced = { [weak self, weak engine] in
            guard let self, let engine else { return }
            Task { self.cleanupAfterSocketReplacement(of: engine) }
        }
    }

    func cleanupAfterSocketReplacement(of engine: WalletEngineSession) {
        let current = engine.socketGeneration
        let id = ObjectIdentifier(engine)
        lock.lock(); defer { lock.unlock() }
        guard let live = engineSession, live === engine else { return }
        for (flowId, origin) in responseKeyOrigin where origin.engine == id && origin.generation < current {
            credentialResponseKeys.removeValue(forKey: flowId)
            decryptedCredentialResponses.removeValue(forKey: flowId)
            responseKeyOrigin.removeValue(forKey: flowId)
        }
    }
}
