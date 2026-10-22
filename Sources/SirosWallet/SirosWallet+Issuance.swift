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

#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

extension SirosWallet {
    // MARK: - Issuance

    /// Discover all available credentials across all visible issuers.
    ///
    /// Returns a flat list of `CredentialOffer` items ready for display in a
    /// picker UI. Each item can be passed to `startIssuanceByOffer`.
    public func getAvailableCredentials() async throws -> [CredentialOffer] {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else {
            throw SirosError.wallet(message: "Not connected")
        }

        // Step 1: Get issuers from backend
        let rawIssuers = try await client.getIssuers()
        let issuersData: Data
        if let dict = rawIssuers as? [[String: Any]] {
            issuersData = try JSONSerialization.data(withJSONObject: dict)
        } else if let obj = rawIssuers as? [String: Any],
                  let arr = obj["issuers"] as? [[String: Any]] ?? obj["data"] as? [[String: Any]] {
            issuersData = try JSONSerialization.data(withJSONObject: arr)
        } else {
            issuersData = try JSONSerialization.data(withJSONObject: rawIssuers)
        }
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        let issuers = (try? decoder.decode([IssuerEntry].self, from: issuersData))?.filter { $0.visible } ?? []

        // Step 2: For each issuer, fetch metadata and build offers
        var offers: [CredentialOffer] = []
        for issuer in issuers {
            do {
                let metaDict = try await client.getIssuerMetadata(id: Int(issuer.id))
                let metaData = try JSONSerialization.data(withJSONObject: metaDict)
                let metaDecoder = JSONDecoder()
                let metadata = try metaDecoder.decode(IssuerMetadata.self, from: metaData)

                for configId in metadata.credentialConfigurationsSupported.keys {
                    if let offer = Self.buildCredentialOffer(
                        issuerUrl: issuer.credentialIssuerIdentifier,
                        configId: configId,
                        metadata: metadata
                    ) {
                        offers.append(offer)
                    }
                }
            } catch {
                // Skip issuers that fail metadata fetch
                continue
            }
        }
        return offers
    }

    /// Build a `CredentialOffer` (display name/logo/colors) for one credential
    /// configuration from an issuer's already-fetched `IssuerMetadata`, reading
    /// the standard OID4VCI `credential_metadata.display` field (falling back
    /// to the issuer's own top-level `display`). Shared by
    /// `getAvailableCredentials` (lists every configuration a registered
    /// issuer supports) and `startIssuance` (resolves display metadata for the
    /// single configuration named in a scanned/deep-linked offer, including
    /// from issuers - e.g. interop test issuers - never registered with this
    /// wallet).
    ///
    /// Returns `nil` if `configId` isn't actually offered by this issuer.
    ///
    /// `static` (takes no wallet state) so it's unit-testable without
    /// constructing a full `SirosWallet`, which requires a keystore -
    /// unavailable in a plain Linux test run (see `KeystoreManager`'s
    /// CryptoKit-gated default).
    static func buildCredentialOffer(
        issuerUrl: String,
        configId: String,
        metadata: IssuerMetadata
    ) -> CredentialOffer? {
        guard let config = metadata.credentialConfigurationsSupported[configId] else { return nil }
        let issuerDisplay = metadata.display?.first
        let issuerName = issuerDisplay?.name
            ?? URL(string: issuerUrl)?.host
            ?? issuerUrl
        let credDisplay = config.credentialMetadata?.display?.first
        let credName = credDisplay?.name ?? configId

        return CredentialOffer(
            credentialConfigurationId: configId,
            credentialIssuerIdentifier: issuerUrl,
            credentialName: credName,
            credentialDescription: credDisplay?.description,
            issuerName: issuerName,
            backgroundColor: credDisplay?.backgroundColor ?? issuerDisplay?.backgroundColor,
            textColor: credDisplay?.textColor ?? issuerDisplay?.textColor,
            logoUri: credDisplay?.logo?.uri,
            issuerLogoUri: issuerDisplay?.logo?.uri,
            vct: config.vct,
            doctype: config.doctype,
            cryptographicBindingMethodsSupported: config.cryptographicBindingMethodsSupported ?? []
        )
    }

    /// Fetch an issuer's standard OID4VCI metadata directly by its URL (not
    /// via `apiClient`, which only knows issuers registered with this
    /// wallet's own backend) - needed to resolve display metadata for
    /// arbitrary/third-party issuers named in a scanned credential offer.
    // Not `private`: `SirosWallet+Renewal.swift`'s `renewCredential` needs
    // it too - same cross-file-extension-access reason as `keystore` above.
    func fetchIssuerMetadata(issuerUrl: String) async throws -> IssuerMetadata {
        let trimmed = issuerUrl.hasSuffix("/") ? String(issuerUrl.dropLast()) : issuerUrl
        guard let url = URL(string: trimmed + "/.well-known/openid-credential-issuer") else {
            throw SirosError.wallet(message: "Invalid issuer URL: \(issuerUrl)")
        }
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw SirosError.wallet(message: "Metadata fetch failed for \(issuerUrl)")
        }
        return try JSONDecoder().decode(IssuerMetadata.self, from: data)
    }

    /// Issuer metadata together with what the backend concluded about it.
    ///
    /// `entitlement` is nil when the backend was not consulted - see
    /// `resolveIssuerMetadata(issuerUrl:credentialTypes:)` - and a nil
    /// entitlement means "not checked", never "checked and fine".
    struct ResolvedIssuerMetadata {
        let metadata: IssuerMetadata
        let entitlement: IssuerEntitlement?
        let trusted: Bool?

        init(metadata: IssuerMetadata, entitlement: IssuerEntitlement? = nil, trusted: Bool? = nil) {
            self.metadata = metadata
            self.entitlement = entitlement
            self.trusted = trusted
        }
    }

    /// Resolve issuer metadata, preferring the backend so the document arrives
    /// authenticated rather than merely fetched.
    ///
    /// The backend verifies the `signed_metadata` JWS, evaluates the signer
    /// against the trust registry, and reports whether the provider is
    /// registered to issue `credentialTypes` (ARF section 6.6.2.3). Doing this
    /// wallet-side would mean a second certificate-handling implementation in
    /// every SDK language, kept in sync by hand.
    ///
    /// Falls back to `fetchIssuerMetadata(issuerUrl:)` when there is no
    /// authenticated session. That path returns metadata that is parsed but not
    /// authenticated, so `entitlement` is left nil and callers must not read
    /// the absence of findings as a pass.
    func resolveIssuerMetadata(
        issuerUrl: String,
        credentialTypes: [String] = []
    ) async throws -> ResolvedIssuerMetadata {
        lock.lock()
        let client = apiClient
        lock.unlock()

        if let client {
            do {
                let resolved = try await client.resolveIssuer(
                    issuerUrl: issuerUrl,
                    credentialTypes: credentialTypes
                )
                let context = resolved["context"] as? [String: Any]
                if let metadataJson = context?["trust_metadata"] as? [String: Any] {
                    let decoder = JSONDecoder()
                    let metadata = try decoder.decode(
                        IssuerMetadata.self,
                        from: JSONSerialization.data(withJSONObject: metadataJson)
                    )
                    var entitlement: IssuerEntitlement?
                    if let entJson = resolved["issuer_entitlement"] as? [String: Any] {
                        do {
                            entitlement = try decoder.decode(
                                IssuerEntitlement.self,
                                from: JSONSerialization.data(withJSONObject: entJson)
                            )
                        } catch {
                            #if canImport(os)
                            // A decision we cannot read is not a decision, so
                            // this stays nil - "not checked" - rather than
                            // becoming a refusal: rejecting a shape we do not
                            // understand would block legitimate issuance the
                            // moment the backend adds a field. But it must not
                            // be silent, because "not checked" and "checked and
                            // fine" are indistinguishable to everything
                            // downstream, and this is the one place that knows
                            // the difference was caused by a malformed response.
                            logger.warning(
                                "Issuer entitlement decision for \(issuerUrl) could not be decoded: \(error.localizedDescription)"
                            )
                            #endif
                        }
                    }
                    return ResolvedIssuerMetadata(
                        metadata: metadata,
                        entitlement: entitlement,
                        trusted: resolved["decision"] as? Bool
                    )
                }
            } catch {
                // A backend that is unreachable must not make issuance
                // impossible, but the caller has to be able to tell that the
                // checks did not run - hence a nil entitlement below.
            }
        }

        return ResolvedIssuerMetadata(metadata: try await fetchIssuerMetadata(issuerUrl: issuerUrl))
    }

    /// The backend's entitlement decision for one credential configuration, or
    /// nil if it could not be obtained.
    ///
    /// Nil means "not checked", and a check that could not run must not block
    /// issuance - the same distinction the backend draws between "revoked" and
    /// "could not determine". Making issuance depend on this round-trip
    /// succeeding would turn a backend outage into an outage for every issuer.
    func issuerEntitlementFor(issuerUrl: String, configurationId: String) async -> IssuerEntitlement? {
        do {
            return try await resolveIssuerMetadata(
                issuerUrl: issuerUrl,
                credentialTypes: [configurationId]
            ).entitlement
        } catch {
            return nil
        }
    }

    /// Refuse issuance when the backend says the provider is not registered to
    /// issue what it is offering.
    ///
    /// Warn mode reports findings while leaving `allowed` true, so this only
    /// throws when the deployment has asked it to.
    func enforceIssuerEntitlement(issuerUrl: String, entitlement: IssuerEntitlement?) throws {
        guard let entitlement, !entitlement.allowed else {
            return
        }
        let reasons = entitlement.findings
            .map { "\($0.code): \($0.message)" }
            .joined(separator: ", ")
        throw SirosError.wallet(
            message: "Issuer '\(issuerUrl)' is not registered to issue this credential: \(reasons)"
        )
    }

    /// Get (creating once, on first use) this wallet installation's persistent
    /// OAuth Client Attestation instance key ID - see
    /// `SessionStoreProtocol.instanceKeyId`.
    private func ensureInstanceKeyId() async throws -> String {
        if let existing = sessionStore.instanceKeyId {
            return existing
        }
        // First use has to be serialised. Two callers arriving together - an
        // engine `buildClientAuth` and a Devices listing, say - would otherwise
        // each generate an ES256 key and each persist it, and whichever lost
        // the race would already have published a WIA for a key the store no
        // longer names. The instance id the backend knows would then disagree
        // with the one this wallet proves, breaking later PoPs and
        // `isThisDevice`. Sharing one in-flight task gives every caller the
        // same key.
        //
        // Scoped to the account it is for: `instanceKeyId` is account-scoped
        // while this task is wallet-wide, so a logout/login that switches
        // accounts mid-generation must not hand the new account the old one's
        // task - nor let that task persist its key into the new account's
        // scope, which would attest the new account under the wrong lifecycle
        // identity.
        let account = sessionStore.activeAccountId
        lock.lock()
        if let inFlight = instanceKeyTask, instanceKeyTaskAccount == account {
            lock.unlock()
            return try await inFlight.value
        }
        let task = Task<String, Error> { [weak self] in
            guard let self else { throw SirosError.wallet(message: "Wallet released") }
            // Re-check under the task: a caller that lost the race above may
            // have persisted one already.
            if let existing = self.sessionStore.instanceKeyId { return existing }
            let keyId = try await self.keystore.generateKey(algorithm: "ES256")
            guard self.sessionStore.activeAccountId == account else {
                throw SirosError.wallet(
                    message: "Account changed while generating the wallet instance key"
                )
            }
            self.sessionStore.instanceKeyId = keyId
            return keyId
        }
        instanceKeyTaskToken &+= 1
        let token = instanceKeyTaskToken
        instanceKeyTask = task
        instanceKeyTaskAccount = account
        lock.unlock()
        defer {
            lock.lock()
            // Only clear it if it is still ours, so a failed generation can be
            // retried by the next caller rather than cached forever.
            if instanceKeyTaskToken == token {
                instanceKeyTask = nil
                instanceKeyTaskAccount = nil
            }
            lock.unlock()
        }
        return try await task.value
    }

    /// Obtain (fetching + caching, refreshing before expiry) a Wallet
    /// Instance Attestation for this wallet instance from this wallet's own
    /// backend (draft-ietf-oauth-attestation-based-client-auth-10 §3.1 /
    /// CS-04 §7.1.2): request a single-use challenge, sign a PoP JWT over it
    /// with the instance key, and exchange both for a WIA JWT.
    ///
    /// Best-effort: returns nil on any failure (network, backend not
    /// configured for WIA, etc.) rather than throwing - a missing/unavailable
    /// client attestation must never block issuance, since not every backend
    /// deployment enables this feature.
    // Not `private`: `SirosWallet.swift`'s `listWalletInstances()` needs it to
    // fill in `isThisDevice` - same cross-file-extension-access reason as
    // `cachedWia` itself.
    func ensureWalletInstanceAttestation() async -> String? {
        let now = Int(Date().timeIntervalSince1970)
        lock.lock(); let cached = cachedWia; let expiresAt = cachedWiaExpiresAt; lock.unlock()
        if let wia = cached, expiresAt - now > 60 {
            return wia
        }
        lock.lock()
        let client = apiClient
        // The session this attestation is being fetched for; see where it is
        // published below.
        let generation = sessionGeneration
        lock.unlock()
        guard let client else { return nil }
        do {
            let keyId = try await ensureInstanceKeyId()
            let challengeResponse = try await client.requestWIAChallenge()
            guard let challenge = challengeResponse["challenge"] as? String else { return nil }
            let pop = try await keystore.generateKeyProof(
                keyId: keyId,
                typ: "oauth-client-attestation-pop+jwt",
                // iss doesn't need to equal client_id for THIS PoP - it's
                // validated by our own backend (WIAService.validatePop only
                // checks iss is non-empty), unlike the per-issuer PoP built in
                // buildClientAttestationPoP. clientAttestationClientId() is
                // still a reasonable choice: consistent, and non-empty.
                issuer: clientAttestationClientId(),
                // Must match the backend's configured wallet_provider_uri, if
                // it enforces one (WIAService.validatePop only checks aud
                // when that's non-empty) - the base backend URL is the only
                // value discoverable client-side without a dedicated endpoint.
                audience: config.backendUrl,
                extraClaims: ["nonce": challenge]
            )
            // Best-effort, on its OWN try/catch (not the outer one): a
            // native-attestation failure must degrade to a plain
            // backend-attested WIA, not abort issuance entirely. No
            // WalletConfig field needed on iOS - unlike Play Integrity,
            // App Attest needs no host-app-supplied config beyond the Xcode
            // entitlement (a project-level setting), so this constructs the
            // provider directly whenever the platform/OS version supports it.
            #if canImport(DeviceCheck)
            var nativeAttestation: [String: Any]?
            let appAttestProvider = AppAttestProvider(
                loadPersistedKeyId: { [weak self] in self?.sessionStore.appAttestKeyId },
                savePersistedKeyId: { [weak self] in self?.sessionStore.appAttestKeyId = $0 }
            )
            if appAttestProvider.isAvailable {
                do {
                    let evidence = try await appAttestProvider.generateEvidence(challenge: challenge, keyId: keyId)
                    nativeAttestation = [
                        "type": evidence.type,
                        "token": evidence.token,
                        "key_id": evidence.keyId,
                        "challenge": evidence.challenge,
                    ]
                } catch {
                    // Best-effort - device capability/entitlement issues are
                    // common and expected (Simulator, no entitlement, key
                    // already attested this install) - but silent failures
                    // here are hard to diagnose in the field, so log them.
                    print("[SirosWallet] App Attest evidence generation failed, continuing without it: \(error)")
                    nativeAttestation = nil
                }
            }
            #else
            let nativeAttestation: [String: Any]? = nil
            #endif
            // draft-ietf-oauth-attestation-based-client-auth-10: "the sub
            // claim MUST specify client_id value of the OAuth Client" -
            // confirmed via a real geneva2026.mdoc.online conformance run
            // that flagged sub=<instance jkt> as a FAIL.
            let clientId = clientAttestationClientId()
            // Links this instance to the passkey it logs in with, so
            // suspending or revoking the instance also refuses login with
            // that passkey (SID-AUTH-06, go-wallet-backend#319).
            let linkedCredentialId = sessionStore.credentialId
            let wia: String
            do {
                wia = try await client.generateWIA(
                    pop: pop,
                    challenge: challenge,
                    clientId: clientId,
                    nativeAttestation: nativeAttestation,
                    credentialId: linkedCredentialId
                )
            } catch let error as SirosError
                where error.apiErrorCode == errorCredentialNotOwned && linkedCredentialId != nil {
                // The passkey this session recorded is not one of the caller's
                // own (a session store carried over from another account, a
                // passkey deleted server-side). The first link recorded for an
                // instance wins, so never guess a different id - drop the
                // stale one and let the instance be attested without a passkey
                // link rather than losing the attestation.
                guard case let .backendApi(code, _, _) = error, code == 403 else { throw error }
                print("[SirosWallet] Backend refused the recorded passkey link (CREDENTIAL_NOT_OWNED) — clearing it and retrying the attestation without it")
                sessionStore.credentialId = nil
                wia = try await client.generateWIA(
                    pop: pop,
                    challenge: challenge,
                    clientId: clientId,
                    nativeAttestation: nativeAttestation,
                    credentialId: nil
                )
            }
            let expiresAt = (CredentialUtils.parseJwtPayload(wia)?["exp"] as? Int) ?? (now + 300)
            lock.lock()
            // Only publish a WIA that still belongs to the session that asked
            // for it. This function performs several awaits, and a logout,
            // account switch or new login landing in that window resets the
            // cache; storing afterwards would make `thisInstanceId` and
            // `currentWalletInstanceId()` answer with the PREVIOUS account's
            // thumbprint for the new session. The caller still gets its own
            // result - it is only the cache that is refused.
            if sessionGeneration == generation {
                cachedWia = wia
                cachedWiaExpiresAt = expiresAt
            }
            lock.unlock()
            return wia
        } catch {
            return nil
        }
    }

    /// The wallet_instance_id to send with a Key Attestation request: the
    /// JWK Thumbprint (`cnf.jkt`) of the current session's WIA-issued
    /// instance key, but only when that WIA's `attestation_source` is a
    /// verified native platform attestation (ios_app_attest /
    /// android_play_integrity) - go-wallet-backend's KA trust gate clamps to
    /// K3 for anything else anyway, so there's no value in sending an ID
    /// that won't lift the clamp, and every other failure mode (no WIA, WIA
    /// disabled, non-native tier) must resolve to omitting the field exactly
    /// like today's pre-this-change behavior.
    ///
    /// Peeks the existing WIA cache only - deliberately does NOT call
    /// `ensureWalletInstanceAttestation()` (real Copilot-review finding:
    /// that would trigger a challenge+generateWIA network round trip, and
    /// retry it on every backend key-attestation attempt in deployments
    /// where WIA is unsupported/misconfigured, adding latency for a field
    /// that's optional in the first place). A WIA obtained earlier this
    /// session (e.g. during issuance) is still picked up; one that was
    /// never fetched simply omits the field, exactly like today's behavior.
    func currentWalletInstanceId() -> String? {
        let now = Int(Date().timeIntervalSince1970)
        let nativeAttestationSources: Set<String> = ["ios_app_attest", "android_play_integrity"]
        lock.lock(); let cached = cachedWia; let expiresAt = cachedWiaExpiresAt; lock.unlock()
        guard let wia = cached, expiresAt - now > 60,
              let payload = CredentialUtils.parseJwtPayload(wia),
              let source = payload["attestation_source"] as? String,
              nativeAttestationSources.contains(source) else { return nil }
        return instanceKeyThumbprint()
    }

    /// The JWK thumbprint of this installation's instance key - the id the
    /// backend registers this wallet instance under, and the value
    /// `currentWalletInstanceId()` sends as `wallet_instance_id`. Read from
    /// the `cnf.jkt` of the WIA this session already holds rather than
    /// recomputed, so it is exactly the id the backend knows. Nil when no
    /// unexpired WIA has been obtained yet. Exposed as `thisInstanceId`.
    func instanceKeyThumbprint() -> String? {
        let now = Int(Date().timeIntervalSince1970)
        lock.lock(); let cached = cachedWia; let expiresAt = cachedWiaExpiresAt; lock.unlock()
        guard let wia = cached, expiresAt - now > 60,
              let payload = CredentialUtils.parseJwtPayload(wia),
              let cnf = payload["cnf"] as? [String: Any],
              let jkt = cnf["jkt"] as? String else { return nil }
        return jkt
    }

    /// The OAuth `client_id` this wallet uses in OID4VCI/OID4VP flows.
    /// Mirrors go-wallet-backend's `OID4VCIHandler.clientID` default
    /// (`h.clientID = h.redirectURI`, OID4VCI §7.1's unregistered-client
    /// convention). Used as the WIA-request PoP's `iss` and as the fallback
    /// per-flow PoP `iss` when the engine's `request_attestation` carries no
    /// `issuer`; when it does, that value wins - it is the effective
    /// client_id for the flow, including any registered per-issuer override
    /// that is not visible client-side.
    private func clientAttestationClientId() -> String {
        config.redirectUri
    }

    /// Answer the engine's `request_attestation` sign request
    /// (go-wallet-backend `SignActionRequestAttestation`, sent from
    /// `OID4VCIHandler.Execute` once issuer metadata has been resolved and
    /// FlowStart carried no attestation of its own).
    ///
    /// The engine supplies exactly what the per-flow PoP must be bound to,
    /// so no client-side offer/metadata discovery is needed here:
    /// `params.audience` is the issuer's authorization server (the PoP
    /// `aud`, and the value the AS checks against its own issuer URL) and
    /// `params.issuer` is the flow's effective `client_id` (the PoP `iss`,
    /// which includes any registered per-issuer override that is invisible
    /// to the client). Falls back to `clientAttestationClientId()` only if
    /// the engine sent no issuer.
    ///
    /// Returns nil - meaning "send an empty sign_response so the flow
    /// proceeds without wallet attestation" - when no WIA is available, no
    /// audience was supplied, or PoP signing fails. Never throws: a missing
    /// attestation must never block issuance, and an unanswered request
    /// would stall the engine for its 30 s sign timeout.
    // Not `private`: called from `SirosWallet+Engine.swift`'s sign-request
    // dispatcher and exercised directly by the test target.
    func clientAttestation(forEngineRequest params: SignRequestParams) async -> (String, String)? {
        guard let audience = params.audience, !audience.isEmpty else { return nil }
        guard let wia = await ensureWalletInstanceAttestation() else { return nil }
        let clientId: String
        if let issuer = params.issuer, !issuer.isEmpty {
            clientId = issuer
        } else {
            clientId = clientAttestationClientId()
        }
        // The audience IS the AS URL - the engine already resolved it
        // (`h.authServerIssuer`), so it goes straight through as the PoP `aud`.
        guard let pop = await buildClientAttestationPoP(asUrl: audience, clientId: clientId) else { return nil }
        return (wia, pop)
    }

    /// What one `sign_client_auth` request produced - see `buildClientAuth`.
    /// `keyId` is nil only when even naming the key failed, which the engine
    /// reads as "action unsupported" and falls back to its own DPoP key.
    struct ClientAuthMaterial {
        let keyId: String?
        let dpopProof: String?
        let wia: String?
        let pop: String?
    }

    /// `buildClientAuth` from the legacy transport's `SignRequestParams`.
    func buildClientAuth(flowId: String, params: SignRequestParams) async -> ClientAuthMaterial {
        await buildClientAuth(
            flowId: flowId,
            keyIdHint: params.keyId,
            audience: params.audience,
            issuer: params.issuer,
            htm: params.htm,
            htu: params.htu,
            dpopNonce: params.dpopNonce,
            ath: params.ath
        )
    }

    /// Produce the client authentication material the engine asked for in
    /// one `sign_client_auth` sign request (go-wallet-backend#317),
    /// transport-agnostic: the legacy `handleSignRequest` and the WMP
    /// `handleWmpSignRequest` both call this.
    ///
    /// The key is this wallet's instance key (`ensureInstanceKeyId`) - the
    /// same key `ensureWalletInstanceAttestation` binds as the WIA `cnf`, so
    /// the DPoP-bound token and the attestation are bound to one key (EC TS03
    /// §2.2.1.1). On a renewal the engine names the key it must be
    /// (`keyIdHint`, the `dpop_key_id` this wallet returned at issuance) and
    /// that is used instead. A DPoP proof is produced when `htm`/`htu` are
    /// given; a WIA and a **fresh** PoP (new `jti`, `aud` = `audience`) when
    /// `audience` is given. Never throws: whatever could not be produced is
    /// simply absent, and the engine decides what that means for the request
    /// it was building (a missing DPoP proof fails it; missing attestation
    /// proceeds unattested).
    func buildClientAuth(
        flowId: String,
        keyIdHint: String?,
        audience: String?,
        issuer: String?,
        htm: String?,
        htu: String?,
        dpopNonce: String?,
        ath: String?
    ) async -> ClientAuthMaterial {
        let clientId: String
        if let issuer, !issuer.isEmpty { clientId = issuer } else { clientId = clientAttestationClientId() }
        var keyId: String?
        var dpopProof: String?
        var wia: String?
        var pop: String?
        do {
            if let keyIdHint, !keyIdHint.isEmpty {
                keyId = keyIdHint
            } else {
                keyId = try await ensureInstanceKeyId()
            }
            if let htm, !htm.isEmpty, let htu, !htu.isEmpty, let signingKeyId = keyId {
                dpopProof = try await keystore.generateDPoPProof(
                    keyId: signingKeyId,
                    htm: htm,
                    htu: htu,
                    nonce: (dpopNonce?.isEmpty == false) ? dpopNonce : nil,
                    accessTokenHash: (ath?.isEmpty == false) ? ath : nil
                )
            }
            if let audience, !audience.isEmpty {
                wia = await ensureWalletInstanceAttestation()
                if wia != nil {
                    pop = await buildClientAttestationPoP(asUrl: audience, clientId: clientId)
                }
            }
        } catch {
            #if canImport(os)
            logger.warning("sign_client_auth for flow \(flowId, privacy: .public) failed part-way: \(error.localizedDescription)")
            #endif
        }
        let attested = wia != nil && pop != nil
        return ClientAuthMaterial(
            keyId: keyId,
            dpopProof: dpopProof,
            wia: attested ? wia : nil,
            pop: attested ? pop : nil
        )
    }

    /// Sign a fresh per-flow OAuth Client Attestation PoP
    /// (`typ: oauth-client-attestation-pop+jwt`) with this instance's key:
    /// `aud` = `asUrl` (the authorization server the PAR/token request goes
    /// to), `iss` = `clientId` (must equal the WIA's `sub` per
    /// draft-ietf-oauth-attestation-based-client-auth-10), plus a `challenge`
    /// claim when `asUrl` publishes a `challenge_endpoint` (see
    /// `fetchAttestationChallenge`). Used by the engine-requested
    /// `clientAttestation(forEngineRequest:)`; kept separate so a future
    /// caller that already knows the AS can sign a PoP without going through
    /// the sign-request params.
    ///
    /// Best-effort: returns nil on any failure rather than throwing.
    func buildClientAttestationPoP(asUrl: String, clientId: String) async -> String? {
        do {
            let challenge = await fetchAttestationChallenge(asUrl: asUrl)
            let keyId = try await ensureInstanceKeyId()
            var extraClaims: [String: String] = [:]
            if let challenge { extraClaims["challenge"] = challenge }
            return try await keystore.generateKeyProof(
                keyId: keyId,
                typ: "oauth-client-attestation-pop+jwt",
                issuer: clientId,
                audience: asUrl,
                extraClaims: extraClaims
            )
        } catch {
            return nil
        }
    }

    /// Fetch a fresh attestation challenge from `asUrl`'s own metadata-published
    /// `challenge_endpoint` (draft-ietf-oauth-attestation-based-client-auth-10
    /// §"Challenge Endpoint"), if it publishes one. Tries the OAuth 2.0
    /// Authorization Server Metadata well-known path (RFC 8414) first, falling
    /// back to the OIDC discovery path for ASes that only publish there.
    ///
    /// Returns nil (never throws) if the AS doesn't publish a challenge
    /// endpoint, or on any fetch failure - the `challenge` claim is optional
    /// per spec, so its absence must never block attestation entirely.
    private func fetchAttestationChallenge(asUrl: String) async -> String? {
        guard let metadata = await fetchOAuthServerMetadata(asUrl: asUrl),
              let challengeEndpoint = metadata["challenge_endpoint"] as? String,
              let url = URL(string: challengeEndpoint) else {
            return nil
        }
        do {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.httpBody = Data("{}".utf8)
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return json?["attestation_challenge"] as? String
        } catch {
            return nil
        }
    }

    private func fetchOAuthServerMetadata(asUrl: String) async -> [String: Any]? {
        let base = asUrl.hasSuffix("/") ? String(asUrl.dropLast()) : asUrl
        for path in ["/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"] {
            guard let url = URL(string: base + path) else { continue }
            do {
                let (data, response) = try await URLSession.shared.data(from: url)
                guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { continue }
                if let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    return json
                }
            } catch {
                // Try the next well-known path.
            }
        }
        return nil
    }

    /// Start issuance with a credential offer object.
    public func startIssuanceByOffer(_ offer: CredentialOffer) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        // ARF section 6.6.2.3: check the provider is registered to issue what
        // it offers before requesting it. Done before the in-flight flag is
        // taken, so a refusal cannot leave issuance wedged.
        try enforceIssuerEntitlement(
            issuerUrl: offer.credentialIssuerIdentifier,
            entitlement: await issuerEntitlementFor(
                issuerUrl: offer.credentialIssuerIdentifier,
                configurationId: offer.credentialConfigurationId
            )
        )

        lock.lock()
        if issuanceInFlight {
            lock.unlock()
            throw SirosError.wallet(message: "Another issuance is already in progress")
        }
        issuanceInFlight = true
        activeOffer = offer
        lock.unlock()
        do {

            // Try to fetch VCTM (SD-JWT) and MDDL schema (mdoc) - format-blind,
            // like `activeVctm`'s existing fetch: whichever one doesn't match
            // this offer's actual format simply fails to decode and stays nil.
            let vctmDocument = await vctmFetcher.fetchDocument(
                issuerUrl: offer.credentialIssuerIdentifier,
                scope: offer.credentialConfigurationId,
                vct: offer.vct,
                registryUrl: resolvedRegistryUrl
            )
            let vctm = vctmDocument?.vctm
            let mddlSchema = await mddlSchemaFetcher.fetch(
                issuerUrl: offer.credentialIssuerIdentifier,
                scope: offer.credentialConfigurationId,
                doctype: offer.doctype,
                registryUrl: resolvedRegistryUrl
            )
            lock.lock()
            activeVctm = vctm
            activeVctmDocument = vctmDocument
            activeMddlSchema = mddlSchema
            lock.unlock()

            var credOffer: [String: AnyCodable] = [
                "credential_issuer": .string(offer.credentialIssuerIdentifier),
                "credential_configuration_ids": .array([.string(offer.credentialConfigurationId)]),
            ]

            var grants: [String: AnyCodable] = [:]
            if let preAuth = offer.preAuthorizedCode {
                var preAuthGrant: [String: AnyCodable] = ["pre-authorized_code": .string(preAuth)]
                if offer.txCode != nil {
                    preAuthGrant["tx_code"] = .object_(["input_mode": .string("text")])
                }
                grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"] = .object_(preAuthGrant)
            } else {
                grants["authorization_code"] = .object_([:])
            }
            credOffer["grants"] = .object_(grants)

            let offerJson: String
            if let data = try? JSONEncoder().encode(credOffer),
               let s = String(data: data, encoding: .utf8) {
                offerJson = s
            } else {
                offerJson = "{}"
            }

            // Wallet attestation is engine-requested (`request_attestation`
            // sign request, answered in `handleSignRequest`) - nothing to
            // resolve or attach up front.
            engine.startIssuance(
                offer: offerJson,
                redirectUri: config.redirectUri.isEmpty ? nil : config.redirectUri,
                authorizationDetails: authorizationDetailsForActiveOffer()
            )
        } catch {
            // A synchronous start failure here means the flow was never
            // registered server-side, so nothing will ever clear the guard
            // via the normal flow_complete/flow_error path - without this,
            // every future issuance attempt would be permanently blocked.
            resetIssuanceGuards()
            throw error
        }
    }

    /// Start issuance with a raw offer URI or JSON.
    /// The OID4VCI `authorization_details` to start this issuance with, from
    /// the offer already resolved into `activeOffer`.
    ///
    /// DIIP requires a Wallet to be able to ask for a credential configuration
    /// this way as well as by `scope`. This SDK never builds the Authorization
    /// Request - the engine does, for every transport - so the wallet states
    /// the intent and the engine forwards it (see
    /// ``FlowStartMessage/authorizationDetails``). wallet-frontend makes the
    /// same split for the same reason, and the two have to agree: same engine,
    /// same issuers.
    ///
    /// Nil when the offer could not be resolved, which leaves the `scope` path
    /// exactly as it was.
    func authorizationDetailsForActiveOffer() -> [AuthorizationDetail]? {
        // Snapshotted under `lock` (review finding): `activeOffer` is mutated
        // under `lock` by `startIssuance`/renewal/reset, and this is read
        // from the async proof-generation path, which can race one of those.
        lock.lock(); let configurationId = activeOffer?.credentialConfigurationId; lock.unlock()
        return AuthorizationDetails.build(credentialConfigurationID: configurationId)
    }

    public func startIssuance(offerUri: String) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        lock.lock()
        if issuanceInFlight {
            lock.unlock()
            throw SirosError.wallet(message: "Another issuance is already in progress")
        }
        issuanceInFlight = true
        lock.unlock()
        do {
            if let offer = await resolveOfferForDisplay(offerUri) {
                lock.lock(); activeOffer = offer; lock.unlock()
                let vctmDocument = await vctmFetcher.fetchDocument(
                    issuerUrl: offer.credentialIssuerIdentifier,
                    scope: offer.credentialConfigurationId,
                    vct: offer.vct,
                    registryUrl: resolvedRegistryUrl
                )
                let vctm = vctmDocument?.vctm
                let mddlSchema = await mddlSchemaFetcher.fetch(
                    issuerUrl: offer.credentialIssuerIdentifier,
                    scope: offer.credentialConfigurationId,
                    doctype: offer.doctype,
                    registryUrl: resolvedRegistryUrl
                )
                lock.lock()
                activeVctm = vctm
                activeVctmDocument = vctmDocument
                activeMddlSchema = mddlSchema
                lock.unlock()
            }
            // Wallet attestation is engine-requested (`request_attestation`
            // sign request, answered in `handleSignRequest`): the engine
            // resolves the offer and the issuer's authorization server itself
            // and tells us the exact PoP audience/client_id, so there is no
            // second client-side fetch of the offer or metadata for it here.
            switch IssuanceStart.resolve(offerUri: offerUri) {
            case .offer(let offer):
                engine.startIssuance(
                    offer: offer,
                    authorizationDetails: authorizationDetailsForActiveOffer()
                )
            case .credentialOfferUri(let uri):
                engine.startIssuance(
                    credentialOfferUri: uri,
                    authorizationDetails: authorizationDetailsForActiveOffer()
                )
            }
        } catch {
            // A synchronous start failure here means the flow was never
            // registered server-side, so nothing will ever clear the guard
            // via the normal flow_complete/flow_error path - without this,
            // every future issuance attempt would be permanently blocked.
            resetIssuanceGuards()
            throw error
        }
    }

    /// Just enough of a raw `credential_offer` JSON object to resolve display
    /// metadata - `credential_issuer` and the first `credential_configuration_ids`
    /// entry.
    private struct RawCredentialOfferHeader: Decodable {
        let credentialIssuer: String
        let credentialConfigurationIds: [String]

        enum CodingKeys: String, CodingKey {
            case credentialIssuer = "credential_issuer"
            case credentialConfigurationIds = "credential_configuration_ids"
        }
    }

    /// Resolve display metadata (name/logo/colors) for a scanned/deep-linked
    /// credential offer, ahead of forwarding it to the engine.
    ///
    /// `activeOffer` was previously only ever set by `startIssuanceByOffer`
    /// (the picker-driven path from `getAvailableCredentials`) - the QR/
    /// deep-link entry point here never populated it, so every credential
    /// issued that way (mdoc or SD-JWT, ours or a third-party issuer's) was
    /// stored with no display metadata AND no recorded issuer/config
    /// identifiers at all (both derive from `activeOffer` at storage time),
    /// confirmed against a real geneva2026.mdoc.online mDL credential offer.
    ///
    /// Best-effort: returns `nil` on any failure (unparseable offer,
    /// unreachable issuer, issuer doesn't support the offered configuration)
    /// rather than throwing - a missing display must never block issuance
    /// itself.
    private func resolveOfferForDisplay(_ offerUri: String) async -> CredentialOffer? {
        guard let header = await extractOfferHeader(offerUri),
              let configId = header.credentialConfigurationIds.first else { return nil }
        do {
            let metadata = try await fetchIssuerMetadata(issuerUrl: header.credentialIssuer)
            return Self.buildCredentialOffer(issuerUrl: header.credentialIssuer, configId: configId, metadata: metadata)
        } catch {
            return nil
        }
    }

    /// Extract the raw `credential_offer` JSON object from any of the shapes
    /// `startIssuance` accepts.
    private func extractOfferHeader(_ offerUri: String) async -> RawCredentialOfferHeader? {
        // Same shape resolution as the engine dispatch in `startIssuance`, so
        // whatever starts issuance also yields its display metadata.
        switch IssuanceStart.resolve(offerUri: offerUri) {
        case .offer(let offer):
            // Inline offer JSON (unpacked from a query parameter, or the raw
            // object itself). A URI the engine is left to interpret is not
            // JSON and decodes to nothing.
            guard let data = offer.data(using: .utf8) else { return nil }
            return try? JSONDecoder().decode(RawCredentialOfferHeader.self, from: data)
        case .credentialOfferUri(let uri):
            return await fetchOfferHeader(uri)
        }
    }

    private func fetchOfferHeader(_ uri: String) async -> RawCredentialOfferHeader? {
        guard let url = URL(string: uri) else { return nil }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { return nil }
            return try? JSONDecoder().decode(RawCredentialOfferHeader.self, from: data)
        } catch {
            return nil
        }
    }

    /// Start a presentation flow.
    public func startPresentation(requestUri: String) async throws {
        guard let engine = engineSession else {
            throw SirosError.wallet(message: "Not connected")
        }
        try await ensureEngineConnected(engine)
        // Snapshot at flow start: a flag flip applies to the next flow only.
        let declare = snapshotTransactionDataEnablement()
        engine.startPresentation(
            requestUri: requestUri,
            features: TransactionDataDeclaration.engineFeatures(enabled: declare)
        )
    }
}

/// How a credential-offer URI handed to `SirosWallet.startIssuance(offerUri:)`
/// reaches the engine. Pure, so the mapping is testable without a connection.
///
/// The engine's own `startIssuance(offer:)` strips the `credential_offer`
/// query parameter for exactly one scheme, lowercase `openid-credential-offer`.
/// Every other carrier of an offer - `haip-vci://`, an issuer's `https://`
/// wallet-redirect page, an upper-cased scheme from a QR code - has to be
/// unpacked here, or the whole URI is sent as if it were the offer JSON and
/// issuance fails on the engine side. So the query parameters decide first,
/// regardless of scheme; what remains is either a fetchable `https://` offer
/// URI or something the engine is trusted to interpret itself.
public enum IssuanceStart: Equatable {
    /// `engine.startIssuance(offer:)` - inline offer JSON, or a URI the engine unpacks.
    case offer(String)
    /// `engine.startIssuance(credentialOfferUri:)` - the engine fetches it.
    case credentialOfferUri(String)

    public static func resolve(offerUri: String) -> IssuanceStart {
        let components = URLComponents(string: offerUri)
        let queryItems = components?.queryItems ?? []
        func queryValue(_ name: String) -> String? {
            queryItems.first(where: { $0.name == name })?.value
        }
        if let credentialOffer = queryValue("credential_offer") {
            return .offer(credentialOffer)
        }
        if let credentialOfferUri = queryValue("credential_offer_uri") {
            return .credentialOfferUri(credentialOfferUri)
        }
        let scheme = components?.scheme?.lowercased()
        if scheme == "https" || scheme == "http" {
            return .credentialOfferUri(offerUri)
        }
        return .offer(offerUri)
    }
}
