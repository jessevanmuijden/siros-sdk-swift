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

extension SirosWallet {
    /// The final payload to hand back to the OS/browser for a W3C Digital
    /// Credentials API presentation - the platform's own credential-provider
    /// bridge (Android's `PendingIntentHandler`, or the equivalent wherever
    /// iOS eventually wires up native DC API OS integration - a separate,
    /// larger, already-tracked gap, not addressed here) wraps `responseJson`
    /// as the `DigitalCredential`'s response data.
    ///
    /// For `response_mode=dc_api` (unencrypted): `{"vp_token": {...}}`.
    /// For `response_mode=dc_api.jwt`: `{"response": "<jwe-compact>"}` per
    /// OpenID4VP 1.0 Appendix A.3.2.
    public struct DCAPIPresentationResult: Sendable {
        public let responseJson: String
        public let credentialIds: [Int64]

        public init(responseJson: String, credentialIds: [Int64]) {
            self.responseJson = responseJson
            self.credentialIds = credentialIds
        }
    }

    /// Process an incoming W3C Digital Credentials API (DC API) OpenID4VP
    /// presentation request entirely client-side - mirrors the Kotlin SDK's
    /// `handleDCAPIRequest` architecture rather than the
    /// `startPresentation`/engine-relay pattern: there is no
    /// `WalletEngineSession` involvement and no DC-API-specific backend call.
    /// The only backend calls made are the SAME generic trust-evaluation
    /// (`evaluateTrustDirect`) and presentation-history persistence the
    /// redirect flow already uses.
    ///
    /// - Parameters:
    ///   - rawRequestJson: the raw request data string from the OS/browser -
    ///     either a raw OpenID4VP request JSON object (unsigned protocol
    ///     variant) or `{"request": "<JWT>"}` (signed/multisigned JAR variant).
    ///   - origin: the browser/page origin that made the
    ///     `navigator.credentials.get()` call, as verified by the platform -
    ///     NOT read from the request body, which is untrusted until the
    ///     platform attests it.
    /// - Throws: `DCAPIRequestException` if the request is malformed or (for
    ///   the signed variant) fails JWS verification; `SirosError.wallet` if
    ///   no credential in the wallet is eligible to satisfy it.
    public func handleDCAPIRequest(rawRequestJson: String, origin: String) async throws -> DCAPIPresentationResult {
        let request = try DCAPIRequestParser.parse(rawRequestJson)
        // The account this request belongs to is fixed BEFORE the first await (trust evaluation, credential load).
        let accountGeneration = currentAccountGeneration()
        // EC TS12: a request carrying `transaction_data` must never be
        // answered as if it did not. Unless TS12 handling is in effect (flag
        // on and a consent handler registered) it is refused before anything
        // is matched or signed (OpenID4VP error `invalid_transaction_data`).
        if request.hasTransactionData {
            guard transactionDataEffectivelyEnabled else {
                let refusal = TransactionDataError(.disabled, detail: "DC API request carries transaction_data and TS12 handling is not in effect")
                await logPreparatoryRefusal(refusal, rawEntries: request.transactionData ?? [], verifier: origin)
                throw SirosError.transactionData(refusal)
            }
            guard request.transactionData != nil else {
                let refusal = TransactionDataError(.invalidEntry, detail: "transaction_data is not an array of strings")
                await logPreparatoryRefusal(refusal, rawEntries: [], verifier: origin)
                throw SirosError.transactionData(refusal)
            }
        }
        let trustResult = try await resolveDCAPITrust(request: request, origin: origin)

        let allCreds = await credentialStore.getAll()
        let selection = try dcapiSelectCandidates(request: request, allCreds: allCreds)
        let matchResults = selection.matchResults
        let selectedIds = selection.selectedIds

        // "origin:<value>" per OpenID4VP 1.0 Appendix A is only used for the
        // VP token audience claim at signing time - trust evaluation above
        // uses the bare origin.
        let audience = "origin:\(origin)"
        let (encryptionJwk, encryptionThumbprint) = try dcapiResolveEncryption(request: request)
        // The consent wait is a tracked task, so a logout cancels it; the account is checked before the plan
        // is built (the trust and credential awaits above may have spanned a switch), after consent and after signing.
        if request.hasTransactionData { try requireSameAccount(accountGeneration) }
        let verifierLabel = Self.transactionVerifierLabel(trust: trustResult, fallback: origin, origin: origin)
        // (A request without `transaction_data` takes none of this: its behaviour is unchanged.)
        let scaPlan: ScaPlan? = request.hasTransactionData
            ? try await trackedTransaction(flowId: "dc-api-\(UUID().uuidString)") {
                try await self.dcapiTransactionPlan(request: request, selection: selection, allCreds: allCreds, verifier: verifierLabel)
            }
            : nil
        do { if scaPlan != nil { try requireSameAccount(accountGeneration) } } catch {
            if !(error is CancellationError) { await scaPlan?.plan.complete(signed: false) }
            throw error
        }

        let finalResponseJson: String
        do {
            let (tokensByQueryId, queryIdOrder) = try await dcapiSignTokens(
                selectedIds: selectedIds,
                matchResultByCredentialId: selection.matchResultByCredentialId,
                allCreds: allCreds,
                origin: origin,
                audience: audience,
                request: request,
                encryptionThumbprint: encryptionThumbprint,
                transactionBindings: scaPlan?.bindings ?? [:],
                transactionKids: scaPlan?.kids ?? [:]
            )
            // After the final signing await: nothing is returned for an ended request or another account.
            if scaPlan != nil { try requireSameAccount(accountGeneration) }
            var vpTokenObj: [String: Any] = [:]
            for queryId in queryIdOrder {
                vpTokenObj[queryId] = tokensByQueryId[queryId] ?? []
            }
            finalResponseJson = try dcapiBuildResponseEnvelope(
                request: request,
                vpTokenObj: vpTokenObj,
                encryptionJwk: encryptionJwk
            )
        } catch {
            if !(error is CancellationError) { await scaPlan?.plan.complete(signed: false) }
            throw error
        }
        // The user's consent is recorded now that the presentation exists.
        await scaPlan?.plan.complete(signed: true)
        // The awaits above can span a logout or an account switch: do not hand one account's response to another.
        if scaPlan != nil { try requireSameAccount(accountGeneration) }

        var seenClaims = Set<String>()
        let requestedClaims = matchResults.flatMap { $0.requestedClaims.flatMap { $0 } }.filter { seenClaims.insert($0).inserted }

        await recordPresentation(PresentationRecord(
            id: randomUint32Id(),
            flowId: "dc-api-\(UUID().uuidString)",
            verifierName: trustResult.entityName,
            credentialIds: selectedIds,
            credentialNames: selectedIds.compactMap { id in allCreds.first(where: { $0.id == id })?.metadata?.name },
            requestedClaims: requestedClaims,
            timestamp: Int64(Date().timeIntervalSince1970 * 1000),
            zkProof: selectedIds.contains(where: { selection.zkRequestedIds.contains($0) })
        ))

        return DCAPIPresentationResult(responseJson: finalResponseJson, credentialIds: selectedIds)
    }

    /// Evaluate (and enforce) trust for the DC API request's verifier -
    /// split out of `handleDCAPIRequest` to keep that function's complexity
    /// within `type_body_length`'s function-level limits.
    private func resolveDCAPITrust(request: DCAPIRequest, origin: String) async throws -> TrustResult {
        // request.clientId is only cryptographically bound to anything when
        // the request is signed (keyMaterial != nil, verified against the
        // JWS header's own key in DCAPIRequestParser) - for the unsigned
        // variant it's just a caller-supplied field in the untrusted request
        // body. Using it there let a malicious page set client_id to some
        // other, possibly-whitelisted verifier's identity and have trust
        // (and presentation history) evaluated against that spoofed identity
        // instead of the platform-attested origin.
        let subjectId = request.keyMaterial != nil ? (request.clientId ?? origin) : origin
        let trustResult: TrustResult
        do {
            trustResult = try await evaluateTrustDirect(
                subjectId: subjectId,
                subjectType: "credential_verifier",
                keyMaterialType: request.keyMaterial?.x5c != nil ? "x5c" : (request.keyMaterial?.jwk != nil ? "jwk" : nil),
                x5c: request.keyMaterial?.x5c,
                jwk: request.keyMaterial?.jwk,
                context: nil
            )
        } catch {
            trustResult = trustCache.get(identifier: subjectId)
                ?? TrustResult(trusted: false, reason: error.localizedDescription, identifier: subjectId)
        }

        // Unlike the QR/redirect flow, there is no engine round-trip here to
        // gate on (trust is evaluated and enforced entirely wallet-side) - a
        // request from an untrusted or trust-eval-failed verifier must be
        // rejected before any credential is matched or signed, not merely
        // have its trust result computed and ignored.
        guard trustResult.trusted else {
            throw SirosError.wallet(message: "Verifier '\(subjectId)' is not trusted: \(trustResult.reason ?? "no reason given")")
        }
        return trustResult
    }

    /// What `dcapiSelectCandidates` resolves once, up front, so every later
    /// step of `handleDCAPIRequest` (eligibility, token signing, the history
    /// record) agrees on which query governs each credential.
    struct DCAPISelection {
        let matchResults: [CredentialMatcher.MatchResult]
        /// Which query result actually governs each candidate - the same
        /// first-match selection `dcapiSignTokens` uses when building
        /// tokens (a credential id can appear as a candidate under more than
        /// one query, e.g. one plain and one "mso_mdoc_zk", so this must be
        /// resolved once and reused everywhere rather than re-derived with
        /// different semantics in different places).
        let matchResultByCredentialId: [Int64: CredentialMatcher.MatchResult]
        /// Candidates that will actually be presented as a ZK proof (vs a
        /// raw disclosure) for THIS request - see `zkRequestedIds(...)`.
        let zkRequestedIds: Set<Int64>
        let selectedIds: [Int64]
    }

    /// Which candidates will be presented as a ZK proof rather than
    /// disclosed, given the first-match query per credential id - a
    /// credential's stored format is always plain "mso_mdoc" even under a
    /// ZK query (see `CredentialMatcher.matchesFormat`), so this must come
    /// from the MATCHED query's format, not the candidate's own. Derived from
    /// the first-match query per id, not from "is this id a candidate under
    /// ANY zk query" - a credential that also matches some other, non-zk
    /// query first would otherwise be wrongly marked zk here even though the
    /// token-building/consent step (which also uses first-match) will
    /// actually raw-disclose it. Feeds `eligibleInstances(from:isZkPresentation:)`
    /// so `CredentialConsumptionPolicy.consumeNonZkp` actually distinguishes
    /// the two, per that policy's own doc comment, and the recorded
    /// `PresentationRecord.zkProof`. Shared by the DC API and both engine
    /// selection paths so the three never disagree.
    static func zkRequestedIds(
        matchResultByCredentialId: [Int64: CredentialMatcher.MatchResult]
    ) -> Set<Int64> {
        Set(matchResultByCredentialId.compactMap { id, result in
            guard let format = result.format, CredentialUtils.isZkpFormat(format) else { return nil }
            return id
        })
    }

    /// First-match query per candidate id, in `matchResults` order (the same
    /// order as the request's own `credentials` array) - see
    /// `DCAPISelection.matchResultByCredentialId`.
    static func firstMatchByCredentialId(
        candidates: [StoredCredential],
        matchResults: [CredentialMatcher.MatchResult]
    ) -> [Int64: CredentialMatcher.MatchResult] {
        // One pass over the results in request order; the first result to
        // name an id wins and later ones are skipped, which is the
        // first-match rule stated in terms of the query list rather than a
        // per-candidate search back through it.
        let wanted = Set(candidates.map(\.id))
        var byId: [Int64: CredentialMatcher.MatchResult] = [:]
        for result in matchResults {
            for candidate in result.candidates where wanted.contains(candidate.id) && byId[candidate.id] == nil {
                byId[candidate.id] = result
            }
        }
        return byId
    }

    /// DCQL-match, dedupe, and apply the credential-consumption eligibility
    /// filter for a DC API request - split out of `handleDCAPIRequest`, see
    /// that function's doc comment for the overall flow.
    private func dcapiSelectCandidates(
        request: DCAPIRequest,
        allCreds: [StoredCredential]
    ) throws -> DCAPISelection {
        let dcqlOutput: CredentialMatcher.DcqlMatchOutput
        if let dcqlQuery = request.dcqlQuery {
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
        let candidates = matchResults.flatMap { $0.candidates }.filter { cred in
            guard !seenIds.contains(cred.id) else { return false }
            seenIds.insert(cred.id)
            return true
        }

        let matchResultByCredentialId = Self.firstMatchByCredentialId(candidates: candidates, matchResults: matchResults)
        let zkRequestedIds = Self.zkRequestedIds(matchResultByCredentialId: matchResultByCredentialId)

        // Unlike the QR/redirect flow, credential selection and consent
        // already happened natively - the OS's own credential picker showed
        // the matching registered entries and the user picked one before
        // this call was ever reached. Routing through eventListener's
        // interactive onCredentialSelectionRequired here would suspend
        // waiting for an in-app consent screen that this headless flow
        // never shows.
        let eligible = eligibleInstances(from: candidates, isZkPresentation: { zkRequestedIds.contains($0.id) })
        let selectedIds = eligible.map(\.id)

        if selectedIds.isEmpty {
            throw SirosError.wallet(message: candidates.isEmpty
                ? "No credential in the wallet matches the request"
                : "No eligible copies of the requested credential remain - renew it to get more"
            )
        }
        return DCAPISelection(
            matchResults: matchResults,
            matchResultByCredentialId: matchResultByCredentialId,
            zkRequestedIds: zkRequestedIds,
            selectedIds: selectedIds
        )
    }

    /// Resolve the verifier's response-encryption key (for `dc_api.jwt`) and
    /// its JWK thumbprint - split out of `handleDCAPIRequest`.
    private func dcapiResolveEncryption(request: DCAPIRequest) throws -> (jwk: [String: Any]?, thumbprint: String?) {
        var encryptionJwk: [String: Any]?
        if request.responseMode == "dc_api.jwt" {
            guard let jwk = Self.findEncryptionJwk(request.clientMetadata) else {
                throw SirosError.wallet(message: "dc_api.jwt response_mode requires client_metadata.jwks with an encryption key")
            }
            encryptionJwk = jwk
        }
        // `DCAPIResponseEncryption` is entirely CryptoKit-gated (Apple
        // platforms only, matching this module's existing convention e.g.
        // `EncryptedContainer`) - `nil` here on an unsupported platform still
        // lets an unencrypted `dc_api` presentation proceed; `dc_api.jwt`
        // itself is rejected below with a clear error instead.
        var encryptionThumbprint: String?
        #if canImport(CryptoKit)
        encryptionThumbprint = encryptionJwk.flatMap { DCAPIResponseEncryption.jwkThumbprint($0) }
        #endif
        return (encryptionJwk, encryptionThumbprint)
    }

    /// Sign a VP token per selected credential (plain SD-JWT/mdoc, or the
    /// ZK-wrapped mdoc branch), grouped by DCQL query id - split out of
    /// `handleDCAPIRequest`, the largest single contributor to that
    /// function's original cyclomatic-complexity/length lint violations.
    private func dcapiSignTokens(
        selectedIds: [Int64],
        matchResultByCredentialId: [Int64: CredentialMatcher.MatchResult],
        allCreds: [StoredCredential],
        origin: String,
        audience: String,
        request: DCAPIRequest,
        encryptionThumbprint: String?,
        transactionBindings: [String: TransactionDataBinding] = [:],
        transactionKids: [String: String] = [:]
    ) async throws -> (tokensByQueryId: [String: [String]], queryIdOrder: [String]) {
        // Per OpenID4VP 1.0 (#response_parameters), vp_token's value for each
        // DCQL query id MUST be a JSON array of one or more Presentations -
        // even when `multiple` is omitted/false, the array MUST still
        // contain exactly one Presentation, never a bare string. A real bug,
        // confirmed via Multipaz's own server source
        // (multipaz-verifier-server's handleDcGetDataOpenID4VP does
        // `value.jsonArray.map{...}` for the openid4vp-v1-signed/-unsigned
        // protocol versions): putting a bare string here throws inside their
        // server and surfaces as an opaque HTTP 500.
        var tokensByQueryId: [String: [String]] = [:]
        var queryIdOrder: [String] = []
        for id in selectedIds {
            guard let cred = allCreds.first(where: { $0.id == id }) else { continue }
            // The same first-match query `dcapiSelectCandidates` already
            // resolved for eligibility and the zk flag - never re-derived
            // here, so the ZK-vs-raw decision can't drift between the two.
            let matchResult = matchResultByCredentialId[id]
            let queryId = matchResult?.queryId ?? "_default"
            let disclosedClaims = matchResult?.requestedClaims.compactMap(\.last)

            let token = try await dcapiSignSingleToken(
                cred: cred,
                matchResult: matchResult,
                disclosedClaims: disclosedClaims,
                origin: origin,
                audience: audience,
                request: request,
                encryptionThumbprint: encryptionThumbprint,
                transactionData: transactionBindings[queryId],
                transactionKid: transactionKids[queryId]
            )

            if tokensByQueryId[queryId] == nil {
                tokensByQueryId[queryId] = []
                queryIdOrder.append(queryId)
            }
            tokensByQueryId[queryId]?.append(token)
        }
        return (tokensByQueryId, queryIdOrder)
    }

    /// Sign one credential's VP token for the DC API response - the
    /// mso_mdoc_zk/mso_mdoc/default three-way branch factored out of
    /// `dcapiSignTokens`'s loop body.
    private func dcapiSignSingleToken(
        cred: StoredCredential,
        matchResult: CredentialMatcher.MatchResult?,
        disclosedClaims: [String]?,
        origin: String,
        audience: String,
        request: DCAPIRequest,
        encryptionThumbprint: String?,
        transactionData: TransactionDataBinding? = nil,
        transactionKid: String? = nil
    ) async throws -> String {
        if transactionData != nil, cred.format == "mso_mdoc" || matchResult?.format.map(CredentialUtils.isZkpFormat) == true {
            // The pipeline refuses non-SD-JWT credentials before this point.
            throw SirosError.transactionData(TransactionDataError(.unsupportedFormat))
        }
        if let format = matchResult?.format, CredentialUtils.isZkpFormat(format) {
            // ZK-wrapped mDoc presentation - see the shared
            // `buildZkPresentationToken` helper's doc comment.
            guard let credBytes = Self.b64UrlDecode(cred.raw) else {
                throw SirosError.wallet(message: "Credential \(cred.id) has malformed base64url raw data")
            }
            // cred.kid is commonly nil for a softkey-issued credential
            // with no explicit per-credential key binding (the plain,
            // non-ZK signing paths tolerate this via a similar
            // fallback) - keystore.sign() below needs an explicit key
            // id, so resolve the same default here rather than
            // treating a nil kid as "no key exists".
            guard let kid = cred.kid ?? keystore.listKeys().first?.keyId else {
                throw SirosError.wallet(message: "No signing key available for credential \(cred.id) - cannot generate a ZK proof for it")
            }
            let mdocDocument = try MdocCbor.parseStoredCredential([UInt8](credBytes))
            let docType = mdocDocument.docType
            // A circuit is compiled for a fixed attribute count, so the
            // verifier's zk_system_type list must be matched against how
            // many claims are actually being disclosed here.
            guard let (system, spec) = zkProofSystemRegistry.resolve(
                credentialType: CredentialTypeRef(format: .msoMdoc, typeId: docType),
                requestedSpecs: matchResult?.zkSystemTypes ?? [],
                numAttributes: disclosedClaims?.count ?? 0
            ) else {
                throw SirosError.wallet(message: "No registered ZK proof system satisfies the verifier's zk_system_type for \(docType)")
            }
            // Only bind a pseudonym when actually disclosed for this
            // query.
            let wantsPseudonym = disclosedClaims?.contains(zkPseudonymClaim) == true
            let verifierIdentity: VerifierIdentity? = wantsPseudonym
                ? VerifierIdentity(clientId: audience, ppidContext: matchResult?.ppidContext)
                : nil
            let sessionTranscript = MdocDeviceResponseBuilder.buildDCAPISessionTranscript(
                origin: origin,
                nonce: request.nonce,
                encryptionPublicJwkThumbprint: encryptionThumbprint
            )
            let result = try await system.generateProof(
                spec: spec,
                document: .mdoc([UInt8](credBytes)),
                sessionTranscript: sessionTranscript,
                requestedClaims: disclosedClaims ?? [],
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
                disclosedClaimNames: disclosedClaims ?? [],
                result: result
            )
            return Self.b64UrlEncode(zkDeviceResponse)
        } else if cred.format == "mso_mdoc" {
            guard let credBytes = Self.b64UrlDecode(cred.raw) else {
                throw SirosError.wallet(message: "Credential \(cred.id) has malformed base64url raw data")
            }
            let deviceResponse = try await keystore.signMdocPresentationForDCAPI(
                credentialBytes: credBytes,
                disclosedClaims: disclosedClaims,
                nonce: request.nonce,
                origin: origin,
                encryptionPublicJwkThumbprint: encryptionThumbprint,
                kid: cred.kid
            )
            return Self.b64UrlEncode(deviceResponse)
        } else {
            if let transactionData {
                return try await keystore.signVpToken(
                    credential: cred.raw,
                    disclosedClaims: disclosedClaims,
                    nonce: request.nonce,
                    audience: audience,
                    transactionData: transactionData,
                    kid: transactionKid ?? cred.kid
                )
            }
            return try await keystore.signVpToken(
                credential: cred.raw,
                disclosedClaims: disclosedClaims,
                nonce: request.nonce,
                audience: audience,
                kid: cred.kid
            )
        }
    }

    /// The TS12 plan for a DC API request carrying `transaction_data`; `nil`
    /// when it carries none. Runs the whole TS12 sequence (validation,
    /// consent, factors) before anything is signed.
    private func dcapiTransactionPlan(
        request: DCAPIRequest,
        selection: DCAPISelection,
        allCreds: [StoredCredential],
        verifier: String
    ) async throws -> ScaPlan? {
        guard request.hasTransactionData, let strings = request.transactionData else { return nil }
        // An empty nonce would sign a KB-JWT with no replay challenge.
        guard !request.nonce.isEmpty else {
            let refusal = TransactionDataError(.invalidEntry, detail: "a transaction presentation needs a non-empty nonce")
            await logPreparatoryRefusal(refusal, rawEntries: strings, verifier: verifier)
            throw SirosError.transactionData(refusal)
        }
        var sca = ScaSelection()
        // A query the transaction is bound to answers with exactly one credential; an
        // unbound query may answer with several (DC API presents an array per query).
        let boundQueries = TransactionDataPipeline.boundQueryIds(rawEntries: strings)
        for id in selection.selectedIds {
            guard let cred = allCreds.first(where: { $0.id == id }) else { continue }
            let queryId = selection.matchResultByCredentialId[id]?.queryId ?? "_default"
            let claims = selection.matchResultByCredentialId[id]?.requestedClaims.compactMap(\.last) ?? []
            if sca.credentials[queryId] != nil {
                guard !boundQueries.contains(queryId) else {
                    let refusal = TransactionDataError(.invalidEntry, detail: "more than one credential answers a query the transaction is bound to")
                    await logPreparatoryRefusal(refusal, rawEntries: strings, verifier: verifier)
                    throw SirosError.transactionData(refusal)
                }
                sca.additional.append(TransactionConsentAttributes(credentialName: Self.consentDisplayName(cred), claims: claims))
                sca.extraCredentials.append(cred)
                continue
            }
            sca.credentials[queryId] = cred
            sca.disclosed[queryId] = claims
        }
        do {
            return try await processTransactionData(
                entries: strings.map { TransactionDataEntryInput(raw: $0) },
                responseMode: request.responseMode,
                selection: sca,
                verifier: verifier,
                // The signed variant's JWS was verified by the parser.
                requestSigned: request.keyMaterial != nil
            )
        } catch let error as TransactionDataError {
            throw SirosError.transactionData(error)
        }
    }

    /// Build the final `{"protocol", "data"}` envelope JSON to hand back to
    /// the OS/browser, optionally JWE-encrypting the response for
    /// `dc_api.jwt` - split out of `handleDCAPIRequest`.
    private func dcapiBuildResponseEnvelope(
        request: DCAPIRequest,
        vpTokenObj: [String: Any],
        encryptionJwk: [String: Any]?
    ) throws -> String {
        var responseBody: [String: Any] = ["vp_token": vpTokenObj]
        // The verifier's only means of correlating this response back to the
        // right authorization session - the response arrives via the DC API
        // callback, a wholly separate channel from the original request,
        // with no other correlator available. Omitting this (a real bug:
        // request.state was parsed but never echoed back) left the verifier
        // decrypting a JWE it had no way to attribute to any session.
        if let state = request.state {
            responseBody["state"] = state
        }
        guard let responseBodyData = try? JSONSerialization.data(withJSONObject: responseBody),
              let responseBodyJson = String(data: responseBodyData, encoding: .utf8) else {
            throw SirosError.wallet(message: "Failed to serialize DC API response body")
        }

        let responseData: [String: Any]
        if request.responseMode == "dc_api.jwt", let encryptionJwk {
            #if canImport(CryptoKit)
            let jwe = try DCAPIResponseEncryption.encryptResponse(responseJson: responseBodyJson, verifierJwk: encryptionJwk)
            responseData = ["response": jwe]
            #else
            throw SirosError.wallet(message: "dc_api.jwt response encryption requires CryptoKit (unsupported on this platform)")
            #endif
        } else {
            responseData = responseBody
        }

        // The platform's own reference wallet
        // (https://github.com/digitalcredentialsdev/CMWallet) wraps its
        // response in this exact {"protocol": ..., "data": {...}} envelope
        // before handing it back - the mirror image of the {"requests":
        // [{"protocol", "data"}]} envelope the request itself arrives in
        // (see `DCAPIRequestParser`). Returning the bare `data` object on its
        // own leaves the platform with no declared protocol to associate the
        // response with.
        let finalResponse: [String: Any] = ["protocol": request.protocolIdentifier, "data": responseData]
        guard let finalResponseData = try? JSONSerialization.data(withJSONObject: finalResponse),
              let finalResponseJson = String(data: finalResponseData, encoding: .utf8) else {
            throw SirosError.wallet(message: "Failed to serialize DC API response envelope")
        }
        return finalResponseJson
    }

    /// Wraps a raw ZK proof result into the full `{version, status,
    /// zkDocuments: [...]}` DeviceResponse-shaped CBOR structure multipaz's
    /// own `DeviceResponseParser` requires (see
    /// `MdocDeviceResponseBuilder.buildZkDeviceResponse`'s doc comment). Bare
    /// proof bytes alone are not a valid `vp_token` entry - a verifier that
    /// understands this format silently shows nothing for one, since its
    /// parser never finds a `documents` or `zkDocuments` key at all. Shared
    /// by both ZK call sites (`handleDCAPIRequest` and the `sign_presentation`
    /// handler) since the wrapping logic is identical regardless of transport.
    // Not `private`: `SirosWallet+Engine.swift` needs it too - same
    // cross-file-extension-access reason as `keystore` above.
    func buildZkPresentationToken(
        credBytes: [UInt8],
        docType: String,
        spec: ZkSystemSpec,
        disclosedClaimNames: [String],
        result: ZkProofResult
    ) throws -> Data {
        let document = try MdocCbor.parseStoredCredential(credBytes)
        // The SAME docType-keyed, deterministic namespace lookup every mdoc
        // ZK proof system resolves a presentation's namespace through (see
        // `zkMdocNamespaceByDocType`'s own doc comment) - NOT
        // `nameSpaces.keys.first` (unspecified iteration order; a real mDL
        // can carry a second, jurisdiction-specific namespace alongside the
        // primary one). Using anything else here risks collecting THIS
        // function's digestIds/issuerSignedItemBytes/claimSlotDigestIds wire
        // metadata from a different namespace than the one the proof was
        // actually built from - confirmed as a real bug via Copilot review
        // on PR #182.
        guard let namespace = zkMdocNamespaceByDocType[docType] else {
            throw MdocError.malformed("mdoc credential has unsupported docType '\(docType)'")
        }
        guard let storedItems = document.issuerSigned.nameSpaces[namespace] else {
            throw MdocError.malformed("mdoc credential '\(docType)' has no disclosed '\(namespace)' namespace")
        }

        var disclosedClaims: [(String, CBOR)] = []
        // Vega-only wire metadata (see `buildZkDeviceResponse`'s own doc
        // comment on `digestIds`/`issuerSignedItemBytes`): harmless/unused
        // for a Longfellow presentation (positional matching, no slot
        // concept), so these two are populated for every disclosed claim
        // regardless of which system produced `result`.
        var digestIds: [String: UInt32] = [:]
        var issuerSignedItemBytes: [String: [UInt8]] = [:]
        for claimName in disclosedClaimNames {
            if claimName == zkPseudonymClaim {
                if let pseudonym = result.pseudonym {
                    disclosedClaims.append((claimName, .byteString(pseudonym)))
                }
            } else if let match = storedItems.first(where: { $0.item.elementIdentifier == claimName }) {
                disclosedClaims.append((claimName, match.item.elementValue))
                if let digestId = UInt32(exactly: match.item.digestId) {
                    digestIds[claimName] = digestId
                }
                issuerSignedItemBytes[claimName] = [UInt8](match.original.encode())
            }
        }

        // The Vega verifier needs the credential's FULL, fixed-shape
        // claim-slot digestID list (document order) to map proof slots back
        // to digestIDs, regardless of which claims THIS presentation
        // discloses - `VegaProofSystem.buildWitness` assigns slots in this
        // same document order. Unlike `digestIds`/`issuerSignedItemBytes`
        // above, this field is NOT harmless for a Longfellow presentation
        // (positional matching, no slot concept at all) - the builder's own
        // wire contract requires `nil` there, so this is gated on
        // `spec.system` rather than populated unconditionally (confirmed as
        // a real bug via Copilot review on PR #182). A malformed
        // out-of-`UInt32`-range digestID here is the same issuer-data
        // problem `VegaProofSystem` itself already rejects before proving
        // even starts, so a Vega proof only reaches this point with every
        // digestID convertible - `compactMap` is defensive, not expected to
        // actually drop anything.
        let claimSlotDigestIds: [UInt32]? = spec.system == vegaZkSystemId
            ? storedItems.compactMap { UInt32(exactly: $0.item.digestId) }
            : nil

        return MdocDeviceResponseBuilder.buildZkDeviceResponse(
            proofBytes: result.proofBytes,
            zkSystemId: spec.id,
            docType: docType,
            timestamp: result.timestamp,
            namespace: namespace,
            disclosedClaims: disclosedClaims,
            issuerAuth: document.issuerSigned.issuerAuth,
            digestIds: digestIds,
            issuerSignedItemBytes: issuerSignedItemBytes,
            claimSlotDigestIds: claimSlotDigestIds
        )
    }

    /// Direct (non-engine-relayed) trust evaluation, for flows like
    /// `handleDCAPIRequest` that have no `WalletEngineSession` involvement at
    /// all - mirrors `handleTrustEvaluation`'s request shape/AuthZEN
    /// action-name mapping exactly.
    private func evaluateTrustDirect(
        subjectId: String,
        subjectType: String?,
        keyMaterialType: String?,
        x5c: [String]?,
        jwk: [String: Any]?,
        context: [String: Any]?
    ) async throws -> TrustResult {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { throw SirosError.wallet(message: "Not connected") }

        var resource: [String: Any] = [
            "type": keyMaterialType ?? "x5c",
            "id": subjectId,
        ]
        if let x5c {
            resource["key"] = x5c
        } else if let jwk {
            resource["key"] = [jwk]
        }

        var evaluationRequest: [String: Any] = [
            "subject": ["type": "key", "id": subjectId],
            "resource": resource,
            "action": ["name": subjectType == "credential_verifier" ? "credential-verifier" : "credential-issuer"],
        ]
        if let context {
            evaluationRequest["context"] = context
        }

        let response = try await client.evaluateTrust(evaluationRequest)
        let decision = response["decision"] as? Bool ?? false
        let respContext = response["context"] as? [String: Any]

        // Mirrors the Kotlin SDK's `evaluateTrustDirect` exactly: unlike
        // `handleTrustEvaluation` (the engine-relayed path), this direct-call
        // variant deliberately does NOT populate `trustCache` on success -
        // only `handleDCAPIRequest`'s catch block reads it, as a fallback
        // when the live call itself fails.
        return TrustResult(
            trusted: decision,
            framework: respContext?["framework"] as? String,
            reason: (respContext?["reason"] as? String) ?? (respContext?["message"] as? String),
            entityName: respContext?["entity_name"] as? String,
            entityLogo: respContext?["logo_uri"] as? String,
            clientIdScheme: nil,
            identifier: subjectId,
            domain: respContext?["domain"] as? String
        )
    }

    /// Find the verifier's response-encryption key (`use: "enc"`) from DC API `client_metadata.jwks`.
    private static func findEncryptionJwk(_ clientMetadata: [String: Any]?) -> [String: Any]? {
        guard let jwks = clientMetadata?["jwks"] as? [String: Any],
              let keys = jwks["keys"] as? [[String: Any]] else {
            return nil
        }
        return keys.first(where: { ($0["use"] as? String) == "enc" }) ?? keys.first
    }
}
