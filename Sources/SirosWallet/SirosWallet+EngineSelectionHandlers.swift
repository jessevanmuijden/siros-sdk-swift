// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

// Credential selection and match handling for the engine transport, moved out of
// `SirosWallet+Engine.swift` unchanged to keep that file under the lint file-length limit.
extension SirosWallet {
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
    func handleCredentialSelection(
        engine: WalletEngineSession,
        flowId: String,
        payload: [String: AnyCodable]?
    ) async {
        // Captured before the first await: the consent listener can return
        // after the account was deleted, and nothing below may then be applied.
        guard let token = currentTeardownToken() else { return }   // a wipe has closed the gate
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
            lock.lock()
            guard isCurrentLocked(token) else { lock.unlock(); return }
            pendingMatchResultsByFlow[flowId] = matchResults
            lock.unlock()

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
            let recorded = await recordPresentation(PresentationRecord(
                id: randomUint32Id(),
                flowId: flowId,
                verifierName: verifierName,
                credentialIds: selectedIds,
                credentialNames: selectedIds.compactMap { id in allCreds.first(where: { $0.id == id })?.metadata?.name },
                requestedClaims: requestedClaims,
                timestamp: Int64(Date().timeIntervalSince1970 * 1000),
                zkProof: selection.zkProof
            ), token: token)
            guard recorded else { return }

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

    func handleMatchRequest(engine: WalletEngineSession, msg: MatchRequestMessage) async {
        guard let token = currentTeardownToken() else { return }   // see `handleCredentialSelection`
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
        lock.lock()
        guard isCurrentLocked(token) else { lock.unlock(); return }
        pendingMatchResultsByFlow[msg.flowId] = matchResults
        lock.unlock()

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
        let recorded = await recordPresentation(PresentationRecord(
            id: randomUint32Id(),
            flowId: msg.flowId,
            credentialIds: selectedIds,
            credentialNames: selectedIds.compactMap { id in
                candidates.first(where: { $0.id == id })?.metadata?.name
            },
            requestedClaims: requestedClaims,
            timestamp: Int64(Date().timeIntervalSince1970 * 1000),
            zkProof: selection.zkProof
        ), token: token)
        guard recorded else { return }

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
}
