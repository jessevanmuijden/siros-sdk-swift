// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

// Credential matching and selection shared by the engine's presentation
// handlers (`SirosWallet+Engine.swift`). Split out of that file because the
// three handlers that need it - WMP `match_request`, legacy `match_request`
// and the `credential_selection` flow_progress step - must apply exactly one
// rule, and that rule is easier to read (and keep single) on its own than
// buried between the transport handlers it serves.
extension SirosWallet {

    /// `matchAndSelectCredentials`' result - see that function's doc comment.
    struct EngineSelection {
        let matchResults: [CredentialMatcher.MatchResult]
        let candidates: [StoredCredential]
        let selectedIds: [Int64]
        /// Selected-or-not candidates whose first-match query is `mso_mdoc_zk`.
        let zkRequestedIds: Set<Int64>
        /// False if the listener returned an id the active policy/keystore
        /// no longer considers usable.
        let allSelectedEligible: Bool
        /// Whether the user could have consented at all - true only when an
        /// `eventListener` was registered AND at least one matched credential
        /// was still presentable. An empty `selectedIds` means "the user said
        /// no" only in that case; otherwise the wallet had nothing to present,
        /// which is a different answer and owes the engine a different one
        /// (see `answerForEmptySelection`).
        let couldHaveConsented: Bool
        /// Whether presenting ANY of `selectedIds` is a ZK proof - the
        /// recorded `PresentationRecord.zkProof`.
        var zkProof: Bool { selectedIds.contains(where: { zkRequestedIds.contains($0) }) }
    }

    /// Shared credential matching + selection for the WMP `match_request`
    /// step (`handleWmpMatchRequest`), and the `"credential_selection"`
    /// flow_progress step (`handleCredentialSelection` - the actual live
    /// path exercised by redirect-flow/haip-vp:// presentations). Filters
    /// `allCreds` against `dcqlQuery` (`nil` matches everything, preserving
    /// each caller's prior no-DCQL fallback behavior), offers the matched
    /// candidates to `eventListener` for consent when one is registered, and
    /// falls back to auto-selecting every currently-eligible candidate
    /// otherwise - mirrors Kotlin's identical fallback in each of its three
    /// equivalent collectors/handlers.
    ///
    /// Also resolves, once, which selected ids will be presented as a ZK
    /// proof rather than disclosed (`zkRequestedIds` - the same first-match
    /// rule the `sign_presentation` handler applies), so consumption
    /// accounting (`consumeNonZkp`) and the recorded `PresentationRecord.zkProof`
    /// agree with what is actually sent. Mirrors Kotlin's `handleDCAPIRequest`
    /// / `matchRequests()` / `handleCredentialSelection`.
    func matchAndSelectCredentials(
        dcqlQuery: [String: Any]?,
        allCreds: [StoredCredential],
        verifierName: String?,
        trustResult: TrustResult?
    ) async -> EngineSelection {
        let matchResults: [CredentialMatcher.MatchResult]
        if let dcqlQuery {
            matchResults = CredentialMatcher.match(dcqlQuery: dcqlQuery, credentials: allCreds)
        } else {
            matchResults = [CredentialMatcher.MatchResult(queryId: "_default", format: nil, candidates: allCreds, requestedClaims: [])]
        }
        var seenIds = Set<Int64>()
        let candidates = matchResults.flatMap { $0.candidates }.filter { seenIds.insert($0.id).inserted }
        let zkRequestedIds = Self.zkRequestedIds(
            matchResultByCredentialId: Self.firstMatchByCredentialId(candidates: candidates, matchResults: matchResults)
        )

        // Evaluated exactly once: it reads the keystore's live key list, and
        // both the auto-selection fallback and the defense-in-depth check
        // below must see the same answer.
        let eligible = eligibleInstances(from: candidates, isZkPresentation: { zkRequestedIds.contains($0.id) })

        lock.lock(); let listener = eventListener; lock.unlock()
        let selectedIds: [Int64]
        // Note `eligible`, not `candidates`: the listener is deliberately
        // shown exhausted copies too (so an app can offer a renewal), but a
        // request it was never possible to satisfy is not one the user
        // refused, whatever they then tapped.
        let couldHaveConsented = listener != nil && !eligible.isEmpty
        if let listener, !candidates.isEmpty {
            selectedIds = await listener.onCredentialSelectionRequired(
                request: PresentationRequest(
                    verifierName: verifierName,
                    trustResult: trustResult,
                    candidates: candidates,
                    requestedClaims: matchResults.flatMap { $0.requestedClaims }
                )
            )
        } else {
            selectedIds = eligible.map(\.id)
        }

        // The app is trusted to only return IDs it was offered, but shouldn't
        // be the only thing enforcing consumption - re-validate here too
        // (defense in depth). Computed once here rather than in each caller
        // so the two engine handlers can't apply different rules.
        let eligibleIds = Set(eligible.map(\.id))
        return EngineSelection(
            matchResults: matchResults,
            candidates: candidates,
            selectedIds: selectedIds,
            zkRequestedIds: zkRequestedIds,
            allSelectedEligible: selectedIds.allSatisfy { eligibleIds.contains($0) },
            couldHaveConsented: couldHaveConsented
        )
    }

    /// Why a selection came back empty - the distinction the engine's
    /// `credential_selection` step needs, and the one this SDK used to lose by
    /// reporting every empty selection as a decline.
    enum NoSelectionAnswer: Equatable {
        /// The user was shown the matching credentials and chose none.
        case declined
        /// There was nothing to show: no credential matched, or none of the
        /// matches has a copy left to spend. Nobody refused anything.
        case noMatch(reason: String)

        /// Wording for the `no_match_reason` the client sends with an empty
        /// match set, in either case.
        var reason: String {
            switch self {
            case .declined: return NoMatchReason.noSelection
            case .noMatch(let reason): return reason
            }
        }
    }

    /// Why a selection cannot be presented even though credentials were
    /// chosen: the copies behind them are spent (or their keys are gone).
    /// Shared by both engine handlers so they say the same thing.
    static let ineligibleSelectionReason = NoMatchReason.credentialsExhausted

    /// Whether this selection can be presented at all, and if not, what to
    /// tell the engine. `nil` means go ahead: credentials were selected and
    /// every one of them is still presentable.
    ///
    /// Two ways to end up with nothing to send, and neither is a refusal:
    /// nothing was selected (see `answerForEmptySelection`), or something was
    /// selected that the consumption policy/keystore no longer considers
    /// usable. The second is why this is not just an empty-selection check:
    /// an app following the documented path shows exhausted copies too (so it
    /// can offer a renewal), so it can hand back an id that cannot be
    /// presented - which used to throw, and the handler's catch reported that
    /// to the verifier as a decline, exactly the wallet-side inability
    /// masquerading as a user refusal this change exists to remove.
    ///
    /// A partly-eligible selection is treated the same as a wholly ineligible
    /// one: `EngineSelection` reduces eligibility to "is everything selected
    /// still usable", deliberately, and presenting the usable subset would
    /// send something other than what the user approved - and might not
    /// satisfy the query anyway.
    static func unpresentableAnswer(
        dcqlQuery: [String: Any]?,
        selection: EngineSelection
    ) -> NoSelectionAnswer? {
        if selection.selectedIds.isEmpty {
            return answerForEmptySelection(dcqlQuery: dcqlQuery, selection: selection)
        }
        guard selection.allSelectedEligible else { return .noMatch(reason: ineligibleSelectionReason) }
        return nil
    }

    /// Which of the two an empty `selectedIds` is.
    ///
    /// The distinction matters on the wire: `decline` is forwarded to the
    /// verifier as `access_denied` / "User declined the request", which is
    /// untrue when the user was never asked, and saying nothing instead leaves
    /// the flow to die on the engine's five-minute user-interaction timeout as
    /// a generic `FLOW_TIMEOUT`. `credentials_matched` with an empty match set
    /// is the honest third answer: the engine ends the flow at once with
    /// `NO_MATCHING_CREDENTIAL`, naming the credential types the query asked
    /// for, and tells the verifier (go-wallet-backend #335 / #336).
    ///
    /// Static and pure so the rule every engine handler applies is testable
    /// without a live session.
    static func answerForEmptySelection(
        dcqlQuery: [String: Any]?,
        selection: EngineSelection
    ) -> NoSelectionAnswer {
        guard !selection.couldHaveConsented else { return .declined }
        return .noMatch(reason: noMatchReason(dcqlQuery: dcqlQuery, candidateCount: selection.candidates.count))
    }

    /// The credential types a DCQL query asks for, in query order and without
    /// duplicates: each credential query's `meta.vct_values` (SD-JWT VC) and
    /// `meta.doctype_value` (mdoc), falling back to the query `id` for a query
    /// that names neither. Mirrors go-wallet-backend's `requestedCredentialTypes`
    /// so the reason this wallet reports and the `requested_types` the engine
    /// derives independently describe the same request.
    ///
    /// Best-effort by design: an exotic or malformed query simply yields no
    /// names, and the caller says "no matching credential" without naming one.
    static func requestedCredentialTypes(dcqlQuery: [String: Any]?) -> [String] {
        guard let queries = dcqlQuery?["credentials"] as? [[String: Any]] else { return [] }
        var types: [String] = []
        var seen = Set<String>()
        func add(_ value: String?) {
            guard let value, !value.isEmpty, seen.insert(value).inserted else { return }
            types.append(value)
        }
        for query in queries {
            let meta = query["meta"] as? [String: Any]
            let vctValues = meta?["vct_values"] as? [String] ?? []
            let doctypeValue = meta?["doctype_value"] as? String
            vctValues.forEach { add($0) }
            add(doctypeValue)
            if vctValues.isEmpty && (doctypeValue?.isEmpty ?? true) {
                add(query["id"] as? String)
            }
        }
        return types
    }

    /// Why this wallet has nothing to present, as the CODE for the `no_match_reason` the engine forwards to the app: the
    /// wallet holds nothing of the requested type (`no_matching_credential`), or it holds some but has no usable copy
    /// left (`credentials_exhausted`). Only a code leaves the device; `noMatchDescription` is for the local log.
    ///
    /// - Parameter candidateCount: credentials the DCQL query did match, none of which turned out to be presentable.
    static func noMatchReason(dcqlQuery: [String: Any]?, candidateCount: Int) -> String {
        candidateCount > 0 ? NoMatchReason.credentialsExhausted : NoMatchReason.noMatchingCredential
    }

    /// The wallet's own words for the same situation, for ITS log only: they name the requested types and how many
    /// credentials the wallet holds, which must never reach the engine (see `NoMatchReason`).
    static func noMatchDescription(dcqlQuery: [String: Any]?, candidateCount: Int) -> String {
        if candidateCount > 0 {
            return "\(candidateCount) matching credential(s) have no eligible copies remaining"
        }
        let requested = requestedCredentialTypes(dcqlQuery: dcqlQuery)
        guard !requested.isEmpty else {
            return "no stored credential matches the request"
        }
        return "no stored credential matches the requested type(s): " + requested.joined(separator: ", ")
    }

    /// The structured half of a `NO_MATCHING_CREDENTIAL` flow error, for
    /// `onNoMatchingCredential`: the engine's `requested_types` (the credential
    /// types the verifier's DCQL query named) and the `no_match_reason` this
    /// wallet sent with its empty match set. Tolerates either detail being
    /// absent - the engine omits `requested_types` for a query that names no
    /// type, and `no_match_reason` for a client that sends none.
    static func noMatchingCredentialDetails(error: FlowError) -> (requestedTypes: [String], reason: String?) {
        let requestedTypes = error.details?["requested_types"]?.arrayValue?.compactMap(\.stringValue) ?? []
        return (requestedTypes, error.details?["no_match_reason"]?.stringValue)
    }

    /// Builds the `"selected_credentials"` flow-action payload the engine's
    /// `"consent"` action expects for the `"credential_selection"` step -
    /// matches go-wallet-backend's `ConsentSelection` wire shape
    /// (`credential_query_id`, `credential_id`, `disclosed_claims`) exactly,
    /// mirroring Kotlin's `handleCredentialSelection`'s identical payload
    /// construction. Internal (not private) and static so it's directly
    /// unit-testable without a live `WalletEngineSession` - see
    /// `requestBackendKeyAttestation`'s doc comment for this file's existing
    /// testability precedent.
    static func buildConsentPayload(
        matchResults: [CredentialMatcher.MatchResult],
        selectedIds: [Int64],
        allCreds: [StoredCredential]
    ) -> [String: AnyCodable] {
        var entries: [AnyCodable] = []
        for id in selectedIds {
            guard allCreds.contains(where: { $0.id == id }) else { continue }
            let matchResult = matchResults.first(where: { result in result.candidates.contains(where: { $0.id == id }) })
            var obj: [String: AnyCodable] = [:]
            // Always set credential_query_id, even for an id that (should
            // never happen, but see below) isn't in any matchResult - the
            // "_default" fallback mirrors the no-DCQL synthetic MatchResult
            // matchAndSelectCredentials builds, and keeps this payload
            // honoring the backend's documented wire contract unconditionally
            // rather than silently omitting the field if a caller ever
            // passes a selectedId inconsistent with matchResults (e.g. a
            // misbehaving eventListener implementation).
            obj["credential_query_id"] = .string(matchResult?.queryId ?? "_default")
            // Legacy engine JSON-RPC protocol keeps credential_id as a string
            // wire contract - a separate contract from privatedata-spec's
            // numeric StoredCredential.id, so it deliberately stays String
            // (mirrors every other call site's identical stringification).
            obj["credential_id"] = .string(String(id))
            // Each requestedClaims entry is a full DCQL claim PATH (e.g.
            // ["eu.europa.ec.eudi.pid.1", "pairwise_pseudonym"]) - only the
            // last segment is the actual disclosable element id (mirrors
            // handleDCAPIRequest's identical `compactMap(\.last)`): the
            // native Longfellow ZK prover validates every requested claim
            // strictly and throws on a raw, un-trimmed path.
            var seenClaims = Set<String>()
            let disclosedClaims = (matchResult?.requestedClaims ?? [])
                .compactMap(\.last)
                .filter { seenClaims.insert($0).inserted }
            obj["disclosed_claims"] = .array(disclosedClaims.map { .string($0) })
            entries.append(.object_(obj))
        }
        return ["selected_credentials": .array(entries)]
    }
}
