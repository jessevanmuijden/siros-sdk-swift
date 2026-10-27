// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
import SirosTransport
@testable import SirosWallet

/// Tests for `SirosWallet.buildConsentPayload` - the `"selected_credentials"`
/// flow-action payload construction for the `"credential_selection"`
/// flow_progress step (the real, live path exercised by redirect-flow/
/// haip-vp:// presentations - see `SirosWallet.handleCredentialSelection`'s
/// doc comment). `WalletEngineSession` is a `final class` with no injectable
/// transport seam, so a live engine round-trip can't be driven from a unit
/// test - these instead pin down the pure payload-construction logic
/// directly, mirroring this file's `SirosWalletDCAPITests` sibling's
/// precedent of testing wallet-facing logic without a live network.
final class SirosWalletCredentialSelectionTests: XCTestCase {
    private func makeCredential(id: Int64, format: String = "mso_mdoc") -> StoredCredential {
        StoredCredential(
            id: id,
            format: format,
            raw: "raw-\(id)",
            batchId: id,
            instanceId: 0
        )
    }

    /// A single matched query with a plain (non-ZK) mdoc candidate: the
    /// consent payload must carry `credential_query_id`, a stringified
    /// `credential_id`, and `disclosed_claims` trimmed to each path's LAST
    /// segment - matching go-wallet-backend's `ConsentSelection` wire shape
    /// and Kotlin's identical `handleCredentialSelection` construction.
    func testBuildConsentPayload_singleMatch_trimsClaimPathsToLastSegment() {
        let cred = makeCredential(id: 42)
        let matchResults = [
            CredentialMatcher.MatchResult(
                queryId: "pid-query",
                format: "mso_mdoc",
                candidates: [cred],
                requestedClaims: [
                    ["eu.europa.ec.eudi.pid.1", "given_name"],
                    ["eu.europa.ec.eudi.pid.1", "family_name"],
                ]
            ),
        ]

        let payload = SirosWallet.buildConsentPayload(matchResults: matchResults, selectedIds: [42], allCreds: [cred])

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        XCTAssertEqual(entries.count, 1)
        guard case .object_(let entry) = entries[0] else {
            return XCTFail("Expected object entry")
        }
        XCTAssertEqual(entry["credential_query_id"]?.stringValue, "pid-query")
        XCTAssertEqual(entry["credential_id"]?.stringValue, "42")
        guard case .array(let disclosed)? = entry["disclosed_claims"] else {
            return XCTFail("Expected disclosed_claims array")
        }
        // Only the last path segment ("given_name"/"family_name") survives -
        // the leading namespace ("eu.europa.ec.eudi.pid.1") must be
        // stripped, or a strict verifier-side ZK claim check downstream
        // would reject the whole path as an unknown attribute.
        XCTAssertEqual(disclosed.compactMap(\.stringValue), ["given_name", "family_name"])
    }

    /// Two independent DCQL queries, each matching a different credential -
    /// each selected credential must be routed to ITS OWN query's id and
    /// claim list, not the first query's.
    func testBuildConsentPayload_multipleQueries_routesEachCredentialToItsOwnQuery() {
        let pidCred = makeCredential(id: 1, format: "mso_mdoc")
        let mdlCred = makeCredential(id: 2, format: "mso_mdoc")
        let matchResults = [
            CredentialMatcher.MatchResult(
                queryId: "pid-query", format: "mso_mdoc", candidates: [pidCred],
                requestedClaims: [["eu.europa.ec.eudi.pid.1", "given_name"]]
            ),
            CredentialMatcher.MatchResult(
                queryId: "mdl-query", format: "mso_mdoc", candidates: [mdlCred],
                requestedClaims: [["org.iso.18013.5.1", "document_number"]]
            ),
        ]

        let payload = SirosWallet.buildConsentPayload(
            matchResults: matchResults, selectedIds: [1, 2], allCreds: [pidCred, mdlCred]
        )

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        XCTAssertEqual(entries.count, 2)
        let byCredId: [String: [String: AnyCodable]] = Dictionary(uniqueKeysWithValues: entries.compactMap {
            guard case .object_(let obj) = $0, let credId = obj["credential_id"]?.stringValue else { return nil }
            return (credId, obj)
        })
        XCTAssertEqual(byCredId["1"]?["credential_query_id"]?.stringValue, "pid-query")
        XCTAssertEqual(byCredId["2"]?["credential_query_id"]?.stringValue, "mdl-query")
    }

    /// A credential id the caller passed in `selectedIds` but that isn't
    /// actually present in `allCreds` must be silently skipped, not crash or
    /// produce a malformed entry - defense against a listener returning an
    /// id it wasn't actually offered.
    func testBuildConsentPayload_selectedIdNotInAllCreds_isSkipped() {
        let cred = makeCredential(id: 1)
        let matchResults = [
            CredentialMatcher.MatchResult(queryId: "q", format: nil, candidates: [cred], requestedClaims: []),
        ]

        let payload = SirosWallet.buildConsentPayload(matchResults: matchResults, selectedIds: [1, 999], allCreds: [cred])

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        XCTAssertEqual(entries.count, 1)
    }

    /// A selected id that IS in `allCreds` but isn't a candidate of any
    /// `matchResults` entry (e.g. an inconsistent listener return, a race, or
    /// a future matcher change - flagged in PR review) must still produce an
    /// entry carrying a `credential_query_id` (falling back to `"_default"`,
    /// mirroring `matchAndSelectCredentials`'s synthetic no-DCQL
    /// MatchResult), never omit the field - go-wallet-backend's
    /// ConsentSelection wire contract requires it on every entry.
    func testBuildConsentPayload_selectedIdNotInAnyMatchResult_fallsBackToDefaultQueryId() {
        let matchedCred = makeCredential(id: 1)
        let orphanCred = makeCredential(id: 2)
        let matchResults = [
            CredentialMatcher.MatchResult(queryId: "q", format: nil, candidates: [matchedCred], requestedClaims: []),
        ]

        let payload = SirosWallet.buildConsentPayload(
            matchResults: matchResults, selectedIds: [2], allCreds: [matchedCred, orphanCred]
        )

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        XCTAssertEqual(entries.count, 1)
        guard case .object_(let entry) = entries[0] else {
            return XCTFail("Expected object entry")
        }
        XCTAssertEqual(entry["credential_query_id"]?.stringValue, "_default")
    }

    /// Duplicate claim paths across a query's requestedClaims (e.g. the
    /// same element requested under two DCQL alternatives) must be
    /// deduplicated in the final disclosed_claims list.
    func testBuildConsentPayload_duplicateClaimPaths_areDeduplicated() {
        let cred = makeCredential(id: 7)
        let matchResults = [
            CredentialMatcher.MatchResult(
                queryId: "q", format: "mso_mdoc", candidates: [cred],
                requestedClaims: [
                    ["eu.europa.ec.eudi.pid.1", "given_name"],
                    ["some.other.ns", "given_name"],
                ]
            ),
        ]

        let payload = SirosWallet.buildConsentPayload(matchResults: matchResults, selectedIds: [7], allCreds: [cred])

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        guard case .object_(let entry) = entries[0], case .array(let disclosed)? = entry["disclosed_claims"] else {
            return XCTFail("Expected disclosed_claims array")
        }
        XCTAssertEqual(disclosed.compactMap(\.stringValue), ["given_name"])
    }

    /// No requested claims at all (e.g. a `"_default"` fallback query with
    /// no DCQL) must produce an empty (not missing/nil) disclosed_claims
    /// array - go-wallet-backend's ConsentSelection expects the field
    /// present.
    func testBuildConsentPayload_noRequestedClaims_producesEmptyArray() {
        let cred = makeCredential(id: 3)
        let matchResults = [
            CredentialMatcher.MatchResult(queryId: "_default", format: nil, candidates: [cred], requestedClaims: []),
        ]

        let payload = SirosWallet.buildConsentPayload(matchResults: matchResults, selectedIds: [3], allCreds: [cred])

        guard case .array(let entries)? = payload["selected_credentials"] else {
            return XCTFail("Expected selected_credentials array")
        }
        guard case .object_(let entry) = entries[0] else {
            return XCTFail("Expected object entry")
        }
        XCTAssertEqual(entry["credential_query_id"]?.stringValue, "_default")
        guard case .array(let disclosed)? = entry["disclosed_claims"] else {
            return XCTFail("Expected disclosed_claims array")
        }
        XCTAssertTrue(disclosed.isEmpty)
    }
}

/// Integration-style tests exercising `CredentialMatcher.match` (the real
/// DCQL matcher, already unit-tested on its own in
/// `Tests/SirosCredentialsTests/CredentialMatcherTests.swift`) the same way
/// `handleCredentialSelection`/`handleMatchRequest`/`handleWmpMatchRequest`
/// now do: parse a `dcql_query` JSON payload into `[String: Any]`, match it
/// against stored credentials, and confirm the query id + zk metadata a
/// `sign_presentation` ZK branch depends on survive the round trip.
final class SirosWalletCredentialSelectionDcqlIntegrationTests: XCTestCase {
    private func makeCredential(id: Int64, format: String, doctype: String? = nil) -> StoredCredential {
        StoredCredential(
            id: id, format: format, raw: "raw-\(id)",
            metadata: doctype.map { CredentialMetadata(doctype: $0) },
            batchId: id, instanceId: 0
        )
    }

    /// Mirrors the exact `dcql_query` shape a `"credential_selection"`
    /// flow_progress payload carries - a plain (non-ZK) mdoc query filtered
    /// by `doctype_value`.
    func testDcqlQueryFromPayload_filtersByDoctype() throws {
        let payloadJson = """
        {
            "credentials": [
                {
                    "id": "mdl-query",
                    "format": "mso_mdoc",
                    "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                    "claims": [{ "path": ["org.iso.18013.5.1", "document_number"] }]
                }
            ]
        }
        """
        let dcqlQuery = try JSONSerialization.jsonObject(with: Data(payloadJson.utf8)) as! [String: Any]

        let mdl = makeCredential(id: 1, format: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL")
        let wrongDoctype = makeCredential(id: 2, format: "mso_mdoc", doctype: "eu.europa.ec.eudi.pid.1")
        let wrongFormat = makeCredential(id: 3, format: "dc+sd-jwt", doctype: "org.iso.18013.5.1.mDL")

        let results = CredentialMatcher.match(dcqlQuery: dcqlQuery, credentials: [mdl, wrongDoctype, wrongFormat])
        XCTAssertEqual(results.count, 1)
        XCTAssertEqual(results[0].queryId, "mdl-query")
        XCTAssertEqual(results[0].candidates.map(\.id), [1])
    }

    /// A `"mso_mdoc_zk"` query must parse `meta.zk_system_type` /
    /// `meta.ppid_context` and still match ordinary `"mso_mdoc"`-stored
    /// credentials - producing a ZK proof is a presentation-time transform,
    /// not a distinct storage format (see `CredentialMatcher`'s own doc
    /// comment on this). This is exactly what `handleSignRequest`'s new ZK
    /// branch depends on `pendingMatchResultsByFlow` having captured.
    func testDcqlQueryFromPayload_zkFormat_matchesOrdinaryMdocAndParsesZkMeta() throws {
        let payloadJson = """
        {
            "credentials": [
                {
                    "id": "zk-query",
                    "format": "mso_mdoc_zk",
                    "meta": {
                        "doctype_value": "eu.europa.ec.eudi.pid.1",
                        "zk_system_type": [{ "id": "longfellow-libzk-v1-c1", "system": "longfellow-libzk-v1", "circuit_id": "c1" }],
                        "ppid_context": "some-context"
                    },
                    "claims": [{ "path": ["eu.europa.ec.eudi.pid.1", "pairwise_pseudonym"] }]
                }
            ]
        }
        """
        let dcqlQuery = try JSONSerialization.jsonObject(with: Data(payloadJson.utf8)) as! [String: Any]
        let pid = makeCredential(id: 5, format: "mso_mdoc", doctype: "eu.europa.ec.eudi.pid.1")

        let results = CredentialMatcher.match(dcqlQuery: dcqlQuery, credentials: [pid])
        XCTAssertEqual(results.count, 1)
        let result = results[0]
        XCTAssertEqual(result.queryId, "zk-query")
        XCTAssertEqual(result.format, "mso_mdoc_zk")
        XCTAssertTrue(result.candidates.contains(where: { $0.id == 5 }))
        XCTAssertEqual(result.ppidContext, "some-context")
        XCTAssertNotNil(result.zkSystemTypes)
        XCTAssertEqual(result.zkSystemTypes?.count, 1)

        // What buildConsentPayload/handleSignRequest's ZK branch actually
        // consume from this MatchResult.
        let consentPayload = SirosWallet.buildConsentPayload(matchResults: results, selectedIds: [5], allCreds: [pid])
        guard case .array(let entries)? = consentPayload["selected_credentials"],
              case .object_(let entry) = entries.first else {
            return XCTFail("Expected one consent entry")
        }
        guard case .array(let disclosed)? = entry["disclosed_claims"] else {
            return XCTFail("Expected disclosed_claims array")
        }
        XCTAssertEqual(disclosed.compactMap(\.stringValue), ["pairwise_pseudonym"])
    }

    // MARK: - zkRequestedIds / firstMatchByCredentialId
    // The shared first-match derivation behind `PresentationRecord.zkProof`
    // and the `consumeNonZkp` resolver on the DC API and both engine
    // selection paths. Mirrors the Kotlin regression test
    // `handleDCAPIRequest_credentialMatchesBothZkAndPlainQuery_usesFirstMatchForZkFlag`.

    /// A single stored mso_mdoc credential is a candidate under BOTH a plain
    /// and a zk query (`CredentialMatcher.matchesFormat`'s zk-matches-plain
    /// rule). First-match over the request's own `credentials` order decides
    /// - plain first means a raw disclosure, so the id must NOT be zk here,
    /// even though it is a candidate under the zk query too.
    func testZkRequestedIds_plainQueryFirst_isNotZk() throws {
        let dcqlQuery = try JSONSerialization.jsonObject(with: Data("""
        {"credentials": [
            {"id": "mdl_plain", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}},
            {"id": "mdl_zk", "format": "mso_mdoc_zk", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}
        ]}
        """.utf8)) as! [String: Any]
        let mdl = makeCredential(id: 1, format: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL")

        let matchResults = CredentialMatcher.match(dcqlQuery: dcqlQuery, credentials: [mdl])
        XCTAssertEqual(matchResults.map(\.queryId), ["mdl_plain", "mdl_zk"], "both queries must match the one credential")

        let byId = SirosWallet.firstMatchByCredentialId(candidates: [mdl], matchResults: matchResults)
        XCTAssertEqual(byId[1]?.queryId, "mdl_plain")
        XCTAssertEqual(SirosWallet.zkRequestedIds(matchResultByCredentialId: byId), [])
    }

    /// Same request with the zk query first: the same credential now IS
    /// presented as a ZK proof.
    func testZkRequestedIds_zkQueryFirst_isZk() throws {
        let dcqlQuery = try JSONSerialization.jsonObject(with: Data("""
        {"credentials": [
            {"id": "mdl_zk", "format": "mso_mdoc_zk", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}},
            {"id": "mdl_plain", "format": "mso_mdoc", "meta": {"doctype_value": "org.iso.18013.5.1.mDL"}}
        ]}
        """.utf8)) as! [String: Any]
        let mdl = makeCredential(id: 1, format: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL")

        let matchResults = CredentialMatcher.match(dcqlQuery: dcqlQuery, credentials: [mdl])
        let byId = SirosWallet.firstMatchByCredentialId(candidates: [mdl], matchResults: matchResults)

        XCTAssertEqual(byId[1]?.queryId, "mdl_zk")
        XCTAssertEqual(SirosWallet.zkRequestedIds(matchResultByCredentialId: byId), [1])
    }

    /// Two credentials, each governed by a different query - the zk flag is
    /// per credential id, never "any zk query anywhere in the request".
    func testZkRequestedIds_isPerCredential() {
        let pid = makeCredential(id: 1, format: "mso_mdoc", doctype: "eu.europa.ec.eudi.pid.1")
        let mdl = makeCredential(id: 2, format: "mso_mdoc", doctype: "org.iso.18013.5.1.mDL")
        let matchResults = [
            CredentialMatcher.MatchResult(queryId: "pid_zk", format: "MSO_MDOC_ZK", candidates: [pid], requestedClaims: []),
            CredentialMatcher.MatchResult(queryId: "mdl_plain", format: "mso_mdoc", candidates: [mdl], requestedClaims: []),
            CredentialMatcher.MatchResult(queryId: "default", format: nil, candidates: [pid, mdl], requestedClaims: []),
        ]

        let byId = SirosWallet.firstMatchByCredentialId(candidates: [pid, mdl], matchResults: matchResults)

        XCTAssertEqual(SirosWallet.zkRequestedIds(matchResultByCredentialId: byId), [1], "case-insensitive, and only the pid")
        XCTAssertEqual(byId[2]?.queryId, "mdl_plain")
    }

}

/// What this wallet says when it has nothing to present, and what it makes of
/// the engine's answer (go-wallet-backend #335/#336). An empty match set ends
/// the flow with `NO_MATCHING_CREDENTIAL` instead of parking it until the
/// user-interaction timeout - the reason travelling with it, and the
/// `requested_types` coming back, are what let an app name the credential the
/// user is missing rather than show "something went wrong".
final class SirosWalletNoMatchingCredentialTests: XCTestCase {

    /// SD-JWT VC `vct_values` and mdoc `doctype_value`, in query order.
    /// Mirrors go-wallet-backend's `requestedCredentialTypes`, so the reason
    /// this wallet reports and the `requested_types` the engine derives on its
    /// own describe the same request.
    func testRequestedCredentialTypes_readsVctValuesAndDoctype() {
        let query: [String: Any] = [
            "credentials": [
                ["id": "pid", "format": "dc+sd-jwt", "meta": ["vct_values": ["urn:eudi:pid:arf-1.8:1", "urn:eudi:pid:1"]]],
                ["id": "mdl", "format": "mso_mdoc", "meta": ["doctype_value": "org.iso.18013.5.1.mDL"]],
            ],
        ]

        XCTAssertEqual(
            SirosWallet.requestedCredentialTypes(dcqlQuery: query),
            ["urn:eudi:pid:arf-1.8:1", "urn:eudi:pid:1", "org.iso.18013.5.1.mDL"]
        )
    }

    /// A query naming no type at all still identifies itself by its id -
    /// better than saying nothing about what was asked for.
    func testRequestedCredentialTypes_fallsBackToQueryId() {
        let query: [String: Any] = ["credentials": [["id": "anything", "format": "dc+sd-jwt"]]]

        XCTAssertEqual(SirosWallet.requestedCredentialTypes(dcqlQuery: query), ["anything"])
    }

    func testRequestedCredentialTypes_deduplicatesAcrossQueries() {
        let query: [String: Any] = [
            "credentials": [
                ["id": "pid-a", "meta": ["vct_values": ["urn:eudi:pid:1"]]],
                ["id": "pid-b", "meta": ["vct_values": ["urn:eudi:pid:1"]]],
            ],
        ]

        XCTAssertEqual(SirosWallet.requestedCredentialTypes(dcqlQuery: query), ["urn:eudi:pid:1"])
    }

    /// Best-effort by design: no query, or one shaped in a way this doesn't
    /// understand, yields no names rather than a wrong one.
    func testRequestedCredentialTypes_missingOrUnparseableQueryYieldsNothing() {
        XCTAssertEqual(SirosWallet.requestedCredentialTypes(dcqlQuery: nil), [])
        XCTAssertEqual(SirosWallet.requestedCredentialTypes(dcqlQuery: ["credential_sets": []]), [])
    }

    /// Nothing matched: the reason names what the verifier asked for, which
    /// is what lets an app say "you need a PID first".
    func testNoMatchReason_namesTheRequestedTypes() {
        let query: [String: Any] = [
            "credentials": [["id": "pid", "meta": ["vct_values": ["urn:eudi:pid:1"]]]],
        ]

        XCTAssertEqual(
            SirosWallet.noMatchReason(dcqlQuery: query, candidateCount: 0),
            "no_matching_credential",
            "only a code goes to the engine: no requested types"
        )
        // The wallet's own words keep the types, for its log only.
        XCTAssertEqual(
            SirosWallet.noMatchDescription(dcqlQuery: query, candidateCount: 0),
            "no stored credential matches the requested type(s): urn:eudi:pid:1"
        )
    }

    func testNoMatchReason_noRequestedTypesStillExplains() {
        XCTAssertEqual(
            SirosWallet.noMatchReason(dcqlQuery: nil, candidateCount: 0),
            "no_matching_credential"
        )
    }

    /// The other way to have nothing to present: the query did match, but
    /// every copy is spent. A different sentence, because it needs a different
    /// answer from the user (renew, not "get a PID").
    func testNoMatchReason_matchedButExhaustedSaysSo() {
        let query: [String: Any] = [
            "credentials": [["id": "pid", "meta": ["vct_values": ["urn:eudi:pid:1"]]]],
        ]

        XCTAssertEqual(
            SirosWallet.noMatchReason(dcqlQuery: query, candidateCount: 2),
            "credentials_exhausted",
            "a code, not \"N credential(s)\": the wallet's inventory size stays local"
        )
        XCTAssertEqual(
            SirosWallet.noMatchDescription(dcqlQuery: query, candidateCount: 2),
            "2 matching credential(s) have no eligible copies remaining"
        )
    }

    // MARK: - decline vs. nothing to present

    private func makeSelection(
        candidates: [StoredCredential],
        couldHaveConsented: Bool,
        selectedIds: [Int64] = [],
        allSelectedEligible: Bool = true
    ) -> SirosWallet.EngineSelection {
        SirosWallet.EngineSelection(
            matchResults: [],
            candidates: candidates,
            selectedIds: selectedIds,
            zkRequestedIds: [],
            allSelectedEligible: allSelectedEligible,
            couldHaveConsented: couldHaveConsented
        )
    }

    private func makeCredential(id: Int64) -> StoredCredential {
        StoredCredential(id: id, format: "mso_mdoc", raw: "raw-\(id)", batchId: id, instanceId: 0)
    }

    /// The bug this fixes: with nothing to offer, the SDK told the engine the
    /// user had declined - which the engine forwards to the verifier as
    /// `access_denied` / "User declined the request", a refusal nobody made.
    func testAnswerForEmptySelection_nothingMatched_isNotADecline() {
        let query: [String: Any] = [
            "credentials": [["id": "pid", "meta": ["vct_values": ["urn:eudi:pid:1"]]]],
        ]

        let answer = SirosWallet.answerForEmptySelection(
            dcqlQuery: query,
            selection: makeSelection(candidates: [], couldHaveConsented: false)
        )

        XCTAssertEqual(
            answer,
            .noMatch(reason: "no_matching_credential")
        )
    }

    /// Matched, but every copy is spent. The listener is still shown those
    /// candidates (so an app can offer a renewal), yet there was never a
    /// consent it could have given - so an empty answer is not a refusal, and
    /// the reason says which of the two cases it was.
    func testAnswerForEmptySelection_matchedButNothingEligible_isNoMatch() {
        let answer = SirosWallet.answerForEmptySelection(
            dcqlQuery: nil,
            selection: makeSelection(candidates: [makeCredential(id: 1)], couldHaveConsented: false)
        )

        XCTAssertEqual(answer, .noMatch(reason: "credentials_exhausted"))
    }

    /// The user was shown a credential they could actually have presented and
    /// picked none - the one case that is a decline, and must stay one.
    func testAnswerForEmptySelection_userChoseNone_isADecline() {
        let answer = SirosWallet.answerForEmptySelection(
            dcqlQuery: nil,
            selection: makeSelection(candidates: [makeCredential(id: 1)], couldHaveConsented: true)
        )

        XCTAssertEqual(answer, .declined)
        XCTAssertEqual(answer.reason, "no_selection")
    }

    // MARK: - a selection that cannot be presented

    /// The same failure mode one step later: the app followed the documented
    /// path, showed an exhausted copy, and the user picked it. That used to
    /// throw, and the handler's catch reported it to the verifier as a
    /// decline - the wallet's own inability dressed up as a user refusal.
    func testUnpresentableAnswer_ineligibleSelection_isNoMatchNotDecline() {
        let answer = SirosWallet.unpresentableAnswer(
            dcqlQuery: nil,
            selection: makeSelection(
                candidates: [makeCredential(id: 1)],
                couldHaveConsented: true,
                selectedIds: [1],
                allSelectedEligible: false
            )
        )

        XCTAssertEqual(answer, .noMatch(reason: SirosWallet.ineligibleSelectionReason))
    }

    /// A partly-eligible selection takes the same path: `EngineSelection`
    /// deliberately reduces eligibility to "is everything selected still
    /// usable", and presenting whichever subset happens to survive would send
    /// something other than what the user approved - and might not satisfy the
    /// query anyway.
    func testUnpresentableAnswer_partlyEligibleSelection_isAlsoNoMatch() {
        let answer = SirosWallet.unpresentableAnswer(
            dcqlQuery: nil,
            selection: makeSelection(
                candidates: [makeCredential(id: 1), makeCredential(id: 2)],
                couldHaveConsented: true,
                selectedIds: [1, 2],
                allSelectedEligible: false
            )
        )

        XCTAssertEqual(answer, .noMatch(reason: SirosWallet.ineligibleSelectionReason))
    }

    /// The ordinary case: something was chosen and all of it can be
    /// presented, so the handler goes on to consent.
    func testUnpresentableAnswer_presentableSelection_isNil() {
        XCTAssertNil(SirosWallet.unpresentableAnswer(
            dcqlQuery: nil,
            selection: makeSelection(
                candidates: [makeCredential(id: 1)],
                couldHaveConsented: true,
                selectedIds: [1]
            )
        ))
    }

    /// An empty selection still answers exactly as `answerForEmptySelection`
    /// decides - the two callers must not drift apart.
    func testUnpresentableAnswer_emptySelection_delegatesToEmptySelectionRule() {
        let declining = makeSelection(candidates: [makeCredential(id: 1)], couldHaveConsented: true)
        XCTAssertEqual(SirosWallet.unpresentableAnswer(dcqlQuery: nil, selection: declining), .declined)

        let nothingToPresent = makeSelection(candidates: [], couldHaveConsented: false)
        XCTAssertEqual(
            SirosWallet.unpresentableAnswer(dcqlQuery: nil, selection: nothingToPresent),
            .noMatch(reason: "no_matching_credential")
        )
    }

    /// `NO_MATCHING_CREDENTIAL`'s details, which the SDK used to decode only
    /// far enough to find `redirect_uri`.
    func testNoMatchingCredentialDetails_readsRequestedTypesAndReason() throws {
        let error = try Self.decodeFlowError("""
        {"type":"flow_error","flow_id":"flow-1","step":"credential_selection","error":{\
        "code":"NO_MATCHING_CREDENTIAL","message":"This request needs a credential you do not have: urn:eudi:pid:1",\
        "details":{"requested_types":["urn:eudi:pid:1"],"no_match_reason":"wallet holds no PID",\
        "redirect_uri":"https://verifier.example/done"}}}
        """)

        XCTAssertEqual(error.code, EngineErrorCodes.noMatchingCredential)
        let details = SirosWallet.noMatchingCredentialDetails(error: error)

        XCTAssertEqual(details.requestedTypes, ["urn:eudi:pid:1"])
        XCTAssertEqual(details.reason, "wallet holds no PID")
    }

    /// The engine omits `requested_types` for a query that names no type, and
    /// `no_match_reason` for a client that sends none - neither is an error.
    func testNoMatchingCredentialDetails_toleratesAbsentDetails() throws {
        let error = try Self.decodeFlowError("""
        {"type":"flow_error","flow_id":"flow-1","error":{"code":"NO_MATCHING_CREDENTIAL","message":"nothing matched"}}
        """)

        let details = SirosWallet.noMatchingCredentialDetails(error: error)

        XCTAssertEqual(details.requestedTypes, [])
        XCTAssertNil(details.reason)
    }

    /// `FlowError`'s memberwise initializer is internal to `SirosTransport`,
    /// so build one the way the session does: off the wire.
    private static func decodeFlowError(_ json: String) throws -> FlowError {
        try JSONDecoder().decode(FlowErrorMessage.self, from: Data(json.utf8)).error
    }
}
