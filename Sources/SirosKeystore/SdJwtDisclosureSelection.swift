// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

/// Which of an SD-JWT credential's disclosures a presentation actually includes, given the engine's
/// `disclosed_claims`. Shared by `JweKeystore` and `WscdKeystoreAdapter` (review finding, SonarCloud
/// `new_duplicated_lines_density`: an identical, several-line explanatory comment duplicated verbatim in both
/// `signVpToken` implementations crossed the duplication threshold - extracted here instead of repeated).
///
/// - `disclosedClaims == nil`: no filter was given at all - disclose every disclosure the credential carries. The
///   caller is responsible for that being correct: a consent-gated caller (`sign_presentation`) only ever reaches
///   either keystore with a concrete list here, because `ConsentMatcher.claimsToDisclose` replaces a nil with the
///   recorded consent before calling it - never passes a nil through.
/// - `disclosedClaims` non-nil, including EMPTY: a distinct, deliberate request, always routed to `filter` (even
///   when empty, which then selects nothing). Review finding (go-wallet-backend#502): a non-nil empty array used
///   to collapse into the same "no filter" branch as nil here, the one shape `ConsentMatcher` itself lets through
///   unchanged (an empty request is trivially within any consent) - so an explicit `disclosed_claims: []` was the
///   one way to defeat the defense-in-depth check and still have everything disclosed.
///
/// `filter` is each caller's OWN disclosure-matching logic, not shared: `JweKeystore` and `WscdKeystoreAdapter`
/// parse a disclosure and fail open/closed differently on an unparseable one - a pre-existing difference this
/// extraction does not change.
enum SdJwtDisclosureSelection {
    static func select(
        _ disclosures: [String],
        disclosedClaims: [String]?,
        filter: ([String], [String]) -> [String]
    ) -> [String] {
        guard let claims = disclosedClaims else { return Array(disclosures) }
        return filter(disclosures, claims)
    }
}
