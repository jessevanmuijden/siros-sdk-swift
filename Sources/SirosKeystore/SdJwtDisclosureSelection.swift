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
/// - `disclosedClaims` non-nil, including EMPTY: a distinct, deliberate request. Review finding
///   (go-wallet-backend#502, first pass): a non-nil empty array used to collapse into the same "no filter" branch
///   as nil here, the one shape `ConsentMatcher` itself lets through unchanged (an empty request is trivially
///   within any consent) - so an explicit `disclosed_claims: []` was the one way to defeat the defense-in-depth
///   check and still have everything disclosed.
///
/// An empty list is decided HERE, never handed to `filter` (review finding, second pass): `filter` fails OPEN on
/// a disclosure it cannot parse as `[salt, claimName, value]` - a two-element SD-JWT array-disclosure
/// (`[salt, value]`, no claim name, used for an element of an already-disclosed array) makes `claimName as? String`
/// fail whenever `value` isn't itself a string (e.g. `["salt", {"ssn": "..."}]`), and `JweKeystore`'s
/// `filterDisclosures` answers that "cannot tell" with `true` - included regardless of `claimNames`, so a
/// non-empty request's own fail-open choice is that caller's to keep, but an explicitly EMPTY list must never let
/// "we could not parse this one" beat "disclose nothing": there is nothing to tell apart when the answer is
/// always zero.
///
/// For a NON-empty list, `filter` is each caller's OWN disclosure-matching logic, not shared: `JweKeystore` and
/// `WscdKeystoreAdapter` fail open/closed differently on an unparseable disclosure - a pre-existing difference
/// this extraction does not change.
enum SdJwtDisclosureSelection {
    static func select(
        _ disclosures: [String],
        disclosedClaims: [String]?,
        filter: ([String], [String]) -> [String]
    ) -> [String] {
        guard let claims = disclosedClaims else { return Array(disclosures) }
        guard !claims.isEmpty else { return [] }
        return filter(disclosures, claims)
    }
}
