// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Why a `sign_presentation` (or a WMP transaction presentation) was refused before anything was signed: the
/// engine's `disclosed_claims` for a credential disagrees with what this wallet recorded as consented when it
/// answered `credential_selection`/`match_request`. Defense in depth against a modified or buggy engine that lists
/// more than the user actually saw and approved (go-wallet-backend#502). `detail` names no claim VALUE, only shapes
/// (which claim names, which the verifier's own query already named, or that consent is simply missing).
public struct ConsentMismatch: Error, Sendable, Equatable {
    public let detail: String
    public init(_ detail: String) { self.detail = detail }
}

/// Decides what a `sign_presentation` request may actually disclose for one credential, checked against what this
/// wallet recorded as consented for it. Pure and Foundation-only, so it is unit-testable without any live wallet or
/// platform crypto.
public enum ConsentMatcher {
    /// The claims to actually disclose for this credential.
    ///
    /// - Parameters:
    ///   - disclosedClaims: the engine's `sign_presentation`/`credentials_to_include[].disclosed_claims` for this
    ///     credential, exactly as received.
    ///   - consented: the claim names this wallet itself recorded as consented for this credential when it
    ///     answered `credential_selection`/`match_request` (the same set it told the engine). `nil` when this
    ///     credential has no recorded consent at all for this flow.
    /// - Returns: `consented` when `disclosedClaims` is `nil` - a nil must NEVER be passed through as "disclose
    ///   everything", which is exactly the worst case a modified engine could produce - or `disclosedClaims` itself
    ///   when every claim it names was actually consented to.
    /// - Throws: ``ConsentMismatch`` when there is no recorded consent to check against (cannot verify, so refuse -
    ///   never guessed), or when `disclosedClaims` names a claim outside `consented`.
    public static func claimsToDisclose(disclosedClaims: [String]?, consented: Set<String>?) throws -> [String] {
        guard let consented else {
            throw ConsentMismatch("no recorded consent for this credential in this flow")
        }
        guard let disclosedClaims else {
            return Array(consented)
        }
        let beyondConsent = Set(disclosedClaims).subtracting(consented)
        guard beyondConsent.isEmpty else {
            throw ConsentMismatch("the request discloses \(beyondConsent.count) claim(s) beyond what was consented to")
        }
        return disclosedClaims
    }

    /// The consented claim names for every credential a match covers: the LAST segment of each path in
    /// `requestedClaims`, deduped - the SAME derivation `SirosWallet.buildConsentPayload` uses for the
    /// `disclosed_claims` it tells the engine were consented to, so the two never disagree about what "consented"
    /// means. One entry per id in `credentialIds` (the credentials actually selected from this match).
    public static func consentedClaims(requestedClaims: [[String]], credentialIds: [String]) -> [String: Set<String>] {
        var seen = Set<String>()
        let claims = Set(requestedClaims.compactMap(\.last).filter { seen.insert($0).inserted })
        var result: [String: Set<String>] = [:]
        for id in credentialIds { result[id] = claims }
        return result
    }
}
