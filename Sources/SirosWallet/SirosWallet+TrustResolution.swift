// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1, including
// P256 ECDSA and Curve25519 - see Package.swift's SirosWallet dependencies
// and SirosWallet+MdocTrust.swift's identical fallback.
import Crypto
#endif
import SirosAuth
import SirosCredentials
import SirosTransport

/// `handleTrustEvaluation` and its `resolveDidKeyMaterial` helper, split out
/// of `SirosWallet+Engine.swift` once the `requires_resolution`/
/// `resolution_subject_id` support (go-wallet-backend#396/#401, this SDK's
/// #168) pushed that file over SwiftLint's 1500-line file_length limit.
extension SirosWallet {

    func handleTrustEvaluation(engine: WalletEngineSession, flowId: String, payload: [String: Any]) async {
        guard let request = payload["request"] as? [String: Any],
              let subjectId = request["subject_id"] as? String, !subjectId.isEmpty else {
            engine.sendTrustResult(flowId: flowId, trusted: false, reason: "Missing subject_id")
            return
        }

        let subjectType = request["subject_type"] as? String
        var keyMaterial = request["key_material"] as? [String: Any]

        // requires_resolution/request_jwt/resolution_subject_id
        // (go-wallet-backend#396/#401, this SDK's #168): set when the engine
        // could not resolve a did:-scheme verifier's key material itself and
        // defers to the frontend/SDK instead. This isn't a universal "no PDP
        // anywhere" guarantee - go-wallet-backend sets it whenever the
        // verifier-specific PDP is unconfigured, which a global/issuer PDP
        // may still be independent of; whether resolution below can actually
        // succeed depends on that backend-side configuration, not on
        // anything this SDK controls. key_material is absent in this case -
        // resolveDidKeyMaterial below is what supplies it.
        //
        // resolution_subject_id is a DIFFERENT identifier from subject_id:
        // subject_id is the original wire-form client_id (still carrying
        // OpenID4VP 1.0's decentralized_identifier: prefix, when the
        // verifier used it) that /v1/evaluate below must keep seeing
        // unchanged, but /v1/resolve needs the bare DID with that prefix
        // already stripped. Required, not defaulted to subjectId: #401's
        // own TrustEvaluationRequest.Validate() makes ResolutionSubjectID
        // mandatory whenever RequiresResolution is true, so an engine that
        // omits it is itself non-conformant - falling back to the
        // (possibly prefixed) subjectId would silently attempt resolution
        // with the wrong identifier instead of surfacing that clearly
        // (review finding).
        //
        // Resolution runs to completion (or fails closed and returns)
        // BEFORE the evaluateTrust call below and its own do/catch, which
        // deliberately falls back to a cached positive result on failure -
        // a resolution/signature failure must never be able to reach that
        // fallback and be softened into "trusted, from cache".
        if request["requires_resolution"] as? Bool == true {
            guard let resolutionSubjectId = (request["resolution_subject_id"] as? String).flatMap({ $0.isEmpty ? nil : $0 }) else {
                engine.sendTrustResult(flowId: flowId, trusted: false, reason: "Trust evaluation requires resolution but no resolution_subject_id was supplied")
                return
            }
            lock.lock(); let resolveClient = apiClient; lock.unlock()
            guard let resolveClient else {
                engine.sendTrustResult(flowId: flowId, trusted: false, reason: "No API client")
                return
            }
            let requestJwt = (request["request_jwt"] as? String).flatMap { $0.isEmpty ? nil : $0 }
            do {
                if subjectType == "credential_verifier" {
                    // A verifier's request_jwt is what resolution is FOR -
                    // there's a signed authorization request to verify
                    // against, so requiring one here is correct (unlike the
                    // issuer branch below).
                    guard let requestJwt else {
                        engine.sendTrustResult(flowId: flowId, trusted: false, reason: "Trust evaluation requires resolution but no request_jwt was supplied")
                        return
                    }
                    let resolvedJwk = try await resolveDidKeyMaterial(client: resolveClient, resolutionSubjectId: resolutionSubjectId, requestJwt: requestJwt)
                    keyMaterial = ["type": "jwk", "jwk": resolvedJwk]
                } else {
                    // credential_issuer: OID4VCI issuance has no signed
                    // request object to verify request_jwt against - the
                    // backend never sends one for a DID issuer, unlike a
                    // verifier (review finding, #168 follow-up).
                    let resolvedJwks = try await resolveIssuerDidKeyMaterial(client: resolveClient, resolutionSubjectId: resolutionSubjectId)
                    keyMaterial = ["type": "jwk", "jwk_array": resolvedJwks]
                }
            } catch {
                engine.sendTrustResult(flowId: flowId, trusted: false, reason: error.localizedDescription)
                return
            }
        }

        let kmType = keyMaterial?["type"] as? String ?? "x5c"

        var resource: [String: Any] = [
            "type": kmType,
            "id": subjectId,
        ]
        if let x5c = keyMaterial?["x5c"] {
            resource["key"] = x5c
        } else if let jwkArray = keyMaterial?["jwk_array"] as? [[String: Any]] {
            resource["key"] = jwkArray
        } else if let jwk = keyMaterial?["jwk"] {
            resource["key"] = [jwk]
        }

        let actionName = subjectType == "credential_verifier" ? "credential-verifier" : "credential-issuer"

        var evaluationRequest: [String: Any] = [
            "subject": ["type": "key", "id": subjectId],
            "resource": resource,
            "action": ["name": actionName],
        ]
        if let ctx = request["context"] {
            evaluationRequest["context"] = ctx
        }

        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else {
            engine.sendTrustResult(flowId: flowId, trusted: false, reason: "No API client")
            return
        }
        do {
            let response = try await client.evaluateTrust(evaluationRequest)
            let decision = response["decision"] as? Bool ?? false
            let context = response["context"] as? [String: Any]
            let reqContext = request["context"] as? [String: Any]

            // Build typed TrustResult from the PDP response
            let trustResult = TrustResult(
                trusted: decision,
                framework: context?["framework"] as? String,
                reason: (context?["reason"] as? String)
                    ?? (context?["message"] as? String)
                    ?? context?["reason"].map { String(describing: $0) },
                entityName: context?["entity_name"] as? String,
                entityLogo: context?["logo_uri"] as? String,
                clientIdScheme: reqContext?["client_id_scheme"] as? String,
                identifier: subjectId,
                domain: context?["domain"] as? String
            )

            // Store for use in credential selection UI
            lock.lock()
            lastTrustResults[flowId] = trustResult
            lock.unlock()

            // Populate trust cache (only positive results are stored)
            trustCache.put(identifier: subjectId, result: trustResult)

            engine.sendTrustResult(flowId: flowId, trusted: decision)
        } catch {
            // Degraded mode: check cache for a recent positive result
            if let cached = trustCache.get(identifier: subjectId) {
                print("[SirosWallet] ⚠️ Using cached trust result for \(subjectId) (backend unreachable)")
                lock.lock()
                lastTrustResults[flowId] = cached
                lock.unlock()
                engine.sendTrustResult(flowId: flowId, trusted: true)
            } else {
                engine.sendTrustResult(flowId: flowId, trusted: false, reason: error.localizedDescription)
            }
        }
    }

    /// Resolves a `did:`-scheme verifier's key material via `POST
    /// /v1/resolve` and verifies `requestJwt` against it, for the
    /// `requires_resolution` path in `handleTrustEvaluation`
    /// (go-wallet-backend#396/#401, this SDK's #168).
    ///
    /// The response's `context.trust_metadata` is treated as a W3C DID
    /// Document: every `verificationMethod` entry's `publicKeyJwk` is a
    /// candidate, tried against `requestJwt`'s signature - a `kid`-matching
    /// entry (by fragment, e.g. `#key-1`) first if the JWT header names one,
    /// then every other entry, so a DID document listing multiple
    /// verification methods (key rotation, multiple purposes) isn't
    /// defeated by trying only the first. Returns the first candidate whose
    /// key actually verifies the signature, as the `jwk` JSON shape
    /// `handleTrustEvaluation` already accepts as key material.
    ///
    /// ES256 (P-256, `alg: "ES256"`) and EdDSA (Ed25519, `alg: "EdDSA"`)
    /// signing keys are supported - RSA is not, matching
    /// `DCAPIRequestParser`'s existing JWS-verification precedent: this SDK
    /// has no JOSE/RSA library dependency and CryptoKit itself has no RSA
    /// signature-verification API (the Kotlin SDK's Nimbus-based port also
    /// supports RS256/RSA - this is a known, judged asymmetry, not an
    /// oversight). Ed25519 IS supported despite that gap, unlike RSA:
    /// CryptoKit has native `Curve25519.Signing` support, and Ed25519
    /// verification methods are common in `did:key`/`did:web` documents
    /// emitted by go-trust's supported DID resolvers - omitting it would
    /// leave every such verifier unresolvable. A `did:` verifier signing
    /// with an unsupported algorithm/key type fails closed rather than
    /// silently mis-verifying.
    ///
    /// Fails closed - throws, never silently falls through to
    /// unverified/no key material - when resolution fails, the response
    /// carries no usable verification method, or the signature does not
    /// verify against any candidate. Callers MUST treat any error thrown
    /// here as an outright trust failure, never as "backend unreachable,
    /// fall back to cache" (unlike the network errors
    /// `handleTrustEvaluation`'s own `evaluateTrust` call can throw): a
    /// `did:`-scheme verifier this wallet cannot actually verify must not be
    /// treated as trusted, or as absent (which callers might read as
    /// legitimately keyless x509_hash/no-attestation cases and proceed
    /// regardless).
    ///
    /// `resolutionSubjectId` is deliberately a distinct parameter from the
    /// `subject_id` used elsewhere for `/v1/evaluate` (go-wallet-backend#401's
    /// `ResolutionSubjectID`): `/v1/evaluate`'s subject must stay the
    /// original, wire-form identifier (e.g. still carrying OpenID4VP 1.0's
    /// `decentralized_identifier:` prefix, per docs/client-id-strategy.md -
    /// a no-PDP and a PDP-backed flow must evaluate the identical subject),
    /// but `/v1/resolve` needs the bare DID with that prefix already
    /// stripped - one field can't serve both.
    func resolveDidKeyMaterial(client: BackendApiClient, resolutionSubjectId: String, requestJwt: String) async throws -> [String: Any] {
        let parts = requestJwt.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3,
              let headerData = Self.base64UrlDecodeForTrustResolution(parts[0]),
              let header = try? JSONSerialization.jsonObject(with: headerData) as? [String: Any],
              let signature = Self.base64UrlDecodeForTrustResolution(parts[2]) else {
            throw SirosError.wallet(message: "request_jwt is not a valid JWS")
        }
        // A compact JWS requires an `alg` header (RFC 7515 §4.1.1) - a
        // missing value must not be silently treated as ES256 (review
        // finding), which would accept a malformed/non-conformant
        // request_jwt this method's contract explicitly rejects.
        let alg = header["alg"] as? String
        guard alg == "ES256" || alg == "EdDSA" else {
            throw SirosError.wallet(message: "Unsupported request_jwt signing algorithm: \(alg ?? "<missing>")")
        }
        let signingInput = Data((parts[0] + "." + parts[1]).utf8)
        // OpenID4VP requires the specific DID verificationMethod to be
        // identified by the JOSE kid - a missing kid, or one that names no
        // verification method in the resolved document, must be rejected
        // outright (review finding). Only the fragment is compared (after
        // the last `#`), which handles both a fully-qualified kid (e.g.
        // "did:web:example.com#key-1") and a relative one resolved against
        // resolutionSubjectId (e.g. "#key-1") identically, since a
        // verificationMethod's own `id` is compared the same way below.
        guard let kid = header["kid"] as? String, !kid.isEmpty else {
            throw SirosError.wallet(message: "request_jwt header is missing a kid")
        }
        guard let kidFragment = kid.split(separator: "#", maxSplits: 1).last.map(String.init), kid.contains("#") else {
            throw SirosError.wallet(message: "request_jwt header's kid '\(kid)' has no fragment")
        }

        let response = try await client.resolveKey(subjectId: resolutionSubjectId)
        // /v1/resolve is itself an AuthZEN evaluation, not a plain lookup -
        // its `decision` must be explicitly true before any of `context` is
        // trusted. A denied response (decision: false) can still carry
        // `trust_metadata` (context is populated independently of the
        // decision), so skipping this check would extract and use a denied
        // subject's key material - go-wallet-backend's own ResolveDID path
        // explicitly rejects decision == false the same way (review
        // finding).
        guard response["decision"] as? Bool == true else {
            throw SirosError.wallet(message: "Resolution of \(resolutionSubjectId) via /v1/resolve was not decided true")
        }
        guard let context = response["context"] as? [String: Any],
              let trustMetadata = context["trust_metadata"] as? [String: Any],
              let verificationMethods = trustMetadata["verificationMethod"] as? [[String: Any]],
              !verificationMethods.isEmpty else {
            throw SirosError.wallet(message: "Resolved DID document for \(resolutionSubjectId) has no verificationMethod entries")
        }

        func vmKidMatches(_ vm: [String: Any]) -> Bool {
            guard let vmId = vm["id"] as? String else { return false }
            let vmFragmentParts = vmId.split(separator: "#", maxSplits: 1)
            return vmFragmentParts.count > 1 && String(vmFragmentParts[1]) == kidFragment
        }
        // Exactly the kid-identified verification method, never any other
        // - trying every remaining method as a fallback (an earlier version
        // of this fix did) let a JWT whose kid selects method A be accepted
        // when a DIFFERENT method B actually signed it, as long as B was
        // also present in the resolved document. OpenID4VP's kid names the
        // SPECIFIC method the JWS asserts it was signed with; a signature
        // that only verifies under some OTHER method must fail closed, not
        // be silently accepted as if the kid had matched (review finding).
        guard let vm = verificationMethods.first(where: vmKidMatches) else {
            throw SirosError.wallet(message: "No verification method for \(resolutionSubjectId) matches kid fragment '#\(kidFragment)'")
        }
        guard let jwk = vm["publicKeyJwk"] as? [String: Any] else {
            throw SirosError.wallet(message: "Verification method '#\(kidFragment)' for \(resolutionSubjectId) has no publicKeyJwk")
        }

        // Not further gated on canImport(CryptoKit): the import block above
        // guarantees P256/Curve25519 either way (CryptoKit on Apple
        // platforms, swift-crypto's API-identical Crypto on Linux) - same
        // precedent as SirosWallet+MdocTrust.swift, which gates only the
        // import, never the usage. Gating this too, as an earlier version
        // of this fix did, silently excluded it (and every test exercising
        // it) on Linux, where resolution would then throw despite a
        // genuinely valid signature - never verified, never caught by CI.
        //
        // The verification primitive is selected by the JWS's OWN declared
        // `alg`, not merely by the candidate key's `kty` - a JWK's kty alone
        // must never pick the algorithm (classic JOSE algorithm-confusion
        // class), so an EC key is only tried for `alg: "ES256"` and an
        // OKP/Ed25519 key only for `alg: "EdDSA"`, matching the exact
        // non-nil `alg` already required above (review finding).
        let verified: Bool
        switch (jwk["kty"] as? String, alg) {
        case ("EC", "ES256"):
            verified = (try? Self.ecPublicKeyBytesForTrustResolution(fromJwk: jwk)).flatMap { publicKeyBytes in
                (try? P256.Signing.PublicKey(x963Representation: publicKeyBytes)).flatMap { publicKey in
                    (try? P256.Signing.ECDSASignature(rawRepresentation: signature)).map { ecdsaSignature in
                        publicKey.isValidSignature(ecdsaSignature, for: signingInput)
                    }
                }
            } ?? false
        case ("OKP", "EdDSA"):
            verified = (jwk["crv"] as? String) == "Ed25519"
                && (jwk["x"] as? String).flatMap(Self.base64UrlDecodeForTrustResolution)
                    .flatMap { try? Curve25519.Signing.PublicKey(rawRepresentation: $0) }
                    .map { $0.isValidSignature(signature, for: signingInput) } ?? false
        default:
            verified = false
        }
        guard verified else {
            throw SirosError.wallet(
                message: "request_jwt signature did not verify against the kid-matching verification method '#\(kidFragment)' for \(resolutionSubjectId)"
            )
        }
        return jwk
    }

    /// Resolves a `did:`-scheme ISSUER's key material via `POST
    /// /v1/resolve`, for the `requires_resolution` path in
    /// `handleTrustEvaluation`/`handleWmpTrustEvaluation` when the request
    /// is for a `credential_issuer` rather than a `credential_verifier`
    /// (review finding, #168 follow-up).
    ///
    /// Unlike [resolveDidKeyMaterial], this takes no `requestJwt` and
    /// verifies no signature: OID4VCI issuance has no signed authorization
    /// request object to verify against (that's specific to OpenID4VP
    /// presentation) - go-wallet-backend still sets `requires_resolution`/
    /// `resolution_subject_id` for a DID-scheme issuer, but never
    /// `request_jwt`, for exactly this reason. Returns every resolved
    /// `verificationMethod`'s `publicKeyJwk` (the PDP evaluates the
    /// resolved key material itself, not a possession proof of it here) -
    /// unlike the single best-candidate `resolveDidKeyMaterial` returns,
    /// there's no signature to narrow the field with, so all of them are
    /// forwarded.
    ///
    /// Still fails closed exactly like `resolveDidKeyMaterial`: throws when
    /// the AuthZEN `decision` on the resolve response isn't explicitly
    /// `true`, or no verification method is present.
    func resolveIssuerDidKeyMaterial(client: BackendApiClient, resolutionSubjectId: String) async throws -> [[String: Any]] {
        let response = try await client.resolveKey(subjectId: resolutionSubjectId)
        guard response["decision"] as? Bool == true else {
            throw SirosError.wallet(message: "Resolution of \(resolutionSubjectId) via /v1/resolve was not decided true")
        }
        guard let context = response["context"] as? [String: Any],
              let trustMetadata = context["trust_metadata"] as? [String: Any],
              let verificationMethods = trustMetadata["verificationMethod"] as? [[String: Any]],
              !verificationMethods.isEmpty else {
            throw SirosError.wallet(message: "Resolved DID document for \(resolutionSubjectId) has no verificationMethod entries")
        }
        let jwks = verificationMethods.compactMap { $0["publicKeyJwk"] as? [String: Any] }
        guard !jwks.isEmpty else {
            throw SirosError.wallet(message: "Resolved DID document for \(resolutionSubjectId) has no verification method with a publicKeyJwk")
        }
        return jwks
    }

    // Deliberately self-contained rather than sharing `DCAPIRequestParser`'s
    // private base64url/JWK helpers (file-private, and that file's own
    // comment explains it avoids depending on other modules' internals for
    // this exact shape of thing).
    private static func base64UrlDecodeForTrustResolution(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        return Data(base64Encoded: base64)
    }

    private static func ecPublicKeyBytesForTrustResolution(fromJwk jwk: [String: Any]) throws -> Data {
        // crv must be checked, not just kty == "EC": P256.Signing.PublicKey
        // only ever reconstructs a P-256 key regardless of what curve the
        // JWK actually claims, so a malformed JWK labeled "EC" with a
        // DIFFERENT curve (e.g. P-384/P-521) but carrying byte strings that
        // happen to decode without erroring would otherwise be silently
        // reinterpreted as P-256 and forwarded to the PDP as a semantically
        // different key than the one actually named (review finding).
        guard (jwk["kty"] as? String) == "EC",
              (jwk["crv"] as? String) == "P-256",
              let xStr = jwk["x"] as? String,
              let yStr = jwk["y"] as? String,
              let x = base64UrlDecodeForTrustResolution(xStr),
              let y = base64UrlDecodeForTrustResolution(yStr) else {
            throw SirosError.wallet(message: "Unsupported did: verification method JWK type")
        }
        return Data([0x04]) + x + y
    }
}
