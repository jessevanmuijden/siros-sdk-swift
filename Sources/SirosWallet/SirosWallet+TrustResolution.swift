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
            guard let requestJwt = request["request_jwt"] as? String, !requestJwt.isEmpty else {
                engine.sendTrustResult(flowId: flowId, trusted: false, reason: "Trust evaluation requires resolution but no request_jwt was supplied")
                return
            }
            guard let resolutionSubjectId = (request["resolution_subject_id"] as? String).flatMap({ $0.isEmpty ? nil : $0 }) else {
                engine.sendTrustResult(flowId: flowId, trusted: false, reason: "Trust evaluation requires resolution but no resolution_subject_id was supplied")
                return
            }
            lock.lock(); let resolveClient = apiClient; lock.unlock()
            guard let resolveClient else {
                engine.sendTrustResult(flowId: flowId, trusted: false, reason: "No API client")
                return
            }
            do {
                let resolvedJwk = try await resolveDidKeyMaterial(client: resolveClient, resolutionSubjectId: resolutionSubjectId, requestJwt: requestJwt)
                keyMaterial = ["type": "jwk", "jwk": resolvedJwk]
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
        let kidFragment: String? = (header["kid"] as? String).flatMap { kid in
            let split = kid.split(separator: "#", maxSplits: 1)
            return split.count > 1 ? String(split[1]) : nil
        }

        let response = try await client.resolveKey(subjectId: resolutionSubjectId)
        guard let context = response["context"] as? [String: Any],
              let trustMetadata = context["trust_metadata"] as? [String: Any],
              let verificationMethods = trustMetadata["verificationMethod"] as? [[String: Any]],
              !verificationMethods.isEmpty else {
            throw SirosError.wallet(message: "Resolved DID document for \(resolutionSubjectId) has no verificationMethod entries")
        }

        func vmKidMatches(_ vm: [String: Any]) -> Bool {
            guard let kidFragment, let vmId = vm["id"] as? String else { return false }
            let vmFragmentParts = vmId.split(separator: "#", maxSplits: 1)
            return vmFragmentParts.count > 1 && String(vmFragmentParts[1]) == kidFragment
        }
        // A kid-matching entry first, but every entry is still tried - an
        // absent/non-matching kid is common (many DID documents predate
        // per-purpose kids), and refusing to try the rest would fail closed
        // on a verifier this wallet CAN actually verify.
        let candidates = verificationMethods.sorted { vmKidMatches($0) && !vmKidMatches($1) }

        // Not further gated on canImport(CryptoKit): the import block above
        // guarantees P256/Curve25519 either way (CryptoKit on Apple
        // platforms, swift-crypto's API-identical Crypto on Linux) - same
        // precedent as SirosWallet+MdocTrust.swift, which gates only the
        // import, never the usage. Gating this loop too, as an earlier
        // version of this fix did, silently excluded it (and every test
        // exercising it) on Linux, where every resolution would then throw
        // the "did not verify against any" error below despite a
        // genuinely valid signature - never verified, never caught by CI.
        for vm in candidates {
            guard let jwk = vm["publicKeyJwk"] as? [String: Any] else { continue }
            // The verification primitive is selected by the JWS's OWN
            // declared `alg`, not merely by the candidate key's `kty` - a
            // JWK's kty alone must never pick the algorithm (classic JOSE
            // algorithm-confusion class), so an EC key is only tried for
            // `alg: "ES256"` and an OKP/Ed25519 key only for `alg: "EdDSA"`,
            // matching the exact non-nil `alg` already required above
            // (review finding).
            switch (jwk["kty"] as? String, alg) {
            case ("EC", "ES256"):
                guard let publicKeyBytes = try? Self.ecPublicKeyBytesForTrustResolution(fromJwk: jwk),
                      let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeyBytes),
                      let ecdsaSignature = try? P256.Signing.ECDSASignature(rawRepresentation: signature),
                      publicKey.isValidSignature(ecdsaSignature, for: signingInput) else {
                    continue
                }
                return jwk
            case ("OKP", "EdDSA"):
                guard (jwk["crv"] as? String) == "Ed25519",
                      let xStr = jwk["x"] as? String,
                      let rawKey = Self.base64UrlDecodeForTrustResolution(xStr),
                      let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: rawKey),
                      publicKey.isValidSignature(signature, for: signingInput) else {
                    continue
                }
                return jwk
            default:
                continue
            }
        }

        throw SirosError.wallet(
            message: "request_jwt signature did not verify against any resolved verification method for \(resolutionSubjectId)"
        )
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
        guard (jwk["kty"] as? String) == "EC",
              let xStr = jwk["x"] as? String,
              let yStr = jwk["y"] as? String,
              let x = base64UrlDecodeForTrustResolution(xStr),
              let y = base64UrlDecodeForTrustResolution(yStr) else {
            throw SirosError.wallet(message: "Unsupported did: verification method JWK type")
        }
        return Data([0x04]) + x + y
    }
}
