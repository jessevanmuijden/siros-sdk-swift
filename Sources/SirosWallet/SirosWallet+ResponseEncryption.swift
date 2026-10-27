// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

/// The wallet's half of engine-blind presentation: for `direct_post.jwt` the engine sends the verifier
/// key (`response_encryption`) and the wallet answers with `response_jwe`, a JWE it built itself around
/// the `vp_token`, so the engine posts ciphertext and never holds a presentation.
/// Why the wallet could not build the response to a `direct_post.jwt` presentation. Carries no token and no key.
struct PresentationResponseError: Error, WmpErrorCodeProviding {
    let code = "RESPONSE_ENCRYPTION_FAILED"
    var wmpErrorCode: String? { code }
}

extension SirosWallet {

    /// One token of a presentation, with the DCQL credential query it answers (nil outside DCQL).
    typealias PresentationPart = (queryId: String?, token: String)

    /// Encrypt the presentation for the verifier. `aud` is `verified_request.client_id` as the engine
    /// validated it; a request without one is not answered.
    func encryptedPresentationResponse(
        parts: [PresentationPart], encryption: ResponseEncryptionRequest, state: String?, verifiedRequest: VerifiedRequest?
    ) throws -> String {
        // Only for a request the engine verified as `direct_post.jwt`: any other mode wants the vp_token.
        guard verifiedRequest?.responseMode == "direct_post.jwt" else {
            throw PresentationResponseError()
        }
        // The JWK's own members are read as they arrived: a known member of the wrong type, or ANY `d`, is a bad
        // key and is refused here rather than dropped before the key checks can see it.
        let keyMembers: Set<String> = ["kty", "crv", "x", "y", "kid", "use", "alg"]
        guard encryption.jwk["d"] == nil,
              encryption.jwk.allSatisfy({ !keyMembers.contains($0.key) || $0.value.stringValue != nil }) else {
            throw PresentationResponseError()
        }
        do {
            return try JarmResponse.encrypt(
                vpToken: VpTokenValue.from(parts: parts), state: state, audience: verifiedRequest?.clientId,
                recipientJwk: encryption.jwkStrings, alg: encryption.alg, enc: encryption.enc
            )
        } catch {
            // Whatever failed, the wallet answers nothing rather than a vp_token the engine would post in clear.
            throw PresentationResponseError()
        }
    }

    /// Answer a `sign_presentation` on the engine WebSocket: `response_jwe` and NO `vp_token` when the
    /// engine asked for encryption, the joined `vp_token` as before otherwise.
    func sendPresentationResponse(engine: any SignResponseSender, msg: SignRequestMessage, parts: [PresentationPart]) throws {
        engine.sendSignResponse(try presentationAnswer(msg: msg, parts: parts))
    }

    /// The `sign_response` itself, built without sending it, so a caller that records a consent can build
    /// it before the consent is recorded and treat a failure to build as a failed signing.
    func presentationAnswer(msg: SignRequestMessage, parts: [PresentationPart]) throws -> SignResponseMessage {
        // `response_encryption: null` (or an unreadable one) is not "absent": it must never become a plain vp_token.
        if msg.params.responseEncryptionMember.isExplicitNull || msg.params.responseEncryptionMember.isMalformed {
            throw PresentationResponseError()
        }
        if let encryption = msg.params.responseEncryption {
            let jwe = try encryptedPresentationResponse(
                parts: parts, encryption: encryption, state: msg.params.state, verifiedRequest: msg.params.verifiedRequest
            )
            return SignResponseMessage(flowId: msg.flowId, messageId: msg.messageId, responseJwe: jwe)
        }
        // A verified `direct_post.jwt` request without encryption parameters is not answered with a plain vp_token.
        if msg.params.verifiedRequest?.responseMode == "direct_post.jwt" || msg.params.responseMode == "direct_post.jwt" { throw PresentationResponseError() }
        return SignResponseMessage(
            flowId: msg.flowId, messageId: msg.messageId, vpToken: parts.map(\.token).joined(separator: "\n")
        )
    }

    /// The same over WMP.
    func wmpPresentationResult(params: SignSubFlowParams, parts: [PresentationPart]) throws -> SignSubFlowResult {
        guard let encryption = params.responseEncryption else {
            if params.verifiedRequest?.responseMode == "direct_post.jwt" || params.responseMode == "direct_post.jwt" { throw PresentationResponseError() }
            return SignSubFlowResult(vpToken: parts.map(\.token).joined(separator: "\n"))
        }
        return SignSubFlowResult(responseJwe: try encryptedPresentationResponse(
            parts: parts, encryption: encryption, state: params.state, verifiedRequest: params.verifiedRequest
        ))
    }
}

/// What building one credential's presentation takes from the request beyond the credential itself,
/// whichever transport carried the request.
struct SignPresentationContext {
    var verifierSessionId: String?
    var responseUri: String?
    var verifierJwkThumbprint: String?

    init(_ params: SignRequestParams) {
        verifierSessionId = params.verifierSessionId
        responseUri = params.responseUri
        verifierJwkThumbprint = Self.handoverThumbprint(encryption: params.responseEncryption, engine: params.verifierJwkThumbprint)
    }

    init(_ params: SignSubFlowParams) {
        verifierSessionId = params.verifierSessionId
        responseUri = params.responseUri
        verifierJwkThumbprint = Self.handoverThumbprint(encryption: params.responseEncryption, engine: params.verifierJwkThumbprint)
    }

    /// The thumbprint the mdoc `OpenID4VPHandover` binds. For a `direct_post.jwt` request it is the thumbprint of the
    /// key the response is encrypted to (`response_encryption.jwk`), which is what the verifier computes; the engine's
    /// `verifier_jwk_thumbprint` is never used for it (nil, not a fallback, when that key has no thumbprint).
    static func handoverThumbprint(encryption: ResponseEncryptionRequest?, engine: String?) -> String? {
        guard let encryption else { return engine }
        return JwkThumbprint.ec(encryption.jwkStrings)
    }
}
