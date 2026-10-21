// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

/// The wallet's half of engine-blind presentation: for `direct_post.jwt` the engine sends the verifier
/// key (`response_encryption`) and the wallet answers with `response_jwe`, a JWE it built itself around
/// the `vp_token`, so the engine posts ciphertext and never holds a presentation.
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
            throw SirosError.wallet(message: "The presentation response could not be encrypted")
        }
        do {
            return try JarmResponse.encrypt(
                vpToken: VpTokenValue.from(parts: parts), state: state, audience: verifiedRequest?.clientId,
                recipientJwk: encryption.jwkStrings, alg: encryption.alg, enc: encryption.enc
            )
        } catch {
            // Whatever failed, the wallet answers nothing rather than a vp_token the engine would post in clear.
            throw SirosError.wallet(message: "The presentation response could not be encrypted")
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
        if let encryption = msg.params.responseEncryption {
            let jwe = try encryptedPresentationResponse(
                parts: parts, encryption: encryption, state: msg.params.state, verifiedRequest: msg.params.verifiedRequest
            )
            return SignResponseMessage(flowId: msg.flowId, messageId: msg.messageId, responseJwe: jwe)
        }
        return SignResponseMessage(
            flowId: msg.flowId, messageId: msg.messageId, vpToken: parts.map(\.token).joined(separator: "\n")
        )
    }

    /// The same over WMP.
    func wmpPresentationResult(params: SignSubFlowParams, parts: [PresentationPart]) throws -> SignSubFlowResult {
        guard let encryption = params.responseEncryption else {
            return SignSubFlowResult(vpToken: parts.map(\.token).joined(separator: "\n"))
        }
        return SignSubFlowResult(responseJwe: try encryptedPresentationResponse(
            parts: parts, encryption: encryption, state: params.state, verifiedRequest: params.verifiedRequest
        ))
    }

    /// The presentation of each credential a WMP `sign_presentation` names, with its query id: the same
    /// per-credential building as the engine WebSocket (mdoc, ZK and SD-JWT with a key-binding JWT).
    func wmpPresentationParts(flowId: String, params: SignSubFlowParams, refs: [CredentialRef]) async throws -> [PresentationPart] {
        let allCreds = await credentialStore.getAll()
        lock.lock()
        let storedMatchResults = pendingMatchResultsByFlow.removeValue(forKey: flowId)
        lock.unlock()
        var parts: [PresentationPart] = []
        for ref in refs {
            // A flow that ended (or a logout) while the user decided must not sign.
            try Task.checkCancellation()
            guard let cred = allCreds.first(where: { $0.id == Int64(ref.credentialId) }) else { continue }
            let matchResult = storedMatchResults?.first(where: { result in
                result.queryId == ref.credentialQueryId || result.candidates.contains(where: { $0.id == cred.id })
            })
            parts.append((ref.credentialQueryId, try await buildSignPresentationVpPart(
                cred: cred, ref: ref, matchResult: matchResult, nonce: params.nonce, audience: params.audience,
                context: SignPresentationContext(params)
            )))
        }
        try Task.checkCancellation()
        return parts
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
        verifierJwkThumbprint = params.verifierJwkThumbprint
    }

    init(_ params: SignSubFlowParams) {
        verifierSessionId = params.verifierSessionId
        responseUri = params.responseUri
        verifierJwkThumbprint = params.verifierJwkThumbprint
    }
}
