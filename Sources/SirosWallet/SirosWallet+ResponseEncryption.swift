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
        if let encryption = msg.params.responseEncryption {
            let jwe = try encryptedPresentationResponse(
                parts: parts, encryption: encryption, state: msg.params.state, verifiedRequest: msg.params.verifiedRequest
            )
            engine.sendSignResponse(flowId: msg.flowId, responseJwe: jwe, messageId: msg.messageId)
        } else {
            engine.sendSignResponse(flowId: msg.flowId, vpToken: parts.map(\.token).joined(separator: "\n"), messageId: msg.messageId)
        }
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
}
