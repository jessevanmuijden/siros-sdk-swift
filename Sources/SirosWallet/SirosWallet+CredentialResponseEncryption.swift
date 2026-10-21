// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

/// Why the wallet could not take a Credential Response. Carries no plaintext, no key material and no
/// credential: an engine that relays the reason (WMP) or a log must learn nothing from it.
enum CredentialResponseError: Error, WmpErrorCodeProviding, Equatable {
    /// `decrypt_credential_response` arrived for a flow with no response-encryption key (never
    /// advertised, or already discarded).
    case noKey
    case decryptFailed
    case malformedResponse
    /// The receiver of `credential_metadata` (delivered-secret validation) refused the response.
    case refused

    var wmpErrorCode: String? {
        switch self {
        case .noKey: return "NO_RESPONSE_KEY"
        case .decryptFailed: return "DECRYPT_FAILED"
        case .malformedResponse: return "MALFORMED_RESPONSE"
        case .refused: return "RESPONSE_REFUSED"
        }
    }
}

/// What the wallet does with a decrypted Credential Response's `credential_metadata` before it keeps it.
///
/// This is the seam where delivered-secret receipt belongs (`DeliveredSecretReceipt`, privatedata-spec
/// section 5A: 1 to 8 namespaces, 32 lowercase hex, a seed needs an encrypted, non-deferred response
/// with a `notification_id`, strip before merge, `SHA256(seed) == ssc`). It runs with the response's
/// facts and throws to refuse the whole response: nothing from it is then stored.
public typealias CredentialMetadataReceiver = @Sendable (
    _ flowId: String,
    _ credentialMetadata: JSONValue?,
    _ jweEncrypted: Bool,
    _ deferred: Bool,
    _ hasNotificationId: Bool
) async throws -> Void

extension SirosWallet {

    // MARK: - generate_proof: the wallet's response-encryption key

    /// A fresh ephemeral key for this proof request, and its public JWK, when the engine asked for
    /// response encryption (`credential_response_encryption`) with a pair this build can open.
    ///
    /// Called per `generate_proof` request, so each c_nonce retry replaces the previous key. The
    /// private half lives only in memory, per flow id, and is dropped when the flow ends, is
    /// cancelled or fails (`resetIssuanceGuards`, `discardCredentialResponseState`).
    ///
    /// nil is a decline: no request, or a pair it cannot open. The engine fails the issuance closed
    /// when it said `required`; otherwise the response comes back in the clear, the issuer's choice.
    func credentialResponseEncryptionJwk(
        flowId: String, request: CredentialResponseEncryptionRequest?
    ) -> [String: String]? {
        lock.lock(); defer { lock.unlock() }
        guard let request,
              let key = CredentialResponseKey(params: CredentialResponseEncryptionParams(alg: request.alg, enc: request.enc)) else {
            credentialResponseKeys.removeValue(forKey: flowId)
            return nil
        }
        credentialResponseKeys[flowId] = key
        return key.publicJwk
    }

    // MARK: - decrypt_credential_response

    /// Decrypt one Credential Response (immediate or deferred) with the flow's key, keep its
    /// credentials and `credential_metadata` here, and return ONLY what the engine needs to carry on:
    /// the deferred-issuance control fields.
    func decryptCredentialResponse(
        flowId: String, jwe: String?, deferred: Bool
    ) async throws -> (transactionId: String?, interval: Int?) {
        lock.lock(); let key = credentialResponseKeys[flowId]; lock.unlock()
        guard let key else { throw CredentialResponseError.noKey }
        guard let jwe, !jwe.isEmpty else { throw CredentialResponseError.malformedResponse }
        let response: DecryptedCredentialResponse
        do {
            response = try DecryptedCredentialResponse.parse(try key.decrypt(jwe))
        } catch is DecryptedCredentialResponse.ParseError {
            throw CredentialResponseError.malformedResponse
        } catch {
            throw CredentialResponseError.decryptFailed
        }
        if let receiver = credentialMetadataReceiver {
            do {
                try await receiver(
                    flowId, response.credentialMetadata, true, deferred,
                    !(response.notificationId ?? "").isEmpty
                )
            } catch {
                throw CredentialResponseError.refused
            }
        }
        lock.lock()
        // A flow that ended while this was decrypting must not leave a response behind.
        if credentialResponseKeys[flowId] != nil {
            decryptedCredentialResponses[flowId, default: []].append(response)
        }
        lock.unlock()
        return (response.transactionId, response.interval)
    }

    /// The responses decrypted for this flow, removed from the store (a flow completes once).
    func takeDecryptedCredentialResponses(flowId: String) -> [DecryptedCredentialResponse] {
        lock.lock(); defer { lock.unlock() }
        return decryptedCredentialResponses.removeValue(forKey: flowId) ?? []
    }

    /// Forget this flow's key and anything decrypted for it.
    func discardCredentialResponseState(flowId: String) {
        lock.lock()
        credentialResponseKeys.removeValue(forKey: flowId)
        decryptedCredentialResponses.removeValue(forKey: flowId)
        lock.unlock()
    }

    // MARK: - flow_complete pairing

    /// `flow_complete.credentials` of an encrypted response carry no `credential`: entry i is the i-th
    /// credential the wallet decrypted. The result has each credential value filled in and the
    /// `notification_id` of the response it arrived in (the engine registered its notification
    /// context with an empty id, so the wallet supplies it). A count mismatch is an error: nothing
    /// is paired by guesswork.
    static func pairEncryptedCredentials(
        entries: [CredentialResult], decrypted: [DecryptedCredentialResponse]
    ) -> [CredentialResult]? {
        var credentials: [(value: String, notificationId: String?)] = []
        for response in decrypted {
            for value in response.credentials { credentials.append((value, response.notificationId)) }
        }
        guard credentials.count == entries.count else { return nil }
        return zip(entries, credentials).map { entry, decrypted in
            CredentialResult(
                format: entry.format, credential: decrypted.value, vct: entry.vct,
                typeMetadata: entry.typeMetadata, notificationId: decrypted.notificationId ?? entry.notificationId
            )
        }
    }

    // MARK: - Transport glue

    /// `decrypt_credential_response` on the engine WebSocket: answer with the control fields and
    /// nothing else; a failure answers with an error that carries no plaintext and drops the flow's state.
    func answerDecryptCredentialResponse(engine: any SignResponseSender, msg: SignRequestMessage) async {
        do {
            let control = try await decryptCredentialResponse(
                flowId: msg.flowId, jwe: msg.params.jwe, deferred: msg.params.deferred ?? false
            )
            engine.sendSignResponse(
                flowId: msg.flowId, transactionId: control.transactionId, interval: control.interval, messageId: msg.messageId
            )
        } catch {
            if Task.isCancelled || error is CancellationError { return }
            let code = (error as? CredentialResponseError)?.wmpErrorCode ?? "DECRYPT_FAILED"
            discardCredentialResponseState(flowId: msg.flowId)
            engine.sendSignResponse(
                flowId: msg.flowId, error: "credential response could not be taken", errorCode: code, messageId: msg.messageId
            )
            reportSignFailure(flowId: msg.flowId, message: code)
        }
    }

    /// The same action over WMP; the profile reports a failure as a flow error carrying only the code.
    func wmpDecryptCredentialResponse(flowId: String, params: SignSubFlowParams) async throws -> SignSubFlowResult {
        do {
            let control = try await decryptCredentialResponse(flowId: flowId, jwe: params.jwe, deferred: params.deferred ?? false)
            return SignSubFlowResult(transactionId: control.transactionId, interval: control.interval)
        } catch {
            discardCredentialResponseState(flowId: flowId)
            throw (error as? CredentialResponseError) ?? CredentialResponseError.decryptFailed
        }
    }

    /// The WMP `flow_complete` result as a `FlowCompleteMessage`, when it says the issuer's response
    /// was encrypted to this wallet's key (`credential_response_encrypted`); nil otherwise, or when
    /// the result does not decode.
    static func encryptedFlowComplete(flowId: String, result: AnyCodable?) -> FlowCompleteMessage? {
        guard var object = result?.objectValue, object["credential_response_encrypted"]?.boolValue == true else { return nil }
        object["type"] = .string(MessageTypes.flowComplete)
        object["flow_id"] = .string(flowId)
        guard let data = try? JSONEncoder().encode(AnyCodable.object_(object)) else { return nil }
        return try? JSONDecoder().decode(FlowCompleteMessage.self, from: data)
    }
}
