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

/// What the wallet does with a decrypted Credential Response before it keeps it.
///
/// This is the seam where delivered-secret receipt belongs (`DeliveredSecretReceipt`, privatedata-spec
/// section 5A: 1 to 8 namespaces, 32 lowercase hex, a seed needs an encrypted, non-deferred response
/// with a `notification_id`, strip before merge, `SHA256(seed) == ssc`). It gets the whole response
/// (the credentials, so a commitment such as `ssc` can be checked against each one of a batch, the
/// `notification_id` and the `credential_metadata`) and whether it answers a deferred request; the
/// response reached it through the wallet's own decryption, so it IS encrypted. It throws to refuse
/// the whole response: nothing from it is then stored, and the issuer is told `credential_failure`.
public typealias CredentialMetadataReceiver = @Sendable (
    _ flowId: String,
    _ response: DecryptedCredentialResponse,
    _ deferred: Bool
) async throws -> Void

/// What `decrypt_credential_response` answers with: exactly one of a count of issued credentials or
/// the deferred-issuance control fields.
struct CredentialResponseControl: Equatable {
    var credentialCount: Int?
    var transactionId: String?
    var interval: Int?
}

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
    /// - Parameter generation: `credentialResponseGeneration(flowId:)` taken BEFORE the awaits that
    ///   precede this call (proof generation). If the flow ended, was cancelled or the session was
    ///   torn down meanwhile, no key is created and nothing is returned.
    func credentialResponseEncryptionJwk(
        flowId: String, request: CredentialResponseEncryptionRequest?, generation: [Int]? = nil
    ) -> [String: String]? {
        lock.lock(); defer { lock.unlock() }
        if let generation, generation != credentialResponseGenerationLocked(flowId: flowId) { return nil }
        guard let request,
              let key = CredentialResponseKey(params: CredentialResponseEncryptionParams(alg: request.alg, enc: request.enc)) else {
            credentialResponseKeys.removeValue(forKey: flowId)
            return nil
        }
        credentialResponseKeys[flowId] = key
        return key.publicJwk
    }

    /// A token that changes when this flow ends or the session is torn down (cancel, logout).
    func credentialResponseGeneration(flowId: String) -> [Int] {
        lock.lock(); defer { lock.unlock() }
        return credentialResponseGenerationLocked(flowId: flowId)
    }

    private func credentialResponseGenerationLocked(flowId: String) -> [Int] {
        [credentialResponseEpoch, flowEndSeq[flowId] ?? 0]
    }

    /// Whether a `generate_proof` request is for the key alone: the engine asked for response
    /// encryption for a configuration without `proof_types_supported`, so no proofs are returned.
    static func isKeyOnlyProofRequest(request: CredentialResponseEncryptionRequest?, proofTypesSupported: [String: AnyCodable]?) -> Bool {
        request != nil && (proofTypesSupported ?? [:]).isEmpty
    }

    // MARK: - decrypt_credential_response

    /// Decrypt one Credential Response (immediate or deferred) with the flow's key, keep its
    /// credentials and `credential_metadata` here, and return ONLY what the engine needs to carry on:
    /// the deferred-issuance control fields.
    func decryptCredentialResponse(
        flowId: String, jwe: String?, deferred: Bool
    ) async throws -> CredentialResponseControl {
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
        // Exactly one of: credentials (1 to 256) or a transaction_id. Both, neither or too many is not a
        // response this wallet accepts.
        guard response.credentials.isEmpty != (response.transactionId == nil), response.credentials.count <= 256 else {
            throw CredentialResponseError.malformedResponse
        }
        if let receiver = credentialMetadataReceiver {
            do {
                try await receiver(flowId, response, deferred)
            } catch {
                // The response was read and rejected: the issuer is owed a credential_failure for it
                // (the engine registered the notification context before relaying the first JWE).
                sendCredentialFailure(flowId: flowId, notificationId: response.notificationId)
                throw CredentialResponseError.refused
            }
        }
        lock.lock()
        // A flow that ended while this was decrypting must not leave a response behind.
        if credentialResponseKeys[flowId] != nil {
            decryptedCredentialResponses[flowId, default: []].append(response)
        }
        lock.unlock()
        if let transactionId = response.transactionId {
            return CredentialResponseControl(transactionId: transactionId, interval: response.interval)
        }
        return CredentialResponseControl(credentialCount: response.credentials.count)
    }

    /// `credential_failure` for a decrypted response this wallet rejected.
    private func sendCredentialFailure(flowId: String, notificationId: String?) {
        guard let notificationId, !notificationId.isEmpty else { return }
        lock.lock(); let notifier = credentialNotifier; lock.unlock()
        notifier?.sendCredentialNotification(
            flowId: flowId, notificationId: notificationId, event: CredentialNotificationEvent.failure
        )
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
    /// `notification_id` of the response it arrived in, and ONLY that: the engine registered its
    /// notification context with an empty id and never sees one, so an id it supplied is not the issuer's. A count mismatch is an error: nothing
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
                typeMetadata: entry.typeMetadata, notificationId: decrypted.notificationId
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
                flowId: msg.flowId, credentialCount: control.credentialCount, transactionId: control.transactionId,
                interval: control.interval, messageId: msg.messageId
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
            return SignSubFlowResult(
                transactionId: control.transactionId, interval: control.interval, credentialCount: control.credentialCount
            )
        } catch {
            // The profile's flow error goes to the peer only; the wallet's own terminal handling is here.
            let code = (error as? CredentialResponseError) ?? CredentialResponseError.decryptFailed
            failIssuanceLocally(flowId: flowId, message: code.wmpErrorCode ?? "DECRYPT_FAILED")
            throw code
        }
    }

    /// Local terminal handling of a flow the wallet is failing itself: drop its response state, end the
    /// issuance and tell the listener.
    func failIssuanceLocally(flowId: String, message: String) {
        cancelTransactionTasks(flowId: flowId)
        discardCredentialResponseState(flowId: flowId)
        resetIssuanceGuards()
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onFlowError(flowId: flowId, errorMessage: message, redirectUri: nil)
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

    /// Whether a WMP `flow_complete` result says the response was encrypted to this wallet (so a
    /// result that then fails to decode is an error, not a plain completion).
    static func claimsEncryptedResponse(_ result: AnyCodable?) -> Bool {
        result?.objectValue?["credential_response_encrypted"]?.boolValue == true
    }

    // MARK: - generate_proof (proofs and/or the response-encryption key)

    /// The proofs for one `generate_proof` request, in the shapes both transports send.
    private func proofObjects(
        audience: String, nonce: String, count: Int, proofTypesSupported: [String: AnyCodable]?, proofTypeHint: String?
    ) async throws -> [ProofObject] {
        let generated = try await generateProofs(
            audience: audience, nonce: nonce, count: count,
            proofTypesSupported: proofTypesSupported, proofTypeHint: proofTypeHint
        )
        // The "attestation" proof type returns a single GeneratedProofData whose attestedKeyIds already
        // covers the whole batch in order; the "jwt" proof type returns one GeneratedProofData PER
        // credential, each with its own single-element attestedKeyIds - flatMap concatenates either
        // shape into one batch-order list. Taking only the first entry's list would silently drop every
        // index past 0 for a "jwt" batch of more than one credential.
        let flattenedKeyIds = generated.flatMap { $0.attestedKeyIds ?? [] }
        lock.lock(); activeAttestedKeyIds = flattenedKeyIds.isEmpty ? nil : flattenedKeyIds; lock.unlock()
        return generated.map { ProofObject(proofType: $0.proofType, jwt: $0.jwt, attestation: $0.attestation) }
    }

    /// `generate_proof` on the engine WebSocket: the proofs (none when the request is for the key alone)
    /// and, when the engine asked for response encryption, a fresh key's public JWK.
    func answerGenerateProof(engine: any SignResponseSender, msg: SignRequestMessage) async throws {
        let generation = credentialResponseGeneration(flowId: msg.flowId)
        let encryption = msg.params.credentialResponseEncryption
        let keyOnly = Self.isKeyOnlyProofRequest(request: encryption, proofTypesSupported: msg.params.proofTypesSupported)
        let proofs = keyOnly ? [] : try await proofObjects(
            audience: msg.params.audience ?? "", nonce: msg.params.nonce ?? "", count: msg.params.count ?? 1,
            proofTypesSupported: msg.params.proofTypesSupported, proofTypeHint: msg.params.proofType
        )
        let jwk = credentialResponseEncryptionJwk(flowId: msg.flowId, request: encryption, generation: generation)
        engine.sendSignResponse(
            flowId: msg.flowId, proofs: proofs.isEmpty ? nil : proofs, credentialResponseEncryptionJwk: jwk, messageId: msg.messageId
        )
    }

    /// The same over WMP. WMP carries `proof_types_supported` only when the peer sends it: an explicit
    /// empty object with response encryption is the key-only request; absence means proofs as before.
    func wmpGenerateProof(flowId: String, params: SignSubFlowParams) async throws -> SignSubFlowResult {
        let generation = credentialResponseGeneration(flowId: flowId)
        let encryption = params.credentialResponseEncryption
        let keyOnly = encryption != nil && params.proofTypesSupported?.isEmpty == true
        let proofs = keyOnly ? [] : try await proofObjects(
            audience: params.audience, nonce: params.nonce, count: params.count ?? 1,
            proofTypesSupported: nil, proofTypeHint: params.proofType
        )
        let jwk = credentialResponseEncryptionJwk(flowId: flowId, request: encryption, generation: generation)
        return SignSubFlowResult(proofs: proofs.isEmpty ? nil : proofs, credentialResponseEncryptionJwk: jwk)
    }
}
