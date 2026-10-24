// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

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
    /// The engine REQUIRES response encryption with an `alg`/`enc` pair this build cannot open.
    case unsupportedRequiredPair
    /// The session this request arrived on has ended (logout, destroy, terminal failure): nothing is allocated for it.
    case sessionEnded
    /// A pending (deferred) response carried a delivered seed.
    case deferredSeed
    /// The request arrived on a socket that has since been replaced: dropped, never answered.
    case staleSocket
    /// The request is for a flow that already ended.
    case flowEnded

    var wmpErrorCode: String? {
        switch self {
        case .deferredSeed: return "DEFERRED_SEED"
        case .staleSocket: return "STALE_SOCKET"
        case .flowEnded: return "FLOW_ENDED"
        case .sessionEnded: return "SESSION_ENDED"
        case .unsupportedRequiredPair: return "UNSUPPORTED_RESPONSE_ENCRYPTION"
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
        // Checked here, in the same critical section that stores the key: a request that was live when it started
        // and resumed after teardown must not leave a retained private key behind.
        if blindSessionEnded { return nil }
        if let generation, generation != credentialResponseGenerationLocked(flowId: flowId) { return nil }
        guard let request,
              let key = CredentialResponseKey(params: CredentialResponseEncryptionParams(alg: request.alg, enc: request.enc)) else {
            credentialResponseKeys.removeValue(forKey: flowId)
            return nil
        }
        credentialResponseKeys[flowId] = key
        offeredResponseKeyFlows.insert(flowId)
        // The flow's original issuance epoch, captured once at its first key (before a later cancel or newer
        // start can advance it): a WMP completion is processed under it, see `handleWmpFlowComplete`.
        if wmpFlowIssuanceEpochs[flowId] == nil { wmpFlowIssuanceEpochs[flowId] = issuanceEpoch }
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

    /// Whether this build can open the pair the engine negotiated.
    static func canOpen(_ request: CredentialResponseEncryptionRequest) -> Bool {
        CredentialResponseEncryptionParams(alg: request.alg, enc: request.enc).isSupported
    }

    /// Whether a `generate_proof` request is for the key alone: the engine asked for response
    /// encryption for a configuration without `proof_types_supported`, so no proofs are returned.
    /// A request that names a `proof_type` still wants a proof, whatever `proof_types_supported` says.
    static func isKeyOnlyProofRequest(
        request: CredentialResponseEncryptionRequest?, proofTypesSupported: [String: AnyCodable]?, proofType: String? = nil
    ) -> Bool {
        request != nil && (proofTypesSupported ?? [:]).isEmpty && (proofType ?? "").isEmpty
    }

    // MARK: - decrypt_credential_response

    /// Decrypt one Credential Response (immediate or deferred) with the flow's key, keep its
    /// credentials and `credential_metadata` here, and return ONLY what the engine needs to carry on:
    /// the deferred-issuance control fields.
    func decryptCredentialResponse(
        flowId: String, jwe: String?, deferred: Bool
    ) async throws -> CredentialResponseControl {
        lock.lock()
        let ended = blindSessionEnded
        let key = credentialResponseKeys[flowId]
        let generation = credentialResponseGenerationLocked(flowId: flowId)
        lock.unlock()
        if ended { throw CredentialResponseError.sessionEnded }
        guard let key else { throw CredentialResponseError.noKey }
        guard let jwe, !jwe.isEmpty else { throw CredentialResponseError.malformedResponse }
        let plaintext: Data
        do { plaintext = try key.decrypt(jwe) } catch { throw CredentialResponseError.decryptFailed }
        let response: DecryptedCredentialResponse
        do {
            response = try DecryptedCredentialResponse.parse(plaintext)
        } catch {
            // Read but rejected: the issuer is owed a credential_failure for it, and the id is in the body.
            await sendCredentialFailure(flowId: flowId, notificationId: DecryptedCredentialResponse.notificationId(in: plaintext))
            throw CredentialResponseError.malformedResponse
        }
        // Exactly one of: credentials (1 to 256) or a transaction_id. Both, neither or too many is not a
        // response this wallet accepts.
        guard response.credentials.isEmpty != (response.transactionId == nil), response.credentials.count <= 256 else {
            await sendCredentialFailure(flowId: flowId, notificationId: response.notificationId)
            throw CredentialResponseError.malformedResponse
        }
        // A PENDING response (transaction_id) never carries the delivered seed: a seed needs the final, encrypted
        // response. It is refused here whether or not a receiver is installed, and the issuer is told, not left
        // to have it silently dropped before any seed check runs.
        if response.transactionId != nil, case .object(let members)? = response.credentialMetadata,
           members["org.siros.secret_seed"] != nil {
            await sendCredentialFailure(flowId: flowId, notificationId: response.notificationId)
            throw CredentialResponseError.deferredSeed
        }
        if let receiver = credentialMetadataReceiver {
            do {
                try await receiver(flowId, response, deferred)
            } catch is CancellationError {
                // A cancelled request is not a rejection: no `credential_failure`, no cleanup here.
                throw CancellationError()
            } catch {
                // A request cancelled while the receiver was suspended is not a rejection, whatever the receiver threw.
                if Task.isCancelled { throw CancellationError() }
                // The response was read and rejected: the issuer is owed a credential_failure for it
                // (the engine registered the notification context before relaying the first JWE).
                await sendCredentialFailure(flowId: flowId, notificationId: response.notificationId)
                throw CredentialResponseError.refused
            }
        }
        // A cancelled sign request (a WMP child flow) must not leave a response behind either.
        try Task.checkCancellation()
        lock.lock()
        // The flow may have ended, been cancelled, or been given a new key while the receiver was
        // suspended: that response is stale and is neither kept nor reported as taken.
        guard credentialResponseKeys[flowId] === key, generation == credentialResponseGenerationLocked(flowId: flowId) else {
            lock.unlock()
            throw CredentialResponseError.noKey
        }
        // Only a response that carries credentials is kept (a deferred poll's answer has nothing to pair, and its
        // metadata tree, up to 1 MiB, must not pile up per poll), and never more than the engine's 256 credentials
        // for the flow.
        // The same JWE delivered again (the engine retrying a child whose answer was lost or cancelled) is idempotent:
        // it is recognised by its digest and not retained a second time, so the parent's count still pairs.
        var retained = response
        retained.sourceDigest = SHA256.hash(data: Data(jwe.utf8)).map { String(format: "%02x", $0) }.joined()
        let held = decryptedCredentialResponses[flowId, default: []]
        let duplicate = held.contains { $0.sourceDigest == retained.sourceDigest }
        let heldCount = held.reduce(0) { $0 + $1.credentials.count }
        guard duplicate || heldCount + response.credentials.count <= 256 else {
            lock.unlock()
            // Read and rejected: the issuer is owed a credential_failure, ahead of the error answer.
            await sendCredentialFailure(flowId: flowId, notificationId: response.notificationId)
            throw CredentialResponseError.malformedResponse
        }
        if !response.credentials.isEmpty, !duplicate { decryptedCredentialResponses[flowId, default: []].append(retained) }
        lock.unlock()
        if let transactionId = response.transactionId {
            return CredentialResponseControl(transactionId: transactionId, interval: response.interval)
        }
        return CredentialResponseControl(credentialCount: response.credentials.count)
    }

    /// `credential_failure` for a decrypted response this wallet rejected.
    ///
    /// Where the transport can say when the notification was handed over, it is awaited, so it precedes the
    /// error answer that follows (the engine registered the notification context before relaying the JWE).
    func sendCredentialFailure(flowId: String, notificationId: String?) async {
        guard let notificationId, !notificationId.isEmpty else { return }
        lock.lock(); let notifier = credentialNotifier; lock.unlock()
        if let awaitable = notifier as? AwaitableCredentialNotifier {
            await awaitable.sendCredentialNotificationAndWait(
                flowId: flowId, notificationId: notificationId, event: CredentialNotificationEvent.failure, eventDescription: nil
            )
        } else {
            notifier?.sendCredentialNotification(flowId: flowId, notificationId: notificationId, event: CredentialNotificationEvent.failure)
        }
    }

    /// The responses decrypted for this flow, removed from the store (a flow completes once).
    func takeDecryptedCredentialResponses(flowId: String) -> [DecryptedCredentialResponse] {
        lock.lock(); defer { lock.unlock() }
        return decryptedCredentialResponses.removeValue(forKey: flowId) ?? []
    }

    /// Nothing of blind issuance stays reachable once the wallet is locked or the session ends: every
    /// flow's private response key and everything opened with it (credentials, a delivered seed).
    /// Refuses a request that reaches a session that has ended, or (on the WebSocket) one that arrived on a
    /// superseded engine session, BEFORE any key or flow state is allocated for it.
    ///
    /// Validating and claiming are ONE step under the teardown lock: the generation it returns is read in the same
    /// critical section as the "session is live" check, so a teardown that lands after the check cannot be followed
    /// by a claim made on a generation taken after it.
    ///
    /// A request is also refused when its flow already ended (a buffered request handled after the flow's terminal
    /// cleanup must not take the incremented end counter as a live generation), and, on the WebSocket, when it was
    /// received on a socket the engine session has since replaced.
    @discardableResult
    func requireLiveSession(
        flowId: String, engine: (any SignResponseSender)? = nil, socketGeneration: Int? = nil, requestEpoch: Int? = nil
    ) throws -> [Int] {
        lock.lock(); defer { lock.unlock() }
        if blindSessionEnded { throw CredentialResponseError.sessionEnded }
        if let engine, let current = engineSession, (engine as AnyObject) !== (current as AnyObject) {
            throw CredentialResponseError.sessionEnded
        }
        if let socketGeneration, let current = engineSession, current.socketGeneration != socketGeneration {
            throw CredentialResponseError.staleSocket
        }
        // Received before the issuance was cancelled (possibly before any flow was named): refused.
        if let requestEpoch, let current = engineSession, current.requestEpoch != requestEpoch {
            throw CredentialResponseError.staleSocket
        }
        if (flowEndSeq[flowId] ?? 0) > 0 { throw CredentialResponseError.flowEnded }
        return credentialResponseGenerationLocked(flowId: flowId)
    }

    var sessionHasEnded: Bool { lock.lock(); defer { lock.unlock() }; return blindSessionEnded }

    /// Marks the session ended: requests that still arrive for it are refused. A new connection clears it.
    func markSessionEnded(_ ended: Bool) {
        lock.lock(); blindSessionEnded = ended; lock.unlock()
    }

    func clearBlindIssuanceState() {
        lock.lock()
        credentialResponseKeys.removeAll()
        decryptedCredentialResponses.removeAll()
        responseKeyOrigin.removeAll()
        offeredResponseKeyFlows.removeAll()
        wmpFlowIssuanceEpochs.removeAll()
        credentialResponseEpoch += 1
        lock.unlock()
    }

    /// Whether the flow already ended here (completed, failed, cancelled): a late completion for it is not honoured.
    func flowAlreadyEnded(_ flowId: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return (flowEndSeq[flowId] ?? 0) > 0
    }

    /// A completion whose credentials were decrypted but cannot be stored (the engine's list does not match, or cannot be
    /// read): the issuer is told with one `credential_failure` per distinct notification id of the decrypted responses,
    /// then the issuance ends. Their responses have already left the retained state.
    func rejectDecryptedCompletion(flowId: String, responses: [DecryptedCredentialResponse], message: String) async {
        let ids = Set(responses.compactMap(\.notificationId).filter { !$0.isEmpty }).sorted()
        for id in ids { await sendCredentialFailure(flowId: flowId, notificationId: id) }
        await failIssuanceLocally(flowId: flowId, message: message)
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
        // An encrypted completion reports at least one credential (the wallet answered `credential_count` 1 to 256).
        guard !entries.isEmpty, credentials.count == entries.count else { return nil }
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
        let liveGeneration: [Int]
        do { liveGeneration = try requireLiveSession(flowId: msg.flowId, engine: engine, socketGeneration: msg.socketGeneration, requestEpoch: msg.requestEpoch) } catch {
            if sessionHasEnded {
                engine.sendSignResponse(flowId: msg.flowId, error: "session ended", errorCode: CredentialResponseError.sessionEnded.wmpErrorCode, messageId: msg.messageId)
            } else if error as? CredentialResponseError == .flowEnded {
                // The flow's key is gone with the flow: a decrypt is answered (the engine waits for it), allocating nothing.
                engine.sendSignResponse(flowId: msg.flowId, error: "credential response could not be taken", errorCode: CredentialResponseError.noKey.wmpErrorCode, messageId: msg.messageId)
            }
            return
        }
        // Taken before the awaits: a failure that arrives after this flow was cancelled (and perhaps another begun)
        // is answered to the engine, but must not touch the wallet-wide state of whatever runs now.
        let generation = liveGeneration
        let keyAtStart = responseKey(flowId: msg.flowId)
        do {
            let control = try await decryptCredentialResponse(
                flowId: msg.flowId, jwe: msg.params.jwe, deferred: msg.params.deferred ?? false
            )
            // The reply goes out on the socket that carried the request: after a replacement the engine session would
            // pick the NEW connection, which never asked.
            guard Self.receivedOnCurrentSocket(engine, msg) else { return }
            engine.sendSignResponse(
                flowId: msg.flowId, credentialCount: control.credentialCount, transactionId: control.transactionId,
                interval: control.interval, messageId: msg.messageId
            )
        } catch {
            if Task.isCancelled || error is CancellationError { return }
            guard Self.receivedOnCurrentSocket(engine, msg) else { return }
            let code = (error as? CredentialResponseError)?.wmpErrorCode ?? "DECRYPT_FAILED"
            // A key replaced by a newer `generate_proof` meanwhile is a stale operation, not a failure of the flow.
            let current = generation == credentialResponseGeneration(flowId: msg.flowId) && !keySuperseded(flowId: msg.flowId, since: keyAtStart)
            if current { discardCredentialResponseState(flowId: msg.flowId) }
            engine.sendSignResponse(
                flowId: msg.flowId, error: "credential response could not be taken", errorCode: code, messageId: msg.messageId
            )
            if current { reportSignFailure(flowId: msg.flowId, message: code) }
        }
    }

    /// Whether the connection `msg` arrived on is still the engine session's current one.
    static func receivedOnCurrentSocket(_ engine: any SignResponseSender, _ msg: SignRequestMessage) -> Bool {
        guard let session = engine as? WalletEngineSession else { return true }
        return session.socketGeneration == msg.socketGeneration
    }

    func responseKey(flowId: String) -> CredentialResponseKey? {
        lock.lock(); defer { lock.unlock() }
        return credentialResponseKeys[flowId]
    }

    /// Whether the flow's key was replaced (by a newer `generate_proof`) since `key` was read.
    func keySuperseded(flowId: String, since key: CredentialResponseKey?) -> Bool {
        guard let current = responseKey(flowId: flowId) else { return false }
        return current !== key
    }

    /// The same action over WMP; the profile reports a failure as a flow error carrying only the code.
    func wmpDecryptCredentialResponse(flowId: String, params: SignSubFlowParams) async throws -> SignSubFlowResult {
        let generation = try requireLiveSession(flowId: flowId)
        let keyAtStart = responseKey(flowId: flowId)
        do {
            let control = try await decryptCredentialResponse(flowId: flowId, jwe: params.jwe, deferred: params.deferred ?? false)
            return SignSubFlowResult(
                transactionId: control.transactionId, interval: control.interval, credentialCount: control.credentialCount
            )
        } catch {
            // A cancelled child answers nothing and ends nothing here: whoever cancelled owns the cleanup.
            if error is CancellationError || Task.isCancelled { throw error }
            // The profile's flow error goes to the peer only; the wallet's own terminal handling is here.
            let code = (error as? CredentialResponseError) ?? CredentialResponseError.decryptFailed
            // A flow that was cancelled meanwhile (and perhaps replaced) is not failed again here.
            if generation != credentialResponseGeneration(flowId: flowId) || keySuperseded(flowId: flowId, since: keyAtStart) { throw code }
            await failIssuanceLocally(flowId: flowId, message: code.wmpErrorCode ?? "DECRYPT_FAILED")
            throw code
        }
    }

    /// Local terminal handling of a flow the wallet is failing itself: drop its response state, end the
    /// issuance and tell the listener.
    func failIssuanceLocally(flowId: String, message: String) async {
        cancelTransactionTasks(flowId: flowId)
        discardCredentialResponseState(flowId: flowId)
        resetIssuanceGuards()
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onFlowError(flowId: flowId, errorMessage: message, redirectUri: nil)
        // A wallet that was flow-active is ready again: the issuance is over.
        await restoreReadyState()
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
    ) async throws -> (proofs: [ProofObject], attestedKeyIds: [String]?) {
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
        return (
            generated.map { ProofObject(proofType: $0.proofType, jwt: $0.jwt, attestation: $0.attestation) },
            flattenedKeyIds.isEmpty ? nil : flattenedKeyIds
        )
    }

    /// Applies what proof generation decided, only if the request was not cancelled meanwhile (a cancelled
    /// sign child must not write issuance state or install a key for a flow that is being torn down).
    ///
    /// The flow's captured generation is validated under the same lock that commits the key ids: a proof that
    /// finishes after its flow was cancelled or failed (or the session ended) must not write the old flow's key ids
    /// into whatever issuance runs now.
    func applyProofResult(_ attestedKeyIds: [String]?, flowId: String, generation: [Int]) throws {
        try Task.checkCancellation()
        lock.lock(); defer { lock.unlock() }
        guard !blindSessionEnded, generation == credentialResponseGenerationLocked(flowId: flowId) else {
            throw CancellationError()
        }
        activeAttestedKeyIds = attestedKeyIds
    }

    /// `generate_proof` on the engine WebSocket: the proofs (none when the request is for the key alone)
    /// and, when the engine asked for response encryption, a fresh key's public JWK.
    func answerGenerateProof(engine: any SignResponseSender, msg: SignRequestMessage) async throws {
        let liveGeneration: [Int]
        do { liveGeneration = try requireLiveSession(flowId: msg.flowId, engine: engine, socketGeneration: msg.socketGeneration, requestEpoch: msg.requestEpoch) } catch {
            // A request from a superseded socket is dropped; one for an ended session is refused. Neither allocates.
            if sessionHasEnded {
                engine.sendSignResponse(flowId: msg.flowId, error: "session ended", errorCode: CredentialResponseError.sessionEnded.wmpErrorCode, messageId: msg.messageId)
            }
            return
        }
        // A required pair this build cannot open is ANSWERED with an error (the engine fails the issuance at
        // once), never left to its sign timeout.
        if let request = msg.params.credentialResponseEncryption, request.required == true, !Self.canOpen(request) {
            engine.sendSignResponse(
                flowId: msg.flowId, error: "response encryption is required with a pair this wallet cannot open",
                errorCode: CredentialResponseError.unsupportedRequiredPair.wmpErrorCode, messageId: msg.messageId
            )
            return
        }
        let generation = liveGeneration
        let encryption = msg.params.credentialResponseEncryption
        let keyOnly = Self.isKeyOnlyProofRequest(request: encryption, proofTypesSupported: msg.params.proofTypesSupported, proofType: msg.params.proofType)
        var proofs: [ProofObject] = []
        if !keyOnly {
            let generated = try await proofObjects(
                audience: msg.params.audience ?? "", nonce: msg.params.nonce ?? "", count: msg.params.count ?? 1,
                proofTypesSupported: msg.params.proofTypesSupported, proofTypeHint: msg.params.proofType
            )
            try applyProofResult(generated.attestedKeyIds, flowId: msg.flowId, generation: generation)
            proofs = generated.proofs
        }
        try Task.checkCancellation()
        // A flow that ended meanwhile gets no reply (not even proofs) built from its stale state.
        if generation != credentialResponseGeneration(flowId: msg.flowId) { throw CancellationError() }
        let jwk = credentialResponseEncryptionJwk(flowId: msg.flowId, request: encryption, generation: generation)
        if jwk != nil, let session = engine as? WalletEngineSession {
            // Which socket created this key: a later replacement's cleanup removes only keys of EARLIER sockets.
            lock.lock(); responseKeyOrigin[msg.flowId] = (ObjectIdentifier(session), msg.socketGeneration); lock.unlock()
        }
        engine.sendSignResponse(
            flowId: msg.flowId, proofs: proofs.isEmpty ? nil : proofs, credentialResponseEncryptionJwk: jwk, messageId: msg.messageId
        )
    }

    /// The same over WMP: response encryption without `proof_types_supported` is the key-only request
    /// (WMP openid4x section 3.1.5.1), and a supplied list is forwarded to the proof selection.
    func wmpGenerateProof(flowId: String, params: SignSubFlowParams) async throws -> SignSubFlowResult {
        let generation = try requireLiveSession(flowId: flowId)
        if let request = params.credentialResponseEncryption, request.required == true, !Self.canOpen(request) {
            throw CredentialResponseError.unsupportedRequiredPair   // a flow error with its code, rejected
        }
        let encryption = params.credentialResponseEncryption
        let keyOnly = Self.isKeyOnlyProofRequest(request: encryption, proofTypesSupported: params.proofTypesSupported, proofType: params.proofType)
        var proofs: [ProofObject] = []
        if !keyOnly {
            let generated = try await proofObjects(
                audience: params.audience, nonce: params.nonce, count: params.count ?? 1,
                proofTypesSupported: params.proofTypesSupported, proofTypeHint: params.proofType
            )
            try applyProofResult(generated.attestedKeyIds, flowId: flowId, generation: generation)
            proofs = generated.proofs
        }
        try Task.checkCancellation()
        if generation != credentialResponseGeneration(flowId: flowId) { throw CancellationError() }
        let jwk = credentialResponseEncryptionJwk(flowId: flowId, request: encryption, generation: generation)
        return SignSubFlowResult(proofs: proofs.isEmpty ? nil : proofs, credentialResponseEncryptionJwk: jwk)
    }
}
