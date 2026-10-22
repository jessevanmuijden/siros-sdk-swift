// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(os)
import os
#endif

/// WebSocket session client for the wallet backend engine protocol.
///
/// Implements the wallet backend's custom type-based WebSocket protocol
/// (handshake → flow_start → sign_request/match_request → flow_complete).
///
/// Connection sequence:
/// 1. Open WebSocket to `/api/v2/wallet?tenant_id=<tenantId>`
/// 2. Send `{"type":"handshake","app_token":"<jwt>"}`
/// 3. Receive `{"type":"handshake_complete","session_id":"...","capabilities":[...]}`
/// 4. Exchange flow messages until disconnect
public final class WalletEngineSession: CredentialNotifier, @unchecked Sendable {
    public enum State: String, Sendable {
        case disconnected, connecting, connected, reconnecting
        /// Distinct from `.failed`: a reconnect attempt's `tokenProvider` call
        /// itself failed (the access-token/session refresh mechanism was
        /// rejected), not merely that the socket couldn't connect - see
        /// `scheduleReconnect`. `.failed` is reserved for exhausting reconnect
        /// attempts on a transient network-level failure.
        case reauthRequired
        case failed
    }

    #if canImport(os)
    private let logger = Logger(subsystem: "org.siros.sdk", category: "WalletEngineSession")
    private func logWarning(_ msg: String) { logger.warning("\(msg)") }
    #else
    private func logWarning(_ msg: String) { print("[WalletEngineSession WARNING] \(msg)") }
    #endif

    private let baseUrl: String
    private let tenantId: String
    private let session: URLSession

    private let encoder = JSONEncoder()
    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        return d
    }()

    private var _state: State = .disconnected
    private let stateContinuation: AsyncStream<State>.Continuation
    public let stateStream: AsyncStream<State>
    public var currentState: State { _state }

    private var webSocketTask: URLSessionWebSocketTask?
    private var sessionId: String?
    var lastAppToken: String?
    /// Mints a fresh handshake token on demand - called before every
    /// automatic reconnect attempt instead of replaying `lastAppToken`, which
    /// is otherwise never updated after the initial `connect` and goes stale
    /// within minutes (the AS's default access-token TTL is 2 minutes) since
    /// this path had no refresh logic at all. Typically wraps
    /// `AuthTokens.ensureAnonymousToken()`, which already handles
    /// expiry-aware caching - this class only needs to call it, not
    /// duplicate that logic. Nil preserves the old (non-refreshing) behavior
    /// for callers that haven't opted in.
    private var tokenProvider: (() async throws -> String)?
    /// Notified whenever `tokenProvider` itself throws during a reconnect
    /// attempt (see `refreshTokenOrSignalReauth`). `WalletEngineSession`
    /// lives in `SirosTransport`, which `SirosAuth` (home of `AuthTokens`
    /// and its rejection-counting `registerTokenRejection`) itself depends
    /// on - so this can't reference `AuthTokens` directly without a circular
    /// target dependency. A plain closure lets the caller (`SirosWallet`,
    /// which already holds both this session and its `AuthTokens` instance -
    /// see `connectEngine`) wire the two together, the same indirection
    /// `tokenProvider` itself already uses for the analogous problem.
    ///
    /// The thrown `Error` is passed through (rather than a bare `Void`
    /// signal) because `tokenProvider` can fail for reasons that are NOT a
    /// real token rejection - a transient network blip talking to the auth
    /// server, for instance - and the caller is the one able to distinguish
    /// those (it knows the concrete error type `SirosTransport` can't
    /// depend on) before deciding whether this should count toward
    /// `registerTokenRejection`'s forced-logout threshold.
    private var onTokenRejected: ((Error) -> Void)?
    /// Called when the socket is lost and a replacement is about to be attempted: whatever the caller keeps for flows
    /// that were running on the old socket (response keys, opened responses) is not valid for a new one. Called on
    /// every automatic reconnect and when reconnecting gives up, before any new connection is made.
    public var onSocketReplaced: (() -> Void)?
    /// How many sockets this session has opened. A replacement is a socket opened while an earlier one existed.
    private(set) var socketGeneration = 0
    private var reconnectAttempts = 0
    private let maxReconnectAttempts = 5
    private let baseReconnectDelayMs: UInt64 = 1000

    /// Guards `_pingIntervalMs` - read from the ping-loop `Task` (see
    /// `startPingLoop`) and written from `handleMessage`'s
    /// `handshakeComplete` case (via `adoptServerPingInterval`), which can
    /// run on a different thread. A Copilot review on this PR caught the
    /// resulting data race - `WalletEngineSession` being `@unchecked
    /// Sendable` doesn't make an actually-shared mutable property safe, it
    /// just tells the compiler to stop checking.
    private let pingIntervalLock = NSLock()

    /// This session's own WebSocket ping cadence, in milliseconds - starts
    /// at `WalletEngineSession.defaultPingIntervalMs` and is updated
    /// whenever the server reports a different value via
    /// `HandshakeCompleteMessage.config`. Unlike the Kotlin SDK's
    /// OkHttp-based equivalent, `startPingLoop` re-reads this on every
    /// iteration, so a mid-connection update takes effect on this same
    /// connection's very next ping rather than only the next reconnect.
    /// Always access via `currentPingIntervalMs()`/`setPingIntervalMs(_:)`,
    /// never directly - see `pingIntervalLock`.
    private var _pingIntervalMs: Int64 = WalletEngineSession.defaultPingIntervalMs

    private func currentPingIntervalMs() -> Int64 {
        pingIntervalLock.lock()
        defer { pingIntervalLock.unlock() }
        return _pingIntervalMs
    }

    private func setPingIntervalMs(_ value: Int64) {
        pingIntervalLock.lock()
        defer { pingIntervalLock.unlock() }
        _pingIntervalMs = value
    }

    /// Used until (and unless) the server tells us otherwise via
    /// `HandshakeCompleteMessage.config` - see `pingIntervalMs`'s doc
    /// comment. 3s, not some more conventional-sounding round number like
    /// 30s: found empirically (raw idle-TLS-connection tests against
    /// production Fly.io apps, not documentation - Fly's own docs don't
    /// state a number) that Fly.io's edge closes a connection with no
    /// traffic on it after ~5-6s, which is why every engine WebSocket in
    /// production was silently reconnecting every few seconds. Matches
    /// go-wallet-backend's own default (`config.ServerConfig.EngineWSPingInterval`).
    static let defaultPingIntervalMs: Int64 = 3000

    /// Upper bound applied to any value adopted from the server (see
    /// `adoptServerPingInterval`) - another Copilot catch on this PR: a
    /// buggy or compromised server could send an `Int64` close to
    /// `Int64.max`, and `startPingLoop`'s `UInt64(intervalMs) * 1_000_000`
    /// (converting milliseconds to nanoseconds for `Task.sleep`) would
    /// overflow `UInt64` and trap. 60s is already far past any interval
    /// that would still serve this mechanism's actual purpose (staying
    /// under whatever intermediary's idle-connection timeout prompted it),
    /// so anything larger is nonsensical regardless of where it's clamped -
    /// clamping here, at the single point values from the server enter
    /// this type, keeps every reader of `_pingIntervalMs` safe for free.
    static let maxPingIntervalMs: Int64 = 60_000

    // Typed message channels
    private let messagesContinuation: AsyncStream<EngineMessage>.Continuation
    private let _messages: AsyncStream<EngineMessage>

    private let flowProgressContinuation: AsyncStream<FlowProgressMessage>.Continuation
    private let _flowProgress: AsyncStream<FlowProgressMessage>

    private let flowCompleteContinuation: AsyncStream<FlowCompleteMessage>.Continuation
    private let _flowComplete: AsyncStream<FlowCompleteMessage>

    private let flowErrorContinuation: AsyncStream<FlowErrorMessage>.Continuation
    private let _flowErrors: AsyncStream<FlowErrorMessage>

    private let signRequestContinuation: AsyncStream<SignRequestMessage>.Continuation
    private let _signRequests: AsyncStream<SignRequestMessage>

    private let matchRequestContinuation: AsyncStream<MatchRequestMessage>.Continuation
    private let _matchRequests: AsyncStream<MatchRequestMessage>

    private let pushContinuation: AsyncStream<PushMessage>.Continuation
    private let _pushMessages: AsyncStream<PushMessage>

    private let notificationAckContinuation: AsyncStream<NotificationAckMessage>.Continuation
    private let _notificationAcks: AsyncStream<NotificationAckMessage>

    public init(
        baseUrl: String,
        tenantId: String = "default",
        session: URLSession = .shared
    ) {
        self.baseUrl = baseUrl
        self.tenantId = tenantId
        self.session = session

        var stateCont: AsyncStream<State>.Continuation!
        self.stateStream = AsyncStream { stateCont = $0 }
        self.stateContinuation = stateCont

        var msgCont: AsyncStream<EngineMessage>.Continuation!
        self._messages = AsyncStream { msgCont = $0 }
        self.messagesContinuation = msgCont

        var fpCont: AsyncStream<FlowProgressMessage>.Continuation!
        self._flowProgress = AsyncStream { fpCont = $0 }
        self.flowProgressContinuation = fpCont

        var fcCont: AsyncStream<FlowCompleteMessage>.Continuation!
        self._flowComplete = AsyncStream { fcCont = $0 }
        self.flowCompleteContinuation = fcCont

        var feCont: AsyncStream<FlowErrorMessage>.Continuation!
        self._flowErrors = AsyncStream { feCont = $0 }
        self.flowErrorContinuation = feCont

        var srCont: AsyncStream<SignRequestMessage>.Continuation!
        self._signRequests = AsyncStream { srCont = $0 }
        self.signRequestContinuation = srCont

        var mrCont: AsyncStream<MatchRequestMessage>.Continuation!
        self._matchRequests = AsyncStream { mrCont = $0 }
        self.matchRequestContinuation = mrCont

        // Unlike flowProgress/flowComplete/flowErrors/signRequests/
        // matchRequests (all drained internally by SirosWallet's own `for
        // await` loops), pushMessages/notificationAcks are host-app-facing,
        // opt-in APIs - nothing in this SDK consumes them itself. A host app
        // that never calls pushMessages()/notificationAcks() would otherwise
        // grow these streams' default `.unbounded` buffer for the entire
        // connection lifetime. Bounding to the most recent 64 caps that
        // growth without affecting a host app that drains them promptly.
        var pCont: AsyncStream<PushMessage>.Continuation!
        self._pushMessages = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { pCont = $0 }
        self.pushContinuation = pCont

        var naCont: AsyncStream<NotificationAckMessage>.Continuation!
        self._notificationAcks = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { naCont = $0 }
        self.notificationAckContinuation = naCont
    }

    /// All incoming messages as raw `EngineMessage`.
    public func messages() -> AsyncStream<EngineMessage> { _messages }

    /// Server flow progress updates.
    public func flowProgress() -> AsyncStream<FlowProgressMessage> { _flowProgress }

    /// Server flow completion events.
    public func flowComplete() -> AsyncStream<FlowCompleteMessage> { _flowComplete }

    /// Server flow error events.
    public func flowErrors() -> AsyncStream<FlowErrorMessage> { _flowErrors }

    /// Server signing requests.
    public func signRequests() -> AsyncStream<SignRequestMessage> { _signRequests }

    /// Server credential matching requests.
    public func matchRequests() -> AsyncStream<MatchRequestMessage> { _matchRequests }

    /// Server push notifications.
    public func pushMessages() -> AsyncStream<PushMessage> { _pushMessages }

    /// Acknowledgements for OID4VCI §10 credential notifications sent via
    /// `sendCredentialNotification`. Each value reports whether the backend
    /// forwarded the notification to the issuer (`status == "forwarded"`) or
    /// rejected it, including any `error` detail.
    public func notificationAcks() -> AsyncStream<NotificationAckMessage> { _notificationAcks }

    /// Whether the underlying WebSocket is currently connected.
    public var isConnected: Bool { webSocketTask != nil }

    /// Connect to the engine WebSocket and perform the handshake.
    /// - Parameters:
    ///   - appToken: JWT used for this initial handshake (avoids an extra
    ///     round trip re-minting a token we were just handed).
    ///   - tokenProvider: mints a fresh token before each subsequent
    ///     automatic reconnect attempt - see `tokenProvider`'s doc comment.
    ///     Omit only if the caller genuinely has no refresh mechanism to
    ///     offer; every real `SirosWallet` call site should pass one.
    ///   - onTokenRejected: notified when `tokenProvider` itself throws
    ///     during a reconnect attempt - see `onTokenRejected`'s doc comment.
    public func connect(
        appToken: String,
        tokenProvider: (() async throws -> String)? = nil,
        onTokenRejected: ((Error) -> Void)? = nil
    ) {
        guard _state != .connected else { return }
        setState(.connecting)
        lastAppToken = appToken
        self.tokenProvider = tokenProvider
        self.onTokenRejected = onTokenRejected
        reconnectAttempts = 0
        doConnect(appToken: appToken)
    }

    private func doConnect(appToken: String) {
        let wsUrl = baseUrl
            .replacingOccurrences(of: "https://", with: "wss://")
            .replacingOccurrences(of: "http://", with: "ws://")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            + "/api/v2/wallet?tenant_id=\(tenantId)"

        guard let url = URL(string: wsUrl) else {
            setState(.failed)
            return
        }

        var request = URLRequest(url: url)
        request.setValue("wmp.v1", forHTTPHeaderField: "Sec-WebSocket-Protocol")

        // Keyed off the replacement itself, not a state transition: whichever path opens the new socket
        // (automatic reconnect, `forceReconnect`), what the wallet holds for flows that ran on the old one goes.
        if socketGeneration > 0, lastAppToken != nil { onSocketReplaced?() }
        socketGeneration += 1
        let task = session.webSocketTask(with: request)
        self.webSocketTask = task
        task.resume()

        // Send handshake
        let handshake = HandshakeMessage(appToken: appToken)
        if let data = try? encoder.encode(handshake),
           let text = String(data: data, encoding: .utf8) {
            task.send(.string(text)) { [weak self] error in
                if error != nil {
                    self?.scheduleReconnect()
                }
            }
        }

        startReceiveLoop(task)
        startPingLoop(task)
    }

    /// Sends a WebSocket ping every `pingIntervalMs` for as long as `task`
    /// stays open. `URLSessionWebSocketTask` (unlike OkHttp's WebSocket
    /// client) has no automatic client-initiated ping - it only
    /// auto-responds to pings the SERVER sends - so without this, the
    /// client side of the connection never generated any traffic of its
    /// own; see `pingIntervalMs`'s doc comment for why that matters against
    /// production infrastructure. Mirrors `startReceiveLoop`'s
    /// `task.state == .running` loop-exit convention rather than tracking a
    /// separate cancellation handle.
    private func startPingLoop(_ task: URLSessionWebSocketTask) {
        Task { [weak self] in
            while task.state == .running {
                let intervalMs = self?.currentPingIntervalMs() ?? Self.defaultPingIntervalMs
                try? await Task.sleep(nanoseconds: UInt64(intervalMs) * 1_000_000)
                guard task.state == .running else { return }
                task.sendPing { [weak self] error in
                    if let error {
                        self?.logWarning("WebSocket ping failed: \(error)")
                    }
                }
            }
        }
    }

    /// Adopts `config.pingIntervalMs` (clamped to `maxPingIntervalMs`, and
    /// only if present, positive, and different from what this session is
    /// already using) for `pingIntervalMs` - see that property's doc
    /// comment and `maxPingIntervalMs`'s. Split out of `handleMessage`'s
    /// `handshakeComplete` case purely to keep that already-large `switch`
    /// under swiftlint's cyclomatic-complexity ceiling; there's nothing
    /// about this logic itself that needs its own function.
    private func adoptServerPingInterval(from config: SessionConfig?) {
        guard let serverPingIntervalMs = config?.pingIntervalMs, serverPingIntervalMs > 0 else {
            return
        }
        let clamped = min(serverPingIntervalMs, Self.maxPingIntervalMs)
        let current = currentPingIntervalMs()
        guard clamped != current else { return }
        logWarning(
            "Server ping interval (\(clamped)ms) differs from ours " +
            "(\(current)ms) - adopting it"
        )
        setPingIntervalMs(clamped)
    }

    private func startReceiveLoop(_ task: URLSessionWebSocketTask) {
        Task { [weak self] in
            while task.state == .running {
                do {
                    let message = try await task.receive()
                    switch message {
                    case .string(let text):
                        await self?.handleMessage(text)
                    case .data(let data):
                        if let text = String(data: data, encoding: .utf8) {
                            await self?.handleMessage(text)
                        }
                    @unknown default:
                        break
                    }
                } catch {
                    self?.scheduleReconnect()
                    return
                }
            }
        }
    }

    func scheduleReconnect() {
        // Flows that were running on the old socket are gone with it: told at each loss, and only for a connection that was
        // lost, not for one this session was told to drop (`disconnect()` clears the token), whose late failure
        // must not reach a replacement session's state.
        if lastAppToken != nil { onSocketReplaced?() }
        guard lastAppToken != nil, reconnectAttempts < maxReconnectAttempts else {
            setState(.failed)
            return
        }
        setState(.reconnecting)
        reconnectAttempts += 1
        let attempt = reconnectAttempts
        let delayMs = baseReconnectDelayMs * UInt64(1 << min(attempt - 1, 4))

        Task {
            try? await Task.sleep(nanoseconds: delayMs * 1_000_000)
            guard self._state == .reconnecting else { return }
            guard let token = await self.refreshTokenOrSignalReauth() else { return }
            if self._state == .reconnecting {
                self.doConnect(appToken: token)
            }
        }
    }

    /// Mints a fresh token via `tokenProvider` (falling back to
    /// `lastAppToken` if no provider was supplied) for a reconnect attempt.
    /// A provider failure means the refresh mechanism itself was rejected -
    /// not a transient network blip like a socket-connect failure - so this
    /// short-circuits straight to `.reauthRequired` rather than consuming
    /// the remaining backoff budget on a broken session.
    /// - Returns: the token to reconnect with, or nil if reconnecting should
    ///   stop (state has already been updated to reflect why).
    private func refreshTokenOrSignalReauth() async -> String? {
        guard let provider = tokenProvider else { return lastAppToken }
        do {
            let fresh = try await provider()
            lastAppToken = fresh
            return fresh
        } catch {
            // Regardless of why the refresh failed, this reconnect attempt
            // can't proceed without a fresh token - transition to
            // .reauthRequired either way. But NOT every failure here is a
            // real token rejection worth counting toward
            // `AuthTokens.registerTokenRejection`'s forced-logout threshold
            // (see `onTokenRejected`'s doc comment) - a transient network
            // blip talking to the auth server would otherwise accumulate
            // the same as a genuine 401, so the error is handed to the
            // caller to make that distinction rather than assumed here.
            onTokenRejected?(error)
            setState(.reauthRequired)
            return nil
        }
    }

    func handleMessage(_ text: String) async {
        guard let data = text.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let type = json["type"] as? String else {
            return
        }

        switch type {
        case MessageTypes.handshakeComplete:
            if let msg = try? decoder.decode(HandshakeCompleteMessage.self, from: data) {
                sessionId = msg.sessionId
                // A recovered connection starts a fresh retry budget: the next loss is not charged for this one's.
                reconnectAttempts = 0
                setState(.connected)
                adoptServerPingInterval(from: msg.config)
            }
        case MessageTypes.flowProgress:
            if let msg = try? decoder.decode(FlowProgressMessage.self, from: data) {
                flowProgressContinuation.yield(msg)
            }
        case MessageTypes.flowComplete:
            if let msg = try? decoder.decode(FlowCompleteMessage.self, from: data) {
                flowCompleteContinuation.yield(msg)
            }
        case MessageTypes.flowError:
            if let msg = try? decoder.decode(FlowErrorMessage.self, from: data) {
                flowErrorContinuation.yield(msg)
            }
        case MessageTypes.signRequest:
            if let msg = try? decoder.decode(SignRequestMessage.self, from: data) {
                signRequestContinuation.yield(msg)
            }
        case MessageTypes.matchRequest:
            if let msg = try? decoder.decode(MatchRequestMessage.self, from: data) {
                matchRequestContinuation.yield(msg)
            }
        case MessageTypes.push:
            if let msg = try? decoder.decode(PushMessage.self, from: data) {
                pushContinuation.yield(msg)
            }
        case MessageTypes.notificationAck:
            if let msg = try? decoder.decode(NotificationAckMessage.self, from: data) {
                notificationAckContinuation.yield(msg)
            }
        case MessageTypes.error:
            let _ = try? decoder.decode(ErrorMessage.self, from: data)
            setState(.failed)
        default:
            break
        }

        // Also send to raw messages channel
        if let envelope = try? decoder.decode(EngineMessage.self, from: data) {
            messagesContinuation.yield(envelope)
        }
    }

    // MARK: - Client → Server messages

    /// Start an OID4VCI credential issuance flow.
    ///
    /// Wallet attestation is not supplied here: once the engine has resolved
    /// the issuer's authorization server it sends a `request_attestation`
    /// sign request (go-wallet-backend#304), answered from `signRequests()`
    /// via `sendSignResponse(clientAttestation:clientAttestationPoP:)` with a
    /// PoP bound to exactly the `audience`/`issuer` the engine asks for.
    ///
    /// - Parameter authorizationDetails: the OID4VCI `authorization_details`
    ///   to ask with - see ``FlowStartMessage/authorizationDetails``. Nil or
    ///   empty omits the field, leaving the `scope` path unchanged.
    public func startIssuance(
        offer: String? = nil,
        credentialOfferUri: String? = nil,
        redirectUri: String? = nil,
        authorizationDetails: [AuthorizationDetail]? = nil
    ) {
        send(FlowStartMessage(
            protocol: "oid4vci",
            offer: offer,
            credentialOfferUri: credentialOfferUri,
            redirectUri: redirectUri,
            authorizationDetails: (authorizationDetails?.isEmpty ?? true) ? nil : authorizationDetails
        ))
    }

    /// Start an OID4VCI issuance flow with a pre-built Wallet Instance
    /// Attestation + PoP on the FlowStart itself.
    ///
    /// Deprecated: building the PoP up front forces the client to discover
    /// the issuer's authorization server (and guess the flow's `client_id`)
    /// on its own, duplicating work the engine does anyway - and getting it
    /// wrong for issuers with a registered client_id override. Use the
    /// parameterless `startIssuance(offer:credentialOfferUri:redirectUri:)`
    /// and answer the engine's `request_attestation` sign request instead.
    /// The engine still honors attestation supplied this way, so existing
    /// callers keep working.
    @available(*, deprecated, message: "Answer the engine's request_attestation sign request via sendSignResponse(clientAttestation:clientAttestationPoP:) instead of pre-supplying attestation on FlowStart.")
    public func startIssuance(
        offer: String? = nil,
        credentialOfferUri: String? = nil,
        redirectUri: String? = nil,
        clientAttestation: String?,
        clientAttestationPoP: String?
    ) {
        send(FlowStartMessage(
            protocol: "oid4vci",
            offer: offer,
            credentialOfferUri: credentialOfferUri,
            redirectUri: redirectUri,
            clientAttestation: clientAttestation,
            clientAttestationPoP: clientAttestationPoP
        ))
    }

    /// Start an OID4VCI renewal flow: exchange `refreshToken` for a fresh
    /// credential batch instead of running a fresh authorization/pre-
    /// authorized_code grant. See `FlowStartMessage`'s renewal field docs.
    public func startRenewal(
        refreshToken: String,
        credentialIssuer: String,
        selectedCredentialConfigurationId: String,
        reissuanceKid: String? = nil,
        dpopJwk: String? = nil,
        dpopKeyId: String? = nil
    ) {
        send(FlowStartMessage(
            protocol: "oid4vci",
            refreshToken: refreshToken,
            credentialIssuer: credentialIssuer,
            selectedCredentialConfigurationId: selectedCredentialConfigurationId,
            reissuanceKid: reissuanceKid,
            dpopJwk: dpopJwk,
            dpopKeyId: dpopKeyId
        ))
    }

    /// Start an OID4VP credential presentation flow.
    public func startPresentation(
        requestUri: String? = nil,
        requestUriRef: String? = nil,
        features: [String]? = nil
    ) {
        send(FlowStartMessage(
            protocol: "oid4vp",
            requestUri: requestUri,
            requestUriRef: requestUriRef,
            features: features
        ))
    }

    /// Cancel an in-progress flow.
    public func cancelFlow(flowId: String) {
        sendFlowAction(flowId: flowId, action: "decline", payload: ["reason": "user_cancelled"])
    }

    /// Send a flow action (consent, select_credential, etc.).
    public func sendFlowAction(flowId: String, action: String, payload: [String: AnyCodable]? = nil) {
        send(FlowActionMessage(
            flowId: flowId,
            action: action,
            payload: payload,
            timestamp: ISO8601DateFormatter().string(from: Date())
        ))
    }

    /// Send a signing response back to the server.
    ///
    /// Always answer a `sign_request`, even with every payload field nil: the
    /// engine's `RequestSign` blocks on a matching `message_id` for 30 s
    /// before giving up (`ErrSignTimeout`), so an unanswered request stalls
    /// the whole flow for that long. An empty response is how the client
    /// declines (e.g. no Wallet Instance Attestation available for a
    /// `request_attestation`).
    ///
    /// - Parameters:
    ///   - credentialRequestExtras: extra members for the credential request
    ///     the backend will send - see
    ///     `SignResponseMessage.credentialRequestExtras`. Nil for every flow
    ///     that does not need them.
    ///   - clientAttestation/clientAttestationPoP: the WIA and per-flow PoP
    ///     answering a `request_attestation` action - see
    ///     `SignResponseMessage.clientAttestation`.
    public func sendSignResponse(
        flowId: String,
        proofJwt: String? = nil,
        vpToken: String? = nil,
        proofs: [ProofObject]? = nil,
        credentialRequestExtras: [String: AnyCodable]? = nil,
        clientAttestation: String? = nil,
        clientAttestationPoP: String? = nil,
        dpopKeyId: String? = nil,
        dpopProof: String? = nil,
        credentialResponseEncryptionJwk: [String: String]? = nil,
        credentialCount: Int? = nil,
        responseJwe: String? = nil,
        transactionId: String? = nil,
        interval: Int? = nil,
        error: String? = nil,
        errorCode: String? = nil,
        messageId: String? = nil
    ) {
        send(SignResponseMessage(
            flowId: flowId,
            messageId: messageId,
            proofJwt: proofJwt,
            vpToken: vpToken,
            proofs: proofs,
            credentialRequestExtras: credentialRequestExtras,
            clientAttestation: clientAttestation,
            clientAttestationPoP: clientAttestationPoP,
            dpopKeyId: dpopKeyId,
            dpopProof: dpopProof,
            credentialResponseEncryptionJwk: credentialResponseEncryptionJwk,
            credentialCount: credentialCount,
            transactionId: transactionId,
            interval: interval,
            responseJwe: responseJwe,
            error: error,
            errorCode: errorCode
        ))
    }

    /// Send a credential matching response back to the server.
    ///
    /// - Parameter noMatchReason: why nothing matched, for an empty `matches`.
    ///   The engine logs it and puts it in the `no_match_reason` detail of the
    ///   error it reports, so dropping it costs the only explanation anyone
    ///   downstream gets of *why* the wallet came up empty.
    public func sendMatchResponse(
        flowId: String,
        matches: [CredentialMatch],
        noMatchReason: String? = nil
    ) {
        send(MatchResponseMessage(
            flowId: flowId,
            matches: matches,
            noMatchReason: noMatchReason
        ))
    }

    /// Report the outcome of local DCQL matching for the engine's
    /// `credential_selection` step.
    ///
    /// An **empty** `matches` ends the flow at once: the engine answers with a
    /// `NO_MATCHING_CREDENTIAL` flow error naming the credential types the
    /// query asked for (`requested_types`), carrying `noMatchReason` through as
    /// `no_match_reason`, and tells the verifier so its session ends rather
    /// than expiring (go-wallet-backend #335/#336). It is the honest answer to
    /// a request this wallet cannot satisfy - `decline` would report a refusal
    /// the user was never asked to make, and saying nothing leaves the flow to
    /// die on the engine's five-minute user-interaction timeout.
    ///
    /// A **non-empty** `matches` is purely informational: the engine goes on
    /// waiting for `consent`/`decline` exactly as if it had never arrived.
    public func sendCredentialsMatched(
        flowId: String,
        matches: [CredentialMatch],
        noMatchReason: String? = nil
    ) {
        sendFlowAction(
            flowId: flowId,
            action: "credentials_matched",
            payload: Self.credentialsMatchedPayload(matches: matches, noMatchReason: noMatchReason)
        )
    }

    /// The `credentials_matched` flow-action payload - go-wallet-backend's
    /// `CredentialsMatchedPayload` wire shape. Internal and static so the wire
    /// contract is unit-testable without a live socket.
    static func credentialsMatchedPayload(
        matches: [CredentialMatch],
        noMatchReason: String?
    ) -> [String: AnyCodable] {
        var payload: [String: AnyCodable] = [
            "matches": .array(matches.map { encode(match: $0) }),
        ]
        if let noMatchReason { payload["no_match_reason"] = .string(noMatchReason) }
        return payload
    }

    /// `CredentialMatch` as the flow-action payload's JSON object - the same
    /// wire shape its `Codable` conformance produces, hand-built because
    /// `FlowActionMessage.payload` is `[String: AnyCodable]`.
    private static func encode(match: CredentialMatch) -> AnyCodable {
        var obj: [String: AnyCodable] = [
            "credential_id": .string(match.credentialId),
            "format": .string(match.format),
        ]
        if let queryId = match.credentialQueryId { obj["credential_query_id"] = .string(queryId) }
        if let vct = match.vct { obj["vct"] = .string(vct) }
        if let claims = match.availableClaims { obj["available_claims"] = .array(claims.map { .string($0) }) }
        return .object_(obj)
    }

    /// Send a trust evaluation result back to the server.
    public func sendTrustResult(flowId: String, trusted: Bool, reason: String? = nil) {
        var payload: [String: AnyCodable] = ["trusted": .bool(trusted)]
        if let reason { payload["reason"] = .string(reason) }
        sendFlowAction(flowId: flowId, action: "trust_result", payload: payload)
    }

    /// Send an OID4VCI §10 credential lifecycle notification for forwarding to
    /// the issuer. The backend authenticates the notification using the
    /// ephemeral issuance token it captured at flow completion.
    ///
    /// This is a no-op when the session is not connected: the notification is
    /// triggered automatically after a credential is stored, which may race with
    /// a concurrent disconnect (e.g. logout). Dropping it in that case is safe
    /// because §10 notifications are optional and best-effort.
    public func sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String? = nil
    ) {
        guard isConnected else { return }
        send(CredentialNotificationMessage(
            flowId: flowId,
            notificationId: notificationId,
            event: event,
            eventDescription: eventDescription,
            timestamp: ISO8601DateFormatter().string(from: Date())
        ))
    }

    /// Suspend until the engine WebSocket handshake completes or fails.
    public func awaitConnected(timeoutMs: UInt64 = 10_000) async throws {
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                for await state in self.stateStream {
                    if state == .connected || state == .failed || state == .reauthRequired {
                        return
                    }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: timeoutMs * 1_000_000)
                throw EngineSessionError.connectionTimeout
            }
            try await group.next()
            group.cancelAll()
        }
        switch _state {
        case .reauthRequired:
            throw EngineSessionError.reauthenticationRequired
        case .failed:
            throw EngineSessionError.connectionFailed
        default:
            break
        }
    }

    /// Force-cancel the current WebSocket - even if it still looks "connected"
    /// (`isConnected`/`currentState` don't detect a "zombie" socket that has
    /// silently stopped delivering messages) - and reconnect.
    ///
    /// Unlike `disconnect()`, this does NOT call `.finish()` on any of the
    /// flow/message `AsyncStream` continuations, so existing `for await`
    /// collectors set up before the reconnect keep working afterward. Callers
    /// resuming a flow after an OAuth redirect should call this (then
    /// `awaitConnected()`) before sending a fresh `flow_start`, since the
    /// original socket may have gone stale during the browser round-trip.
    public func forceReconnect(appToken: String) {
        webSocketTask?.cancel(with: .goingAway, reason: nil)
        webSocketTask = nil
        sessionId = nil
        lastAppToken = appToken
        reconnectAttempts = 0
        setState(.connecting)
        doConnect(appToken: appToken)
    }

    /// Resume an OID4VCI credential issuance flow after an OAuth authorization
    /// redirect, via a brand-new `flow_start` message - NOT a `flow_action` on
    /// the original flow_id, which is not guaranteed to still be alive after
    /// the redirect round-trip. Mirrors the wallet-backend's
    /// `resumeWithAuthCode` contract already used by the web client.
    ///
    /// Wallet attestation for the resumed flow arrives the same way as for a
    /// fresh one: go-wallet-backend's `Execute()` runs its attestation setup
    /// before branching on `msg.AuthCode`, so it sends `request_attestation`
    /// here too - see `startIssuance(offer:credentialOfferUri:redirectUri:)`.
    public func resumeIssuance(
        offer: String? = nil,
        credentialOfferUri: String? = nil,
        redirectUri: String? = nil,
        authCode: String,
        codeVerifier: String? = nil
    ) {
        send(FlowStartMessage(
            protocol: "oid4vci",
            offer: offer,
            credentialOfferUri: credentialOfferUri,
            redirectUri: redirectUri,
            authCode: authCode,
            codeVerifier: codeVerifier
        ))
    }

    /// Resume an OID4VCI issuance flow with a pre-built Wallet Instance
    /// Attestation + PoP on the FlowStart itself. Deprecated for the same
    /// reason as the matching `startIssuance` overload.
    @available(*, deprecated, message: "Answer the engine's request_attestation sign request via sendSignResponse(clientAttestation:clientAttestationPoP:) instead of pre-supplying attestation on resume.")
    public func resumeIssuance(
        offer: String? = nil,
        credentialOfferUri: String? = nil,
        redirectUri: String? = nil,
        authCode: String,
        codeVerifier: String? = nil,
        clientAttestation: String?,
        clientAttestationPoP: String?
    ) {
        send(FlowStartMessage(
            protocol: "oid4vci",
            offer: offer,
            credentialOfferUri: credentialOfferUri,
            redirectUri: redirectUri,
            authCode: authCode,
            codeVerifier: codeVerifier,
            clientAttestation: clientAttestation,
            clientAttestationPoP: clientAttestationPoP
        ))
    }

    /// Disconnect the WebSocket session.
    public func disconnect() {
        lastAppToken = nil
        tokenProvider = nil
        onTokenRejected = nil
        webSocketTask?.cancel(with: .normalClosure, reason: "client disconnect".data(using: .utf8))
        webSocketTask = nil
        sessionId = nil
        setState(.disconnected)
        messagesContinuation.finish()
        flowProgressContinuation.finish()
        flowCompleteContinuation.finish()
        flowErrorContinuation.finish()
        signRequestContinuation.finish()
        matchRequestContinuation.finish()
        pushContinuation.finish()
        notificationAckContinuation.finish()
    }

    private func send<T: Encodable>(_ message: T) {
        // Crashing the whole process here (the original `preconditionFailure`)
        // meant any caller racing a concurrent `disconnect()` - or invoked
        // just after a dropped connection the receive loop hasn't yet
        // reacted to - brought down the entire app rather than just failing
        // this one send. `send` is called from many public, non-throwing
        // methods (sendTrustResult, sendMatchResponse, sendSignResponse,
        // etc.), so log-and-return matches the encode-failure branch just
        // below rather than crashing.
        guard let ws = webSocketTask else {
            logWarning("send: not connected, dropping message")
            return
        }
        guard let data = try? encoder.encode(message),
              let text = String(data: data, encoding: .utf8) else {
            return
        }
        // Mirrors the handshake send's own completion handler (above): a
        // send failure here means the same dead socket the receive loop
        // would otherwise independently notice and reconnect from - discarding
        // the error silently (the previous `{ _ in }`) just delayed detection
        // until the next inbound frame timed out instead of reacting to it
        // immediately.
        ws.send(.string(text)) { [weak self] error in
            if error != nil {
                self?.scheduleReconnect()
            }
        }
    }

    private func setState(_ state: State) {
        _state = state
        stateContinuation.yield(state)
    }
}

public enum EngineSessionError: Error, Sendable {
    case connectionTimeout
    case connectionFailed
    /// The token-refresh mechanism itself was rejected before a reconnect -
    /// the session is invalid, not just the socket. Distinct from
    /// `.connectionFailed` (transient network failure) - callers should
    /// route the user to the login screen rather than retrying.
    case reauthenticationRequired
}

extension EngineSessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .connectionTimeout: return "Engine session connection timed out"
        case .connectionFailed: return "Engine session connection failed"
        case .reauthenticationRequired: return "Session expired and could not be refreshed - user must log in again"
        }
    }
}
