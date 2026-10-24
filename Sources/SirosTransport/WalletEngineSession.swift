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
    private let socketFactory: EngineSocketFactory

    private let encoder = JSONEncoder()
    private let decoder: JSONDecoder = {
        let d = JSONDecoder()
        return d
    }()

    private var _state: State = .disconnected
    private let stateContinuation: AsyncStream<State>.Continuation
    public let stateStream: AsyncStream<State>
    public var currentState: State { _state }

    private var webSocketTask: EngineSocket?

    /// Single-flight bookkeeping. The engine keeps ONE session per
    /// (tenant, user) and closes the older socket when a second connects, so
    /// two sockets open at once kill each other and a flow's replies go to a
    /// socket the engine no longer knows (found on Android, Kotlin SDK #282:
    /// a forced reconnect after a QR scan plus the reconnect each callback of
    /// the replaced socket scheduled).
    ///
    /// `epoch` identifies the one socket (or pending reconnect attempt) that
    /// may act: it is bumped whenever a socket is installed, ends, or is torn
    /// down (`forceReconnect`, `disconnect`). Every callback, loop and
    /// scheduled attempt carries the epoch it was created for and does
    /// nothing once that is no longer current. All changes of `epoch`,
    /// `webSocketTask` and `pendingReconnect` happen under `connLock`.
    private let connLock = NSLock()
    /// Serialises whole lifecycle operations (`doConnect`, `forceReconnect`,
    /// `disconnect`): predecessor teardown AND replacement startup of one call
    /// finish before the next call starts, so a concurrent connect can never
    /// resume its socket while a predecessor it superseded is still live.
    /// NOT recursive, on purpose: user code (a token provider's cancellation
    /// handler, `onTokenRejected`, a send completion) must never run inside it,
    /// because a re-entrant `forceReconnect`/`disconnect` interleaving with the
    /// outer operation would leave a socket open after a disconnect, or a
    /// disconnect that never cancels the socket installed under it. So inside it
    /// only socket swaps and `EngineSocket.cancel`/`resume` happen; every Task
    /// cancel (which can run a handler synchronously) and every send happens
    /// AFTER it is released, where a re-entrant call is simply the next
    /// operation. Taken BEFORE `connLock`; `connLock` is never held across a
    /// cancel() or a callback.
    private let lifecycleLock = NSLock()
    private var epoch = 0
    /// Called (outside every lock) each time the connection this session had is lost, or is replaced by
    /// `forceReconnect`: what the owner keeps for flows that ran on it goes. The epoch has already moved on.
    public var onSocketReplaced: (() -> Void)?
    /// Advanced by the owner when what has been received so far is no longer wanted (a cancelled flow): requests
    /// stamped with an older value are refused when handled. Under `connLock`, like `epoch`.
    public private(set) var requestEpoch = 0

    /// The identity of the live socket: a request stamped with an older value was received on one that has since been
    /// lost or replaced. This is the session's `epoch`.
    public var socketGeneration: Int { connLock.lock(); defer { connLock.unlock() }; return epoch }

    /// Marks every request received so far as obsolete (they are refused when the wallet handles them).
    public func invalidateBufferedRequests() { connLock.lock(); requestEpoch += 1; connLock.unlock() }
    /// The one pending backoff-then-connect attempt; any connect replaces it.
    private var pendingReconnect: Task<Void, Never>?
    private var sessionId: String?
    private var lastAppToken: String?
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
    private var reconnectAttempts = 0
    private let maxReconnectAttempts = 5
    /// Internal so tests can shorten the backoff.
    var baseReconnectDelayMs: UInt64 = 1000

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

    public convenience init(
        baseUrl: String,
        tenantId: String = "default",
        session: URLSession = .shared
    ) {
        self.init(baseUrl: baseUrl, tenantId: tenantId, session: session, socketFactory: nil)
    }

    /// - Parameter socketFactory: test seam; nil opens a `URLSessionWebSocketTask` on `session`.
    init(
        baseUrl: String,
        tenantId: String = "default",
        session: URLSession = .shared,
        socketFactory: EngineSocketFactory?
    ) {
        self.baseUrl = baseUrl
        self.tenantId = tenantId
        self.session = session
        self.socketFactory = socketFactory ?? { request in
            URLSessionEngineSocket(session.webSocketTask(with: request))
        }

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
    public var isConnected: Bool {
        connLock.lock(); defer { connLock.unlock() }
        return webSocketTask != nil
    }

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

    private func urlRequest() -> URLRequest? {
        let wsUrl = baseUrl
            .replacingOccurrences(of: "https://", with: "wss://")
            .replacingOccurrences(of: "http://", with: "ws://")
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            + "/api/v2/wallet?tenant_id=\(tenantId)"
        guard let url = URL(string: wsUrl) else { return nil }
        var request = URLRequest(url: url)
        request.setValue("wmp.v1", forHTTPHeaderField: "Sec-WebSocket-Protocol")
        return request
    }

    /// Opens THE live socket (see `epoch`): the previous socket and any pending
    /// backoff attempt are superseded, then cancelled, so at most one socket
    /// is ever open.
    /// - Parameter onlyIfEpoch: an automatic attempt connects only while the
    ///   epoch it was scheduled for is still current; one that was superseded
    ///   meanwhile (by `forceReconnect`, `disconnect`, another connect) does nothing.
    private func doConnect(appToken: String, onlyIfEpoch: Int? = nil) {
        guard let request = urlRequest() else {
            setState(.failed)
            return
        }

        lifecycleLock.lock()
        let after = installSocketLocked(request: request, appToken: appToken, onlyIfEpoch: onlyIfEpoch)
        lifecycleLock.unlock()
        after?()
    }

    /// The locked half of `doConnect`; `lifecycleLock` must be held. Supersedes
    /// the previous socket and the pending attempt, swaps in the new socket,
    /// cancels the predecessor and resumes the replacement.
    /// - Returns: what must run AFTER `lifecycleLock` is released (cancelling the
    ///   pending attempt, which can run a handler; the handshake and the loops),
    ///   or nil when a superseded attempt did nothing.
    private func installSocketLocked(request: URLRequest, appToken: String, onlyIfEpoch: Int?) -> (() -> Void)? {
        connLock.lock()
        if let onlyIfEpoch, onlyIfEpoch != epoch {
            connLock.unlock()
            logWarning("a superseded reconnect attempt did nothing")
            return nil
        }
        epoch += 1
        let myEpoch = epoch
        resetStartTags()
        let pending = pendingReconnect
        pendingReconnect = nil
        let previous = webSocketTask
        let socket = socketFactory(request)
        webSocketTask = socket
        connLock.unlock()

        // The epoch was bumped above, so the failure the previous socket's cancel
        // raises is recognised as stale. Predecessor teardown and replacement start
        // are one step under lifecycleLock: the next operation sees both done.
        previous?.cancel(closeCode: .goingAway, reason: nil)
        socket.resume()

        return { [self] in
            // Outside every lock: a cancellation handler may call back into the session.
            pending?.cancel()

            // Send handshake
            let handshake = HandshakeMessage(appToken: appToken)
            if let data = try? encoder.encode(handshake),
               let text = String(data: data, encoding: .utf8) {
                socket.sendText(text) { [weak self] error in
                    if error != nil {
                        self?.socketEnded(epoch: myEpoch)
                    }
                }
            }

            startReceiveLoop(socket, epoch: myEpoch)
            startPingLoop(socket, epoch: myEpoch)
        }
    }

    /// Whether `e` is still the epoch allowed to act.
    private func isCurrent(epoch e: Int) -> Bool {
        connLock.lock(); defer { connLock.unlock() }
        return epoch == e
    }

    /// Sends a WebSocket ping every `pingIntervalMs` for as long as `socket`
    /// stays open and current. `URLSessionWebSocketTask` (unlike OkHttp's
    /// WebSocket client) has no automatic client-initiated ping - it only
    /// auto-responds to pings the SERVER sends - so without this, the
    /// client side of the connection never generated any traffic of its
    /// own; see `pingIntervalMs`'s doc comment for why that matters against
    /// production infrastructure. A missing pong is only logged: unlike
    /// OkHttp's pong deadline (which the Kotlin SDK keeps at 10 s or more,
    /// #282, because the engine pings every 3 s itself) it never closes the
    /// socket, so a slow pong cannot cause a reconnect.
    private func startPingLoop(_ socket: EngineSocket, epoch e: Int) {
        Task { [weak self] in
            while socket.isRunning, self?.isCurrent(epoch: e) == true {
                let intervalMs = self?.currentPingIntervalMs() ?? Self.defaultPingIntervalMs
                try? await Task.sleep(nanoseconds: UInt64(intervalMs) * 1_000_000)
                guard socket.isRunning, self?.isCurrent(epoch: e) == true else { return }
                socket.sendPing { [weak self] error in
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

    private func startReceiveLoop(_ socket: EngineSocket, epoch e: Int) {
        Task { [weak self] in
            while socket.isRunning {
                do {
                    let message = try await socket.receiveMessage()
                    switch message {
                    case .string(let text):
                        self?.handleFrame(text, epoch: e)
                    case .data(let data):
                        if let text = String(data: data, encoding: .utf8) {
                            self?.handleFrame(text, epoch: e)
                        }
                    @unknown default:
                        break
                    }
                } catch {
                    self?.socketEnded(epoch: e)
                    return
                }
            }
        }
    }

    /// The socket that carried `epoch` ended (failed, refused a frame, closed).
    /// Only the CURRENT socket's end schedules a reconnect: the failure a
    /// replaced socket raises from its own `cancel()`, or a second callback
    /// for a socket that already ended, finds a newer epoch and does nothing.
    private func socketEnded(epoch e: Int) {
        // Through lifecycleLock like every other teardown: the failed socket is
        // cancelled before a concurrent connect()/forceReconnect() can start its
        // replacement.
        lifecycleLock.lock()
        connLock.lock()
        guard epoch == e else {
            connLock.unlock()
            lifecycleLock.unlock()
            return
        }
        // Not a usable socket any more: isConnected/send() must not claim it during the backoff.
        resetStartTags()
        let failed = webSocketTask
        webSocketTask = nil
        epoch += 1
        let hadToken = lastAppToken != nil
        let replaced = scheduleReconnectLocked()
        connLock.unlock()
        // A send or handshake error can arrive while its receive is still pending:
        // cancel it so neither it nor its receive loop outlives the replacement.
        // Its callbacks are stale (the epoch moved on).
        failed?.cancel(closeCode: .goingAway, reason: nil)
        lifecycleLock.unlock()
        replaced?.cancel()
        // The connection was lost (not dropped on purpose): outside every lock, after the epoch moved on.
        if hadToken { onSocketReplaced?() }
    }

    /// Schedules the one backoff attempt. Called with `connLock` held, by
    /// `socketEnded` only.
    /// - Returns: the pending attempt it replaced, for the caller to cancel
    ///   after releasing `connLock`.
    private func scheduleReconnectLocked() -> Task<Void, Never>? {
        // disconnect() already cleared this and set .disconnected itself.
        guard lastAppToken != nil else { return nil }
        guard reconnectAttempts < maxReconnectAttempts else {
            setState(.failed)
            return nil
        }
        setState(.reconnecting)
        reconnectAttempts += 1
        let attempt = reconnectAttempts
        let delayMs = baseReconnectDelayMs * UInt64(1 << min(attempt - 1, 4))
        let scheduledFor = epoch

        let replaced = pendingReconnect
        pendingReconnect = Task { [weak self] in
            try? await Task.sleep(nanoseconds: delayMs * 1_000_000)
            guard let self, !Task.isCancelled, self._state == .reconnecting else { return }
            guard let token = await self.refreshTokenOrSignalReauth(epoch: scheduledFor) else { return }
            if self._state == .reconnecting {
                self.doConnect(appToken: token, onlyIfEpoch: scheduledFor)
            }
        }
        return replaced
    }

    /// Mints a fresh token via `tokenProvider` (falling back to
    /// `lastAppToken` if no provider was supplied) for a reconnect attempt.
    /// A provider failure means the refresh mechanism itself was rejected -
    /// not a transient network blip like a socket-connect failure - so this
    /// short-circuits straight to `.reauthRequired` rather than consuming
    /// the remaining backoff budget on a broken session.
    /// - Parameter epoch: the epoch the attempt was scheduled for. A refresh
    ///   whose attempt was superseded meanwhile (`forceReconnect`) publishes
    ///   nothing: no token, no reauth signal, no state change - it must not
    ///   clobber the state of the connection that replaced it.
    /// - Returns: the token to reconnect with, or nil if reconnecting should
    ///   stop (state has already been updated to reflect why).
    private func refreshTokenOrSignalReauth(epoch e: Int) async -> String? {
        guard let provider = tokenProvider else { return lastAppToken }
        do {
            let fresh = try await provider()
            commitFreshToken(fresh, epoch: e)
            return fresh
        } catch {
            // Validate the epoch and publish the state in ONE step: a forceReconnect
            // landing between a check and the write could otherwise be overwritten.
            guard markReauthRequired(epoch: e) else { return nil }
            // Regardless of why the refresh failed, this reconnect attempt
            // can't proceed without a fresh token - transition to
            // .reauthRequired either way. But NOT every failure here is a
            // real token rejection worth counting toward
            // `AuthTokens.registerTokenRejection`'s forced-logout threshold
            // (see `onTokenRejected`'s doc comment) - a transient network
            // blip talking to the auth server would otherwise accumulate
            // the same as a genuine 401, so the error is handed to the
            // caller to make that distinction rather than assumed here.
            // After the state is published, so a callback that reconnects
            // synchronously cannot be overwritten by it.
            onTokenRejected?(error)
            return nil
        }
    }

    private func commitFreshToken(_ token: String, epoch e: Int) {
        connLock.lock(); defer { connLock.unlock() }
        if epoch == e { lastAppToken = token }
    }

    private func markReauthRequired(epoch e: Int) -> Bool {
        connLock.lock(); defer { connLock.unlock() }
        guard epoch == e else { return false }
        setState(.reauthRequired)
        return true
    }

    /// A frame of a superseded socket belongs to a session the engine has dropped.
    /// The epoch check and the publication of the frame (state change, streams)
    /// are one step under `connLock`: a replacement cannot land in between, so an
    /// old `handshake_complete` can never mark the new session connected.
    private func handleFrame(_ text: String, epoch e: Int) {
        connLock.lock(); defer { connLock.unlock() }
        guard epoch == e else { return }
        handleMessage(text)
    }

    // MARK: - Issuer trust reports and start tags

    /// Issuer trust reports awaiting their flow's completion. The engine reports
    /// its issuer evaluation as a progress step, but the decision that needs it
    /// is taken when the flow completes; the two arrive on separate streams, so
    /// they are joined here, in the one place that sees the frames in order.
    private var issuerTrustReports: [String: IssuerTrustReport] = [:]
    private let issuerTrustLock = NSLock()

    /// A flow carries the tag its caller attached to its `flow_start` (the wallet's
    /// issuance epoch, captured when the start was committed - not when a message is
    /// finally sent, which can be after a cancel and a newer start). See
    /// `StartTagTracker` for how a tag is tied to the flow id the engine assigns,
    /// and why it refuses to guess when that is ambiguous.
    let startTags = StartTagTracker()
    /// Held across tagging AND sending, so concurrent starts enqueue in send order.
    private let flowStartLock = NSLock()

    private func sendFlowStart(_ message: FlowStartMessage, tag: Int? = nil) {
        flowStartLock.lock(); defer { flowStartLock.unlock() }
        // A start sent with no socket is dropped by send(); it must not be queued.
        connLock.lock(); let hasSocket = webSocketTask != nil; connLock.unlock()
        if hasSocket { startTags.enqueue(tag) }
        send(message)
    }

    /// The start tag the flow `flowId` carries now (set by its first message), or nil.
    public func startTag(forFlow flowId: String) -> Int? { startTags.peek(flowId: flowId) }

    /// A dead or replaced socket answers no more starts: tags queued for it would
    /// misalign every later flow.
    private func resetStartTags() { startTags.reset() }

    private func recordIssuerTrustReport(_ msg: FlowProgressMessage) {
        guard msg.step == "trust_evaluated",
              let payload = msg.payload?.objectValue,
              payload["issuer_trust_evaluated"]?.boolValue == true else { return }
        let report = IssuerTrustReport(
            issuer: payload["issuer"]?.stringValue,
            trusted: payload["trusted"]?.boolValue ?? false,
            framework: payload["framework"]?.stringValue,
            reason: payload["reason"]?.stringValue
        )
        issuerTrustLock.lock(); defer { issuerTrustLock.unlock() }
        issuerTrustReports[msg.flowId] = report
    }

    private func attachingIssuerTrust(to msg: FlowCompleteMessage) -> FlowCompleteMessage {
        issuerTrustLock.lock(); defer { issuerTrustLock.unlock() }
        var copy = msg
        copy.issuerTrust = issuerTrustReports.removeValue(forKey: msg.flowId)
        copy.startTag = startTags.take(flowId: msg.flowId)
        return copy
    }

    private func discardIssuerTrustReport(flowId: String?, code: String? = nil) {
        let answersStart = code != EngineErrorCodes.unknownFlow && code != EngineErrorCodes.tooManyRequests
        startTags.discard(flowId: flowId, answersStart: answersStart)
        guard let flowId else { return }
        issuerTrustLock.lock(); defer { issuerTrustLock.unlock() }
        issuerTrustReports.removeValue(forKey: flowId)
    }

    /// Internal so tests can feed frames without a socket (production goes through
    /// `handleFrame`, which holds `connLock` and checks the epoch).
    func handleMessage(_ text: String) {
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
                startTags.firstProgress(flowId: msg.flowId)
                recordIssuerTrustReport(msg)
                flowProgressContinuation.yield(msg)
            }
        case MessageTypes.flowComplete:
            if let msg = try? decoder.decode(FlowCompleteMessage.self, from: data) {
                flowCompleteContinuation.yield(attachingIssuerTrust(to: msg))
            }
        case MessageTypes.flowError:
            if let msg = try? decoder.decode(FlowErrorMessage.self, from: data) {
                discardIssuerTrustReport(flowId: msg.flowId, code: msg.error.code)
                flowErrorContinuation.yield(msg)
            }
        case MessageTypes.signRequest:
            if var msg = try? decoder.decode(SignRequestMessage.self, from: data) {
                // handleFrame holds `connLock` and has just checked the epoch, so these are the receiving socket's.
                msg.socketGeneration = epoch
                msg.requestEpoch = requestEpoch
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
        authorizationDetails: [AuthorizationDetail]? = nil,
        startTag: Int? = nil
    ) {
        sendFlowStart(FlowStartMessage(
            protocol: "oid4vci",
            offer: offer,
            credentialOfferUri: credentialOfferUri,
            redirectUri: redirectUri,
            authorizationDetails: (authorizationDetails?.isEmpty ?? true) ? nil : authorizationDetails
        ), tag: startTag)
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
        sendFlowStart(FlowStartMessage(
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
        dpopKeyId: String? = nil,
        startTag: Int? = nil
    ) {
        sendFlowStart(FlowStartMessage(
            protocol: "oid4vci",
            refreshToken: refreshToken,
            credentialIssuer: credentialIssuer,
            selectedCredentialConfigurationId: selectedCredentialConfigurationId,
            reissuanceKid: reissuanceKid,
            dpopJwk: dpopJwk,
            dpopKeyId: dpopKeyId
        ), tag: startTag)
    }

    /// Start an OID4VP credential presentation flow.
    public func startPresentation(
        requestUri: String? = nil,
        requestUriRef: String? = nil,
        features: [String]? = nil
    ) {
        sendFlowStart(FlowStartMessage(
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
        // Supersede first (epoch), then cancel: the failure the old socket's
        // cancel raises is then stale, and a pending backoff attempt is replaced
        // rather than added to.
        lifecycleLock.lock()
        connLock.lock()
        epoch += 1
        let pending = pendingReconnect
        pendingReconnect = nil
        let old = webSocketTask
        webSocketTask = nil
        connLock.unlock()
        old?.cancel(closeCode: .goingAway, reason: nil)
        sessionId = nil
        lastAppToken = appToken
        reconnectAttempts = 0
        setState(.connecting)
        // Teardown and the replacement are ONE operation: nothing can run between them.
        var after: (() -> Void)?
        if let request = urlRequest() {
            after = installSocketLocked(request: request, appToken: appToken, onlyIfEpoch: nil)
        } else {
            setState(.failed)
        }
        lifecycleLock.unlock()
        // After the lock: a cancellation handler that disconnects or reconnects
        // is the NEXT operation, not a nested one. (The epoch already makes the
        // cancelled attempt inert.)
        pending?.cancel()
        after?()
        if old != nil { onSocketReplaced?() }
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
        codeVerifier: String? = nil,
        startTag: Int? = nil
    ) {
        sendFlowStart(FlowStartMessage(
            protocol: "oid4vci",
            offer: offer,
            credentialOfferUri: credentialOfferUri,
            redirectUri: redirectUri,
            authCode: authCode,
            codeVerifier: codeVerifier
        ), tag: startTag)
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
        sendFlowStart(FlowStartMessage(
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
        resetStartTags()
        lastAppToken = nil
        tokenProvider = nil
        onTokenRejected = nil
        lifecycleLock.lock()
        connLock.lock()
        epoch += 1
        let pending = pendingReconnect
        pendingReconnect = nil
        let old = webSocketTask
        webSocketTask = nil
        connLock.unlock()
        old?.cancel(closeCode: .normalClosure, reason: "client disconnect".data(using: .utf8))
        sessionId = nil
        setState(.disconnected)
        lifecycleLock.unlock()
        messagesContinuation.finish()
        flowProgressContinuation.finish()
        flowCompleteContinuation.finish()
        flowErrorContinuation.finish()
        signRequestContinuation.finish()
        matchRequestContinuation.finish()
        pushContinuation.finish()
        notificationAckContinuation.finish()
        // Last, and after the lock (see lifecycleLock): a handler that reconnects
        // from here is the next operation, not one nested inside this disconnect.
        pending?.cancel()
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
        connLock.lock()
        let ws = webSocketTask
        let sentOn = epoch
        connLock.unlock()
        guard let ws else {
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
        ws.sendText(text) { [weak self] error in
            if error != nil {
                self?.socketEnded(epoch: sentOn)
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
