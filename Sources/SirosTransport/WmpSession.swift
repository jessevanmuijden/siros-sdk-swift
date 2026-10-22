// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// WMP session client managing a single session over a `TransportProtocol`.
///
/// Handles session lifecycle (create/resume/close), request-response correlation,
/// and automatic reconnection with session resumption.
public final class WmpSession: @unchecked Sendable {
    private let transport: any TransportProtocol
    internal let codec: WmpCodec
    private let config: WmpSessionConfig

    private var sessionId: String?
    private var resumptionToken: String?
    private var lastReceivedId: String?

    private var _state: WmpSessionState = .closed
    private let stateContinuation: AsyncStream<WmpSessionState>.Continuation
    public let stateStream: AsyncStream<WmpSessionState>

    public var currentState: WmpSessionState { _state }

    /// Called once when the session has ended for good: closed, or every reconnect attempt exhausted. NOT on a
    /// transient `.failed` (one failed resume that the retry loop goes on from). A hook rather than a state
    /// observer, so it never takes elements from `stateStream`, which a host may be reading.
    public var onTerminal: (@Sendable () -> Void)?

    // Request-response correlation
    private nonisolated(unsafe) var pendingRequests: [String: CheckedContinuation<JsonRpcResponse, Error>] = [:]
    private let pendingLock = NSLock()

    // Notifications
    private let notificationContinuation: AsyncStream<JsonRpcRequest>.Continuation
    private let _notifications: AsyncStream<JsonRpcRequest>

    // Send serialization — actor ensures no concurrent sends without holding locks across await
    private let sendSerializer = SendSerializer()

    /// Notifications from the server (flow.progress, flow.complete, etc.).
    public func notifications() -> AsyncStream<JsonRpcRequest> {
        _notifications
    }

    public init(
        transport: any TransportProtocol,
        codec: WmpCodec = WmpCodec(),
        config: WmpSessionConfig = WmpSessionConfig()
    ) {
        self.transport = transport
        self.codec = codec
        self.config = config

        var stateCont: AsyncStream<WmpSessionState>.Continuation!
        self.stateStream = AsyncStream { stateCont = $0 }
        self.stateContinuation = stateCont

        var notifCont: AsyncStream<JsonRpcRequest>.Continuation!
        self._notifications = AsyncStream { notifCont = $0 }
        self.notificationContinuation = notifCont
    }

    /// Create a new WMP session with the given auth token.
    public func create(
        authToken: String,
        sender: String? = nil,
        capabilitiesOffered: [String: AnyCodable]? = nil
    ) async throws {
        setState(.connecting)
        try await transport.connect()
        startMessageLoop()

        let params = try codec.encodeParams(
            SessionCreateParams(
                wmp: WmpMeta(sender: sender),
                capabilitiesOffered: capabilitiesOffered,
                ttl: config.sessionTtlSeconds,
                auth: SessionAuth(type: "bearer", token: authToken)
            )
        )

        let response = try await sendRequest(method: "wmp.session.create", params: params)
        if let error = response.error {
            setState(.failed)
            throw WmpSessionError.sessionCreationFailed(error.message)
        }

        guard let result = response.result else {
            throw WmpSessionError.missingResult
        }

        // Parse the result to extract session info
        let resultData = try JSONEncoder().encode(result)
        let parsed = try JSONDecoder().decode(SessionCreateResult.self, from: resultData)

        sessionId = parsed.wmp.sessionId
        resumptionToken = parsed.resumptionToken

        setState(.active)
    }

    /// Resume an existing session after reconnection.
    public func resume() async throws {
        guard let sid = sessionId else { throw WmpSessionError.noSession }
        guard let token = resumptionToken else { throw WmpSessionError.noResumptionToken }

        setState(.resuming)
        try await transport.connect()
        startMessageLoop()

        let params = try codec.encodeParams(
            SessionResumeParams(
                wmp: WmpMeta(sessionId: sid),
                sessionId: sid,
                resumptionToken: token,
                lastReceivedId: lastReceivedId
            )
        )

        let response = try await sendRequest(method: "wmp.session.resume", params: params)
        if let error = response.error {
            setState(.failed)
            throw WmpSessionError.resumeFailed(error.message)
        }

        setState(.active)
    }

    /// Close the session gracefully.
    public func close(reason: String = "complete") async throws {
        guard let sid = sessionId else { return }

        let params = try codec.encodeParams(
            SessionCloseParams(
                wmp: WmpMeta(sessionId: sid),
                reason: reason
            )
        )

        try await sendNotification(method: "wmp.session.close", params: params)
        await transport.disconnect()
        setState(.closed)
        onTerminal?()
        sessionId = nil
        resumptionToken = nil
    }

    /// Send a JSON-RPC request and wait for the correlated response.
    public func sendRequest(
        method: String,
        params: [String: AnyCodable]?,
        timeoutMs: Int = 0
    ) async throws -> JsonRpcResponse {
        let effectiveTimeout = timeoutMs > 0 ? timeoutMs : Int(config.requestTimeoutMs)
        let id = UUID().uuidString

        let message = try codec.encodeRequest(method: method, params: params, id: id)

        return try await withCheckedThrowingContinuation { continuation in
            pendingLock.lock()
            pendingRequests[id] = continuation
            pendingLock.unlock()

            Task {
                do {
                    try await sendSerializer.send(message, via: transport)
                } catch {
                    pendingLock.lock()
                    let cont = pendingRequests.removeValue(forKey: id)
                    pendingLock.unlock()
                    cont?.resume(throwing: error)
                    return
                }

                // Timeout
                try? await Task.sleep(nanoseconds: UInt64(effectiveTimeout) * 1_000_000)
                pendingLock.lock()
                let cont = pendingRequests.removeValue(forKey: id)
                pendingLock.unlock()
                cont?.resume(throwing: WmpTimeoutError(method: method, timeoutMs: effectiveTimeout))
            }
        }
    }

    /// Send a JSON-RPC notification (no response expected).
    public func sendNotification(method: String, params: [String: AnyCodable]?) async throws {
        let message = try codec.encodeNotification(method: method, params: params)
        try await sendSerializer.send(message, via: transport)
    }

    /// Send a JSON-RPC response for an incoming request.
    public func sendResponse(id: String, result: AnyCodable?) async throws {
        let resultDict: [String: AnyCodable]?
        if case .object_(let dict) = result {
            resultDict = dict
        } else {
            resultDict = nil
        }
        let message = try codec.encodeResponse(id: id, result: resultDict)
        try await sendSerializer.send(message, via: transport)
    }

    /// Send a JSON-RPC error response for an incoming request.
    public func sendErrorResponse(id: String, code: Int, message: String) async throws {
        let msg = try codec.encodeErrorResponse(id: id, code: code, message: message)
        try await sendSerializer.send(msg, via: transport)
    }

    // MARK: - Private

    private func startMessageLoop() {
        // Collect incoming messages
        Task {
            for await data in transport.incoming() {
                do {
                    try handleIncoming(data)
                } catch {
                    // Log and continue
                }
            }
        }

        // Monitor transport state for disconnects
        Task {
            for await transportState in transport.stateStream {
                switch transportState {
                case .disconnected, .failed:
                    if _state == .active {
                        await handleDisconnect()
                    }
                default:
                    break
                }
            }
        }
    }

    private func handleIncoming(_ data: Data) throws {
        let message = try codec.decodeMessage(data)

        switch message {
        case .response(let response):
            if let id = response.id {
                pendingLock.lock()
                let continuation = pendingRequests.removeValue(forKey: id)
                pendingLock.unlock()
                continuation?.resume(returning: response)
            }
        case .notification(let notification):
            if let id = notification.id {
                lastReceivedId = id
            }
            notificationContinuation.yield(notification)
        case .request(let request):
            if let id = request.id {
                lastReceivedId = id
            }
            notificationContinuation.yield(request)
        }
    }

    private func handleDisconnect() async {
        guard resumptionToken != nil else { return }
        setState(.resuming)

        for attempt in 0..<config.maxReconnectAttempts {
            let backoffMs = min(
                config.reconnectBaseMs * Int64(1 << (attempt + 1)),
                config.reconnectMaxMs
            )
            try? await Task.sleep(nanoseconds: UInt64(backoffMs) * 1_000_000)

            do {
                try await resume()
                return
            } catch {
                // Try again
            }
        }

        setState(.failed)
        onTerminal?()
        // Cancel all pending requests
        pendingLock.lock()
        let pending = pendingRequests
        pendingRequests.removeAll()
        pendingLock.unlock()
        for (_, continuation) in pending {
            continuation.resume(throwing: WmpSessionError.connectionFailed)
        }
    }

    private func setState(_ state: WmpSessionState) {
        _state = state
        stateContinuation.yield(state)
    }
}

// MARK: - Supporting types

public enum WmpSessionState: String, Sendable {
    case closed
    case connecting
    case active
    case resuming
    case failed
}

public struct WmpSessionConfig: Sendable {
    public var sessionTtlSeconds: Int
    public var requestTimeoutMs: Int64
    public var maxReconnectAttempts: Int
    public var reconnectBaseMs: Int64
    public var reconnectMaxMs: Int64

    public init(
        sessionTtlSeconds: Int = 3600,
        requestTimeoutMs: Int64 = 30_000,
        maxReconnectAttempts: Int = 10,
        reconnectBaseMs: Int64 = 1_000,
        reconnectMaxMs: Int64 = 30_000
    ) {
        self.sessionTtlSeconds = sessionTtlSeconds
        self.requestTimeoutMs = requestTimeoutMs
        self.maxReconnectAttempts = maxReconnectAttempts
        self.reconnectBaseMs = reconnectBaseMs
        self.reconnectMaxMs = reconnectMaxMs
    }
}

public enum WmpSessionError: Error, Sendable {
    case sessionCreationFailed(String)
    case resumeFailed(String)
    case flowFailed(String)
    case missingResult
    case noSession
    case noResumptionToken
    case connectionFailed
}

extension WmpSessionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .sessionCreationFailed(let msg): return "Session creation failed: \(msg)"
        case .resumeFailed(let msg): return "Session resume failed: \(msg)"
        case .flowFailed(let msg): return "Flow request failed: \(msg)"
        case .missingResult: return "Missing result in WMP response"
        case .noSession: return "No active WMP session"
        case .noResumptionToken: return "No resumption token available"
        case .connectionFailed: return "WMP connection failed"
        }
    }
}

public struct WmpTimeoutError: Error, Sendable {
    public let method: String
    public let timeoutMs: Int
}

extension WmpTimeoutError: LocalizedError {
    public var errorDescription: String? {
        "Request '\(method)' timed out after \(timeoutMs)ms"
    }
}

/// Actor that serializes transport sends without holding locks across `await`.
private actor SendSerializer {
    func send(_ data: Data, via transport: any TransportProtocol) async throws {
        try await transport.send(data)
    }
}
