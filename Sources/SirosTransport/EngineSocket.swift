// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// The part of `URLSessionWebSocketTask` that `WalletEngineSession` uses.
///
/// A seam, not an abstraction for its own sake: `URLSession` cannot be driven
/// by a `URLProtocol` for WebSockets, so without it the connection state
/// machine (which socket is current, what a callback of a replaced socket may
/// do) could not be tested without a live server.
protocol EngineSocket: AnyObject, Sendable {
    /// Whether the socket is still open; false once it was cancelled or closed.
    var isRunning: Bool { get }
    func resume()
    func cancel(closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?)
    func sendText(_ text: String, completion: @escaping @Sendable (Error?) -> Void)
    func receiveMessage() async throws -> URLSessionWebSocketTask.Message
    func sendPing(completion: @escaping @Sendable (Error?) -> Void)
}

/// Opens one socket for a request. The default wraps `URLSession.webSocketTask(with:)`.
typealias EngineSocketFactory = @Sendable (URLRequest) -> EngineSocket

final class URLSessionEngineSocket: EngineSocket, @unchecked Sendable {
    private let task: URLSessionWebSocketTask

    init(_ task: URLSessionWebSocketTask) { self.task = task }

    var isRunning: Bool { task.state == .running }

    func resume() { task.resume() }

    func cancel(closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        task.cancel(with: closeCode, reason: reason)
    }

    func sendText(_ text: String, completion: @escaping @Sendable (Error?) -> Void) {
        task.send(.string(text), completionHandler: completion)
    }

    func receiveMessage() async throws -> URLSessionWebSocketTask.Message {
        try await task.receive()
    }

    func sendPing(completion: @escaping @Sendable (Error?) -> Void) {
        task.sendPing(pongReceiveHandler: completion)
    }
}
