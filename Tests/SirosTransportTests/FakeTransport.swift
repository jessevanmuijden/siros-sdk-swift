// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
@testable import SirosTransport

/// In-memory transport for unit testing. Allows sending canned responses
/// and capturing outgoing messages.
final class FakeTransport: TransportProtocol, @unchecked Sendable {
    private var _currentState: TransportState = .disconnected
    var currentState: TransportState { _currentState }

    private let stateCont: AsyncStream<TransportState>.Continuation
    let stateStream: AsyncStream<TransportState>

    private let incomingCont: AsyncStream<Data>.Continuation
    private let _incoming: AsyncStream<Data>

    private let lock = NSLock()
    private var _sent: [Data] = []
    var sentMessages: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return _sent
    }

    init() {
        var sc: AsyncStream<TransportState>.Continuation!
        self.stateStream = AsyncStream { sc = $0 }
        self.stateCont = sc

        var ic: AsyncStream<Data>.Continuation!
        self._incoming = AsyncStream { ic = $0 }
        self.incomingCont = ic
    }

    func connect() async throws {
        _currentState = .connected
        stateCont.yield(.connected)
    }

    /// Sends of this JSON-RPC method throw (a failed POST on an otherwise healthy connection).
    var failingMethod: String? {
        get { lock.lock(); defer { lock.unlock() }; return _failingMethod }
        set { lock.lock(); _failingMethod = newValue; lock.unlock() }
    }
    private var _failingMethod: String?
    struct SendFailed: Error {}

    func send(_ message: Data) async throws {
        lock.lock()
        let failing = _failingMethod
        lock.unlock()
        if let failing, String(decoding: message, as: UTF8.self).contains("\"method\":\"\(failing)\"") { throw SendFailed() }
        lock.lock()
        _sent.append(message)
        lock.unlock()
    }

    func incoming() -> AsyncStream<Data> {
        _incoming
    }

    func disconnect() async {
        _currentState = .disconnected
        stateCont.yield(.disconnected)
    }

    /// Simulate receiving a message from the server.
    func receiveFromServer(_ data: Data) {
        incomingCont.yield(data)
    }

    func simulateDisconnect() {
        _currentState = .disconnected
        stateCont.yield(.disconnected)
    }

    func simulateFailure() {
        _currentState = .failed
        stateCont.yield(.failed)
    }
}
