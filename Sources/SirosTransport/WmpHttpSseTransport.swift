// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// WMP HTTP+SSE transport binding.
///
/// Uses HTTP POST for sending messages and Server-Sent Events (SSE) for
/// receiving messages. This is useful for environments where WebSocket
/// connections are blocked by firewalls or corporate proxies.
///
/// - Note: Requires Apple platforms (URLSession async bytes API).
#if canImport(Darwin)
public final class WmpHttpSseTransport: TransportProtocol, @unchecked Sendable {
    private let sendUrl: URL
    private let sseUrl: URL
    private let urlSession: URLSession
    private let extraHeaders: [String: String]

    private var _state: TransportState = .disconnected
    public var currentState: TransportState { _state }
    private let stateCont: AsyncStream<TransportState>.Continuation
    public let stateStream: AsyncStream<TransportState>

    private let incomingCont: AsyncStream<Data>.Continuation
    private let _incoming: AsyncStream<Data>
    private var sseTask: Task<Void, Never>?
    // The SSE event-id state outlives a single connection: a reconnect presents the last id seen
    // (`Last-Event-ID`) and an event whose id was already delivered is dropped, so a replayed
    // completion is never handed to the wallet twice.
    private var eventParser = SseEventParser()
    private var replayFilter = SseReplayFilter()
    // One reader at a time: two overlapping connects must not feed one parser from two tasks.
    private let readerGate = SseReaderGate()

    public init(
        sendUrl: URL,
        sseUrl: URL,
        session: URLSession = .shared,
        extraHeaders: [String: String] = [:]
    ) {
        self.sendUrl = sendUrl
        self.sseUrl = sseUrl
        self.urlSession = session
        self.extraHeaders = extraHeaders

        var sc: AsyncStream<TransportState>.Continuation!
        self.stateStream = AsyncStream { sc = $0 }
        self.stateCont = sc

        var ic: AsyncStream<Data>.Continuation!
        self._incoming = AsyncStream { ic = $0 }
        self.incomingCont = ic
    }

    public func connect() async throws {
        // The request is built first; the reader is claimed and installed in ONE step under the gate lock, so a
        // concurrent `disconnect()` always finds the reader it has to cancel.

        var request = URLRequest(url: sseUrl)
        request.setValue("text/event-stream", forHTTPHeaderField: "Accept")
        for (key, value) in extraHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }
        let baseRequest = request   // a `let` for the closure: not changed after this point
        let started = readerGate.start { generation in
            // The resume cursor is read under the gate lock, where readers update it, so it is the one the
            // previous reader left, not a value torn between two readers.
            var finalRequest = baseRequest
            if let lastEventId = eventParser.lastEventId {
                finalRequest.setValue(lastEventId, forHTTPHeaderField: "Last-Event-ID")
            }
            let sent = finalRequest
            setState(.connecting)
            sseTask = Task { [weak self] in
                guard let self else { return }
                await self.runReader(generation: generation, request: sent)
            }
        }
        _ = started   // false: a reader is already connecting or connected
    }

    private func runReader(generation: Int, request: URLRequest) async {
            do {
                let (bytes, response) = try await self.urlSession.bytes(for: request)
                guard let httpResponse = response as? HTTPURLResponse,
                      (200..<300).contains(httpResponse.statusCode) else {
                    self.readerGate.finish(generation) { self.setState(.failed) }
                    return
                }
                // Checking that this reader is still current, publishing `.connected` and starting the response
                // are one step: a stop that lands before it leaves no `.connected` behind.
                // Split the bytes ourselves: `bytes.lines` omits the blank line that ends an event.
                // A new response never continues a block the previous one left unfinished.
                // The closure names its type: with two statements and no annotation the older toolchain CodeQL builds with cannot
                // infer `T` ("missing return in closure").
                let stillCurrent: Void? = self.readerGate.ifCurrent(generation) { () -> Void in
                    self.setState(.connected)
                    self.eventParser.beginResponse()
                }
                guard stillCurrent != nil else { return }
                var splitter = SseLineSplitter()
                for try await byte in bytes {
                    guard let line = splitter.feed(byte: byte) else { continue }
                    // The parser and filter are touched only while this reader is the current one, and the gate
                    // is held for that whole step: a replaced or stopped reader never mutates its successor's state.
                    let delivered: Data?? = self.readerGate.ifCurrent(generation) { () -> Data? in
                        guard let event = self.eventParser.feed(line: line), self.replayFilter.admit(event) else { return Data?.none }
                        return event.data.data(using: .utf8)
                    }
                    guard let delivered else { break }          // stale: stop reading
                    if let data = delivered { self.incomingCont.yield(data) }
                }
                // Free the gate and publish the state as one step: a consumer that reconnects as soon as it sees
                // `.disconnected` finds the gate open, and a stale reader never overwrites its successor's state.
                self.readerGate.finish(generation) { self.setState(.disconnected) }
            } catch {
                self.readerGate.finish(generation) {
                    if self._state != .disconnected { self.setState(.failed) }
                }
            }
    }

    public func send(_ message: Data) async throws {
        var request = URLRequest(url: sendUrl)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        for (key, value) in extraHeaders {
            request.setValue(value, forHTTPHeaderField: key)
        }
        request.httpBody = message

        let (_, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse,
              (200..<300).contains(httpResponse.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? 0
            throw TransportError.sendFailed("HTTP POST failed: \(code)")
        }
    }

    public func incoming() -> AsyncStream<Data> { _incoming }

    public func disconnect() async {
        // Invalidating the reader, cancelling ITS task and publishing the state are one step under the gate lock:
        // a `connect()` that follows cannot install a task this disconnect then cancels instead.
        readerGate.stop {
            sseTask?.cancel()
            sseTask = nil
            setState(.disconnected)
        }
        incomingCont.finish()
        stateCont.finish()
    }

    private func setState(_ state: TransportState) {
        _state = state
        stateCont.yield(state)
    }
}
#endif // canImport(Darwin)
