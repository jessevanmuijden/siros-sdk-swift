// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// One dispatched Server-Sent Event.
public struct SseEvent: Sendable, Equatable {
    /// The event's `id` field, if it set one. Never contains NUL.
    public let id: String?
    /// The `event` field (the type), if any.
    public let event: String?
    /// The `data` lines joined with `\n`. May hold a delivered secret: never log it.
    public let data: String
}

extension SseEvent: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Redacted: a WMP frame can carry credentials, tokens and a delivered seed.
    public var description: String { "SseEvent(id: \(id ?? "nil"), <data redacted>)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [("id", id as Any)], displayStyle: .struct) }
}

/// An incremental parser for the `text/event-stream` format (WHATWG HTML section 9.2),
/// fed one line at a time (without its line terminator). Pure, so it is testable off
/// Apple platforms; the HTTP+SSE transport drives it.
///
/// Tracks the stream's `lastEventId` as the specification says: an `id` field (without NUL)
/// fills a buffer that is COMMITTED to `lastEventId` only when the block's terminating blank
/// line arrives, so an unfinished block never advances the resume cursor (a server resuming
/// after it could skip an event that was never delivered). It persists across events (an
/// event without an `id` does not reset it) and is what a reconnect sends as `Last-Event-ID`;
/// an empty `id` resets it to nil. Call ``beginResponse()`` at the start of each HTTP response.
public struct SseEventParser: Sendable {
    private var dataLines: [String] = []
    private var eventType: String?
    /// The `id` field of the block being read (nil when it has none).
    private var pendingId: String?
    private var atStartOfResponse = true
    /// The last COMMITTED event id of this stream, for `Last-Event-ID` on reconnect. Nil when none, or after
    /// an empty `id` reset it.
    public private(set) var lastEventId: String?

    public init() {}

    /// Starts a new HTTP response: discards a block the previous response left unfinished (its data, event
    /// type and pending id; joining it with the next response's data would corrupt both), and expects the
    /// response's one optional leading byte order mark. The committed ``lastEventId`` is kept.
    public mutating func beginResponse() {
        dataLines = []
        eventType = nil
        pendingId = nil
        atStartOfResponse = true
    }

    /// Feeds one line. Returns an event when the line is the blank line that dispatches one.
    ///
    /// The line is read as Unicode SCALARS, never as Swift `Character`s: the colon and the one optional
    /// space are scalars, and a combining mark after either belongs to the value, not to the delimiter
    /// (`id:\u{0301}x` is the field `id` with the value `\u{0301}x`).
    public mutating func feed(line rawLine: String) -> SseEvent? {
        var scalars = Substring(rawLine).unicodeScalars
        if atStartOfResponse {
            atStartOfResponse = false
            if scalars.first == "\u{FEFF}" { scalars.removeFirst() } // one BOM, at the start of the response only
        }
        if scalars.last == "\r" { scalars.removeLast() }
        if scalars.isEmpty { return dispatch() }
        if scalars.first == ":" { return nil } // comment / keep-alive
        let field: String
        var value: Substring.UnicodeScalarView
        if let colon = scalars.firstIndex(of: ":") {
            field = String(scalars[..<colon])
            value = scalars[scalars.index(after: colon)...]
            if value.first == " " { value.removeFirst() }
        } else {
            field = String(scalars)
            value = Substring("").unicodeScalars
        }
        let text = String(value)
        switch field {
        case "data": dataLines.append(text)
        case "event": eventType = text
        case "id":
            if !value.contains("\u{0}") { pendingId = text }
        default: break // retry and unknown fields are ignored
        }
        return nil
    }

    private mutating func dispatch() -> SseEvent? {
        defer { dataLines = []; eventType = nil; pendingId = nil }
        // The id is committed by the blank line, also for a block that carries no data; an empty id resets the cursor.
        if let pendingId { lastEventId = pendingId.isEmpty ? nil : pendingId }
        // An event with no data is not dispatched.
        guard !dataLines.isEmpty else { return nil }
        // An empty `id` is a cursor reset, not an identifier: it is never used to drop a later event.
        return SseEvent(id: pendingId.flatMap { $0.isEmpty ? nil : $0 }, event: eventType, data: dataLines.joined(separator: "\n"))
    }
}

/// Drops events whose `id` was already delivered, so a replay after a reconnect or resume
/// never hands the same completion to the wallet twice. Events without an id are never
/// treated as duplicates. Remembers only the most recent `capacity` ids.
public struct SseReplayFilter: Sendable {
    // Keyed by the id's UTF-8 BYTES: an id is an opaque identifier, and Swift `String` equality would treat
    // canonically equivalent but different byte strings (`\u{00E9}` and `e\u{0301}`) as one id and drop a distinct event.
    private var order: [[UInt8]] = []
    private var seen: Set<[UInt8]> = []
    private let capacity: Int

    public init(capacity: Int = 1024) {
        self.capacity = max(1, capacity)
    }

    /// True when `event` is new (deliver it); false for a replayed id.
    public mutating func admit(_ event: SseEvent) -> Bool {
        guard let text = event.id else { return true }
        let id = Array(text.utf8)
        if seen.contains(id) { return false }
        seen.insert(id)
        order.append(id)
        if order.count > capacity { seen.remove(order.removeFirst()) }
        return true
    }
}

/// Splits a byte stream into lines on LF, CRLF or a lone CR, KEEPING empty lines. SSE
/// dispatches an event on a blank line, and `URLSession.AsyncBytes.lines` omits empty
/// lines, so the transport splits the bytes itself.
public struct SseLineSplitter: Sendable {
    private var buffer: [UInt8] = []
    private var previousWasCR = false

    public init() {}

    /// Feeds one byte; returns a completed line (without its terminator) or nil.
    public mutating func feed(byte: UInt8) -> String? {
        if previousWasCR {
            previousWasCR = false
            if byte == 0x0A { return nil } // the LF of a CRLF: the line was already emitted at the CR
        }
        switch byte {
        case 0x0A:
            return takeLine()
        case 0x0D:
            previousWasCR = true
            return takeLine()
        default:
            buffer.append(byte)
            return nil
        }
    }

    private mutating func takeLine() -> String {
        defer { buffer.removeAll(keepingCapacity: true) }
        return String(decoding: buffer, as: UTF8.self)
    }
}

/// Lets exactly one SSE reader run at a time. Two overlapping `connect()` calls would otherwise start two
/// readers feeding one parser and one replay filter, corrupting both. `tryStart()` hands a generation to
/// the first caller only; a reader that finishes calls `finish` with its generation, which frees the gate
/// only if it is still the current reader.
public final class SseReaderGate: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Int?
    private var next = 0

    public init() {}

    /// The generation of the reader that may start, or nil when one is already running.
    public func tryStart() -> Int? {
        lock.lock(); defer { lock.unlock() }
        guard current == nil else { return nil }
        next += 1
        current = next
        return next
    }

    /// Claims the gate and installs the reader in one step under the lock: `install` receives the new
    /// generation and runs before any `stop` can interleave, so a stop always finds the reader it must cancel.
    /// False when a reader is already running.
    public func start(install: (Int) -> Void) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard current == nil else { return false }
        next += 1
        current = next
        install(next)
        return true
    }

    /// Invalidates the current reader and runs `teardown` (cancel its task, publish the state) in the same step,
    /// so a `start` that follows can never be cancelled by it, nor have its state overwritten.
    public func stop(teardown: () -> Void) {
        lock.lock(); defer { lock.unlock() }
        current = nil
        teardown()
    }

    /// Whether `generation` is the reader that may still act.
    public func isCurrent(_ generation: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return current == generation
    }

    /// Runs `body` only if `generation` is still the current reader, and holds the gate for its whole run, so
    /// a reader that is replaced or stopped can never be inside `body` while a successor starts. nil when stale.
    public func ifCurrent<T>(_ generation: Int, _ body: () -> T) -> T? {
        lock.lock(); defer { lock.unlock() }
        guard current == generation else { return nil }
        return body()
    }

    public func finish(_ generation: Int) {
        lock.lock(); defer { lock.unlock() }
        if current == generation { current = nil }
    }

    /// Frees the gate AND publishes the reader's terminal state as ONE step under the gate lock, only if
    /// `generation` is still current. A successor that starts right after sees the gate open, and its own
    /// `.connecting` / `.connected` is never overwritten by a stale `.disconnected` or `.failed`. A stale
    /// reader publishes nothing.
    public func finish(_ generation: Int, publishing publish: () -> Void) {
        lock.lock(); defer { lock.unlock() }
        guard current == generation else { return }
        current = nil
        publish()
    }

    /// Stops whichever reader is running (for `disconnect`): it is no longer current.
    public func cancelCurrent() {
        lock.lock(); defer { lock.unlock() }
        current = nil
    }
}
