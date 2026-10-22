// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import CoreFoundation
#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1, including SHA256.
import Crypto
#endif

/// The one cache for AuthZEN trust decisions (`POST /v1/evaluate`), shared by
/// every evaluate call site of a `SirosWallet`. Ports the Kotlin SDK's
/// `TrustDecisionCache` (https://github.com/sirosfoundation/siros-sdk-kotlin/pull/276).
///
/// What is cached: a SUCCESSFUL evaluation, i.e. a response carrying a boolean
/// `decision`, whether true or false. Never an error: a network failure,
/// timeout, 4xx or 5xx is not a decision and is not remembered, and an expired
/// entry is deleted rather than served, even when the backend is unreachable
/// (an unreachable backend is handled by the explicit fallback and refusal
/// rules, never by a stale answer).
///
/// Key: `key(for:client:)` hashes the complete request body - action, subject
/// type and id, the whole certificate chain / key material, and the full
/// `context` - and names the backend client the answer came from, so a
/// different certificate, doc type or any other input never reuses an entry.
///
/// Trade-off: a revocation or registry change can take up to `ttl` to be
/// noticed by a wallet that asked the same question within that window. A `ttl`
/// of zero (or less) disables the cache: every call goes to the backend.
///
/// In memory only, bounded (`maxSize`, least recently used evicted), thread
/// safe, with concurrent identical evaluations sharing one in-flight request.
/// `clear()` drops everything, detaches evaluations already in flight and keeps
/// their results from being stored.
final class TrustDecisionCache: @unchecked Sendable {
    static let defaultMaxSize = 256

    /// An evaluation response. `[String: Any]` is not `Sendable`; the dictionary
    /// is never mutated after it is wrapped.
    private final class Response: @unchecked Sendable {
        let body: [String: Any]
        init(_ body: [String: Any]) { self.body = body }
    }

    private struct Entry {
        let response: Response
        let storedAt: ContinuousClock.Instant
    }

    /// The leader's result, awaited by identical concurrent callers.
    private final class Flight: @unchecked Sendable {
        private let lock = NSLock()
        private var result: Result<Response, Error>?
        private var waiters: [UUID: CheckedContinuation<Result<Response, Error>, Never>] = [:]
        private var cancelledBeforeRegistering: Set<UUID> = []

        /// Waits for the leader. Cancelling THIS task resumes only this waiter with
        /// `CancellationError`; the leader and the other waiters are unaffected.
        func wait() async -> Result<Response, Error> {
            let id = UUID()
            return await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in
                    if let ready = settleOrEnqueue(id, continuation) { continuation.resume(returning: ready) }
                }
            } onCancel: {
                if let waiter = cancel(id) { waiter.resume(returning: .failure(CancellationError())) }
            }
        }

        // The handler may run before the body registers (or after the leader finished);
        // every ordering resumes the continuation exactly once.
        private func settleOrEnqueue(_ id: UUID, _ c: CheckedContinuation<Result<Response, Error>, Never>) -> Result<Response, Error>? {
            lock.lock(); defer { lock.unlock() }
            if let result { return result }
            if cancelledBeforeRegistering.remove(id) != nil { return .failure(CancellationError()) }
            waiters[id] = c
            return nil
        }

        private func cancel(_ id: UUID) -> CheckedContinuation<Result<Response, Error>, Never>? {
            lock.lock(); defer { lock.unlock() }
            if let waiter = waiters.removeValue(forKey: id) { return waiter }
            if result == nil { cancelledBeforeRegistering.insert(id) }
            return nil
        }

        func complete(_ value: Result<Response, Error>) {
            let pending: [CheckedContinuation<Result<Response, Error>, Never>] = {
                lock.lock(); defer { lock.unlock() }
                result = value
                let w = Array(waiters.values)
                waiters = [:]
                return w
            }()
            for waiter in pending { waiter.resume(returning: value) }
        }
    }

    /// A leader that was cancelled says nothing about the question: followers ask again.
    private struct LeaderCancelled: Error {}

    private let ttl: Duration
    private let maxSize: Int
    private let now: @Sendable () -> ContinuousClock.Instant
    private let lock = NSLock()
    private var generation = 0
    private var entries: [String: Entry] = [:]
    private var accessOrder: [String] = []
    private var inFlight: [String: Flight] = [:]

    /// - Parameters:
    ///   - ttl: how long a decision is served, in seconds; zero or less disables the cache.
    ///   - now: a clock that keeps counting through sleep (an entry must not outlive
    ///     its TTL on a phone that slept); injectable for tests.
    init(
        ttl: TimeInterval,
        maxSize: Int = TrustDecisionCache.defaultMaxSize,
        now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now }
    ) {
        self.ttl = .seconds(max(0, ttl))
        self.maxSize = maxSize
        self.now = now
    }

    var enabled: Bool { ttl > .zero }

    /// Number of live entries (expired ones may still be counted until next touched).
    var size: Int { locked { entries.count } }

    private enum Role {
        case hit(Response)
        case stale
        case follow(Flight)
        case lead(Flight)
    }

    func getOrEvaluate(key: String, evaluate: () async throws -> [String: Any]) async throws -> [String: Any] {
        guard enabled else { return try await evaluate() }
        // Pinned for this whole call, including retries after a cancelled leader:
        // a call that began before clear() never registers a result.
        let startedGeneration = locked { generation }
        while true {
            // A cancelled caller never gets an answer, cached, shared or fresh.
            try Task.checkCancellation()
            switch claim(key: key, generation: startedGeneration) {
            case .stale:
                // Invalidated since this call began (its connection is gone): never
                // share or consult the new generation's state.
                return try await evaluate()
            case .hit(let response):
                return response.body
            case .follow(let flight):
                switch await flight.wait() {
                case .success(let response):
                    try Task.checkCancellation()
                    return response.body
                case .failure(let error):
                    if error is LeaderCancelled { continue }
                    throw error
                }
            case .lead(let flight):
                return try await lead(flight, key: key, generation: startedGeneration, evaluate: evaluate)
            }
        }
    }

    private func claim(key: String, generation startedGeneration: Int) -> Role {
        locked {
            if generation != startedGeneration { return .stale }
            if let entry = entries[key] {
                if now() - entry.storedAt < ttl {
                    touch(key)
                    return .hit(entry.response)
                }
                remove(key)
            }
            if let existing = inFlight[key] { return .follow(existing) }
            let flight = Flight()
            inFlight[key] = flight
            return .lead(flight)
        }
    }

    private func lead(
        _ flight: Flight,
        key: String,
        generation startedGeneration: Int,
        evaluate: () async throws -> [String: Any]
    ) async throws -> [String: Any] {
        do {
            let body = try await evaluate()
            let response = Response(body)
            locked {
                if inFlight[key] === flight { inFlight[key] = nil }
                if generation == startedGeneration && Self.isDecision(body) {
                    entries[key] = Entry(response: response, storedAt: now())
                    touch(key)
                    while entries.count > maxSize, let eldest = accessOrder.first { remove(eldest) }
                }
            }
            flight.complete(.success(response))
            return body
        } catch {
            locked { if inFlight[key] === flight { inFlight[key] = nil } }
            let cancelled = error is CancellationError || (error as? URLError)?.code == .cancelled
            flight.complete(.failure(cancelled ? LeaderCancelled() : error))
            throw error
        }
    }

    func clear() {
        locked {
            generation += 1
            entries.removeAll()
            accessOrder.removeAll()
            // Detach pending evaluations: a request made after clear() (e.g. for a
            // new connection) must not join the old connection's.
            inFlight.removeAll()
        }
    }

    // Called with `lock` held.
    private func touch(_ key: String) {
        accessOrder.removeAll { $0 == key }
        accessOrder.append(key)
    }

    private func remove(_ key: String) {
        entries.removeValue(forKey: key)
        accessOrder.removeAll { $0 == key }
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body()
    }

    /// A JSON boolean, not a number: `JSONSerialization` yields `NSNumber` for
    /// both, and `{"decision":1}` also satisfies `is Bool`, so check the CF type.
    private static func isDecision(_ response: [String: Any]) -> Bool {
        guard let number = response["decision"] as? NSNumber else { return false }
        return CFGetTypeID(number) == CFBooleanGetTypeID()
    }

    /// Cache key: SHA-256 over the full evaluation request body (keys sorted, so
    /// the same request always hashes the same), prefixed with the identity of
    /// the backend client that will answer it - a call that captured an old
    /// client before logout/re-login can then neither answer nor populate entries
    /// for the new client. Nil if the request cannot be serialised; such a
    /// request is simply not cached.
    static func key(for request: [String: Any], client: AnyObject) -> String? {
        guard JSONSerialization.isValidJSONObject(request),
              let data = try? JSONSerialization.data(withJSONObject: request, options: [.sortedKeys]) else {
            return nil
        }
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return "\(UInt(bitPattern: ObjectIdentifier(client).hashValue)):\(digest)"
    }
}
