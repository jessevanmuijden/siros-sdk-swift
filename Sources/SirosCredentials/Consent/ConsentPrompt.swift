// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Bridges an SDK question that must be answered by a person ("may I share this?", "which key store?") to
/// whatever UI the host app has, with the guarantees every such bridge needs and apps keep getting wrong:
///
/// - **Exactly one answer.** However the user, a timeout, a dismissal, a newer question and task cancellation
///   race, the awaiting SDK call resumes once.
/// - **Decline by default.** A question nobody can show (no ``onChange`` set), a dismissed sheet, an expired
///   timeout, a superseded question and a cancelled task all resolve to the `decline` answer. There is no silent
///   consent.
/// - **One question at a time.** A new question declines the one still pending.
/// - **A stale answer is a no-op.** A ``Pending`` handle answers only its own question: a response from an
///   outgoing sheet can never answer (or clear) a newer one.
///
/// The SDK side calls ``ask(_:)`` (typically from a handler's `confirm`); the host sets ``onChange`` to show UI
/// and calls ``Pending/answer(_:)`` / ``Pending/decline()``, and ``dismiss()`` when its UI goes away.
///
/// ```swift
/// let prompt = ConsentPrompt<MyRequest, Bool>(decline: false, timeout: 120)
/// prompt.onChange = { pending in /* show a sheet for `pending.request`, or hide it when nil */ }
/// // SDK side:      let ok = await prompt.ask(request)
/// // UI side:       pending.answer(true)   // or pending.decline()
/// ```
public final class ConsentPrompt<Request: Sendable, Answer: Sendable>: @unchecked Sendable {
    /// One question that is waiting for an answer. `Identifiable` so a SwiftUI `.sheet(item:)` can be driven by it.
    public struct Pending: Identifiable, Sendable {
        public let id: UUID
        public let request: Request
        private let resolveWith: @Sendable (Answer?) -> Bool

        fileprivate init(id: UUID, request: Request, resolve: @escaping @Sendable (Answer?) -> Bool) {
            self.id = id
            self.request = request
            self.resolveWith = resolve
        }

        /// Answers this question. Returns false (and does nothing) when it was already answered, declined,
        /// expired or superseded.
        @discardableResult
        public func answer(_ answer: Answer) -> Bool { resolveWith(answer) }

        /// Declines this question (same as the prompt's `decline` answer). False when it is already resolved.
        @discardableResult
        public func decline() -> Bool { resolveWith(nil) }
    }

    private final class Entry {
        let id = UUID()
        let request: Request
        var continuation: CheckedContinuation<Answer, Never>?
        var timeout: Task<Void, Never>?
        var resolved = false
        /// Set when the asking task is cancelled, possibly BEFORE the entry is installed.
        var cancelled = false

        init(request: Request) { self.request = request }
    }

    private let lock = NSLock()
    private let declineAnswer: Answer
    private let timeout: TimeInterval?
    private var entry: Entry?
    private var change: (@Sendable (Pending?) -> Void)?
    /// Notification delivery: serialised, coalesced, and always ending on the state that is current.
    private var delivering = false
    private var dirty = false
    /// Test seam: runs between the cancellation check and the installation of a question.
    var beforeInstall: (() -> Void)?

    /// - Parameters:
    ///   - decline: the answer that means "no" (`false`, `.cancelled`, ...).
    ///   - timeout: seconds after which a still-unanswered question is declined; nil (or a non-finite value) waits for
    ///     the user, a negative value expires at once, and a huge value is capped.
    public init(decline: Answer, timeout: TimeInterval? = nil) {
        declineAnswer = decline
        // Only a finite, representable wait reaches the timer: infinity and NaN mean "wait for the user" (like nil),
        // a negative value expires at once and a huge one is capped (about 292 years), never converted unchecked.
        if let timeout, timeout.isFinite {
            self.timeout = min(max(timeout, 0), Double(UInt64.max / 2) / 1_000_000_000)
        } else {
            self.timeout = nil
        }
    }

    /// Called with the question to show, and with nil when it is gone (answered, declined, expired). Set it
    /// before the first question; with none set every question is declined at once.
    public var onChange: (@Sendable (Pending?) -> Void)? {
        get { lock.withLock { change } }
        set {
            // Removing the callback leaves nobody to answer: the pending question is declined, not left suspended.
            let retire: UUID? = lock.withLock {
                change = newValue
                return newValue == nil ? entry?.id : nil
            }
            if let retire { _ = resolve(id: retire, with: nil) }
        }
    }

    /// The question waiting for an answer, if any.
    public var current: Pending? { lock.withLock { entry.map(pending) } }

    /// Asks `request` and suspends until it is answered or declined. Never throws and resumes exactly once.
    public func ask(_ request: Request) async -> Answer {
        guard onChange != nil, !Task.isCancelled else { return declineAnswer }
        let new = Entry(request: request)
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Answer, Never>) in
                beforeInstall?()
                // Install atomically with the cancellation check: a cancellation that arrived first is recorded on
                // the entry, and then nothing is published.
                let installed: (superseded: Entry?, install: Bool) = lock.withLock {
                    // Cancelled, or the host removed its callback since the first check: nobody could answer.
                    guard !new.cancelled, change != nil else { new.resolved = true; return (nil, false) }
                    new.continuation = continuation
                    let old = entry
                    entry = new
                    old?.resolved = true
                    dirty = true
                    return (old, true)
                }
                guard installed.install else {
                    continuation.resume(returning: declineAnswer)
                    return
                }
                if let superseded = installed.superseded {
                    superseded.timeout?.cancel()
                    superseded.continuation?.resume(returning: declineAnswer)
                    superseded.continuation = nil
                }
                if let timeout {
                    let id = new.id
                    let task = Task { [weak self] in
                        try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                        guard !Task.isCancelled else { return }
                        _ = self?.resolve(id: id, with: nil)
                    }
                    let keep = lock.withLock { () -> Bool in
                        if new.resolved { return false }
                        new.timeout = task
                        return true
                    }
                    if !keep { task.cancel() }
                }
                deliver()
            }
        } onCancel: { [weak self] in
            self?.cancel(new)
        }
    }

    /// Declines the question that is pending, if any (the host calls this when its UI goes away).
    public func dismiss() {
        if let id = lock.withLock({ entry?.id }) { _ = resolve(id: id, with: nil) }
    }

    // MARK: -

    private func pending(_ entry: Entry) -> Pending {
        let id = entry.id
        return Pending(id: id, request: entry.request) { [weak self] answer in self?.resolve(id: id, with: answer) ?? false }
    }

    /// The asking task was cancelled: mark the entry (so an installation that has not happened yet declines) and
    /// resolve it when it is already the pending one.
    private func cancel(_ target: Entry) {
        let id: UUID? = lock.withLock {
            target.cancelled = true
            return entry?.id == target.id ? target.id : nil
        }
        if let id { _ = resolve(id: id, with: nil) }
    }

    /// Resolves the question `id` once. False when it is not the pending one (already resolved or superseded).
    private func resolve(id: UUID, with answer: Answer?) -> Bool {
        let taken: (Entry, CheckedContinuation<Answer, Never>?)? = lock.withLock {
            guard let current = entry, current.id == id, !current.resolved else { return nil }
            current.resolved = true
            entry = nil
            dirty = true
            let continuation = current.continuation
            current.continuation = nil
            return (current, continuation)
        }
        guard let (resolved, continuation) = taken else { return false }
        resolved.timeout?.cancel()
        // The host hears the question is gone BEFORE the asking call continues.
        deliver()
        continuation?.resume(returning: answer ?? declineAnswer)
        return true
    }

    /// Tells the host the current state. Deliveries are serialised and coalesced: only one thread delivers at a
    /// time, each delivery reads the state that is current THEN, and the last delivered value is always the
    /// current question (or nil), however resolutions and new questions interleave. A callback that answers
    /// synchronously is fine: the nested call only marks the state dirty and the delivering loop picks it up.
    private func deliver() {
        lock.lock()
        guard !delivering else { lock.unlock(); return }
        delivering = true
        while dirty {
            dirty = false
            let snapshot = entry.map(pending)
            let callback = change
            lock.unlock()
            callback?(snapshot)
            lock.lock()
        }
        delivering = false
        lock.unlock()
    }
}
