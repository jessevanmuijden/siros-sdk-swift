// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Ties the tag a caller attached to a `flow_start` (the wallet's issuance epoch)
/// to the flow id the engine assigns, which is only known from the flow's first
/// message back.
///
/// The ordering is NOT guaranteed: go-wallet-backend runs every `flow_start` in
/// its own goroutine (`internal/engine/session.go`, `go m.handleFlowStart`), so
/// with two starts unanswered the first reply may belong to either. The tracker
/// therefore pairs only when it is unambiguous:
///
/// - exactly ONE start is unanswered: the next unseen flow id answers it and takes
///   its tag;
/// - TWO OR MORE are unanswered: it cannot be told which one this flow answers, so
///   NO tag is assigned and ALL pending tags are dropped (the other flow then finds
///   nothing pending either). A flow without a tag is refused by the wallet when it
///   would store credentials, so an ambiguity costs availability, never safety.
///
/// A pending start expires (`ttl`): a start the engine never answered must not make
/// later flows look ambiguous. A client-generated flow id would remove the residual
/// (see the PR description); until then this is the conservative reading.
final class StartTagTracker: @unchecked Sendable {
    private struct Pending {
        let tag: Int?
        let at: ContinuousClock.Instant
    }

    private let lock = NSLock()
    private let ttl: Duration
    private let now: @Sendable () -> ContinuousClock.Instant
    private var pending: [Pending] = []
    private var byFlow: [String: Int] = [:]
    private var seen: Set<String> = []

    init(ttl: Duration = .seconds(60), now: @escaping @Sendable () -> ContinuousClock.Instant = { ContinuousClock.now }) {
        self.ttl = ttl
        self.now = now
    }

    func enqueue(_ tag: Int?) {
        lock.lock(); defer { lock.unlock() }
        pending.append(Pending(tag: tag, at: now()))
    }

    /// Call for every message of a flow; only the first one of a flow id pairs.
    func firstProgress(flowId: String) {
        lock.lock(); defer { lock.unlock() }
        pairLocked(flowId)
    }

    /// The tag of `flowId` (consumed), nil if it has none. A flow that completes before
    /// any progress was seen is paired now, under the same rule.
    func take(flowId: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        pairLocked(flowId)
        seen.remove(flowId)
        return byFlow.removeValue(forKey: flowId)
    }

    func discard(flowId: String) { _ = take(flowId: flowId) }

    func reset() {
        lock.lock(); defer { lock.unlock() }
        pending.removeAll(); byFlow.removeAll(); seen.removeAll()
    }

    // Call with `lock` held.
    private func pairLocked(_ flowId: String) {
        guard seen.insert(flowId).inserted else { return }
        let cutoff = now()
        pending.removeAll { cutoff - $0.at > ttl }
        switch pending.count {
        case 0:
            return
        case 1:
            if let tag = pending.removeFirst().tag { byFlow[flowId] = tag }
        default:
            pending.removeAll()
        }
    }
}
