// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Ties the tag a caller attached to a `flow_start` (the wallet's issuance epoch)
/// to the flow id the engine assigns, which is only known from the flow's first
/// message back.
///
/// The ordering is NOT guaranteed: go-wallet-backend runs every `flow_start` in
/// its own goroutine (`internal/engine/session.go`, `go m.handleFlowStart`), so
/// with two starts outstanding the first reply may belong to either, and a start
/// whose tag was dropped can still reply later. So the tracker accounts for every
/// outstanding reply (`unaccounted` + `pending`) and pairs ONLY when it is certain:
///
/// - exactly one start is outstanding and it is pending (nothing unaccounted): the
///   next unseen flow id answers it and takes its tag;
/// - otherwise the reply cannot be tied to a start: it gets NO tag, all pending tags
///   are dropped, and the starts that may still reply stay counted as `unaccounted`.
///   While anything is unaccounted the tracker is `isPoisoned`: no new start can be
///   paired (a late reply of a dropped start would take its tag), and the wallet
///   retires the socket (`reset()` via a reconnect, which also ends every flow the
///   old socket carried) before its next issuance start.
///
/// There is no timer: expiring a start would let its late reply take a newer start's
/// tag. A flow without a tag is refused by the wallet when it would store credentials,
/// so ambiguity costs availability, never safety. What stays unprovable without a
/// client-generated flow id (go-wallet-backend#478) is which of two concurrent starts
/// a given reply answers; the tracker never guesses.
final class StartTagTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var pending: [Int?] = []
    private var unaccounted = 0
    private var byFlow: [String: Int] = [:]
    private var seen: Set<String> = []

    func enqueue(_ tag: Int?) {
        lock.lock(); defer { lock.unlock() }
        pending.append(tag)
    }

    /// Whether a start whose tag was dropped may still reply on this socket.
    var isPoisoned: Bool {
        lock.lock(); defer { lock.unlock() }
        return unaccounted > 0
    }

    /// Call for every message of a flow; only the first one of a flow id pairs.
    func firstProgress(flowId: String) {
        lock.lock(); defer { lock.unlock() }
        pairLocked(flowId)
    }

    /// The tag `flowId` carries right now, without consuming it.
    func peek(flowId: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        return byFlow[flowId]
    }

    /// The tag of `flowId` (consumed), nil if it has none. A flow that completes before
    /// any progress was seen is paired now, under the same rule.
    func take(flowId: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        pairLocked(flowId)
        seen.remove(flowId)
        return byFlow.removeValue(forKey: flowId)
    }

    /// A flow ended in error; with no flow id it still answers one outstanding start.
    func discard(flowId: String?) {
        lock.lock(); defer { lock.unlock() }
        if let flowId {
            pairLocked(flowId)
            seen.remove(flowId)
            byFlow.removeValue(forKey: flowId)
        } else {
            answerLocked(assigning: nil)
        }
    }

    func reset() {
        lock.lock(); defer { lock.unlock() }
        pending.removeAll(); unaccounted = 0; byFlow.removeAll(); seen.removeAll()
    }

    // Call with `lock` held.
    private func pairLocked(_ flowId: String) {
        guard seen.insert(flowId).inserted else { return }
        answerLocked(assigning: flowId)
    }

    /// One reply arrived (for `flowId`, or an error naming no flow).
    private func answerLocked(assigning flowId: String?) {
        let outstanding = unaccounted + pending.count
        guard outstanding > 0 else { return }
        if unaccounted == 0, pending.count == 1 {
            let tag = pending.removeFirst()
            if let flowId, let tag { byFlow[flowId] = tag }
        } else {
            pending.removeAll()
            unaccounted = outstanding - 1
        }
    }
}
