// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Joins each `flow_start` the session sends with the first progress message of
/// the flow the engine assigns to it. One socket delivers frames in order, so the
/// first progress of a flow id nobody has seen yet belongs to the OLDEST start that
/// has not been answered. The tag the caller attached to that start (the wallet's
/// issuance epoch) then travels with the flow id until its completion.
final class StartTagTracker: @unchecked Sendable {
    private let lock = NSLock()
    private var pending: [Int?] = []
    private var byFlow: [String: Int] = [:]
    private var seen: Set<String> = []

    func enqueue(_ tag: Int?) {
        lock.lock(); defer { lock.unlock() }
        pending.append(tag)
    }

    /// Call for every progress message; only the first one of a flow id acts.
    func firstProgress(flowId: String) {
        lock.lock(); defer { lock.unlock() }
        guard seen.insert(flowId).inserted, !pending.isEmpty else { return }
        if let tag = pending.removeFirst() { byFlow[flowId] = tag }
    }

    /// The tag of `flowId` (consumed), nil if it has none.
    func take(flowId: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        seen.remove(flowId)
        return byFlow.removeValue(forKey: flowId)
    }

    func discard(flowId: String) { _ = take(flowId: flowId) }

    func reset() {
        lock.lock(); defer { lock.unlock() }
        pending.removeAll(); byFlow.removeAll(); seen.removeAll()
    }
}
