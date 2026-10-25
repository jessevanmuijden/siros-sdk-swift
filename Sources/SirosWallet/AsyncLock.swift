// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A FIFO async mutual-exclusion lock.
///
/// Unlike `NSLock`, safe to hold across `await` points. Unlike a plain
/// `actor` (whose isolated methods are reentrant at every suspension point),
/// a body passed to `withLock` cannot interleave with another `withLock`
/// body even though both themselves `await` internally - exactly what's
/// needed to serialize a read-modify-write sequence (e.g. export a
/// container, then push it) against another such sequence, rather than just
/// against synchronous access.
actor AsyncLock {
    private var locked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    init() {}

    private func acquire() async {
        if !locked {
            locked = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    private func release() {
        guard !waiters.isEmpty else {
            locked = false
            return
        }
        // Handed straight to the next waiter rather than cleared: avoids a
        // lock/unlock gap where a third caller could jump the queue.
        waiters.removeFirst().resume()
    }

    /// Runs `body` with exclusive access, waiting its turn if another
    /// `withLock` body is already running. `body`'s own throw propagates;
    /// the lock is always released first.
    func withLock<T>(_ body: () async throws -> T) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await body()
    }
}
