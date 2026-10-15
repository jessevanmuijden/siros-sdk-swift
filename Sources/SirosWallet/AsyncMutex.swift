// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A FIFO mutual-exclusion lock for async work (an actor would interleave at
/// every `await`). Used to keep "export the container, then sync it" atomic:
/// two overlapping persists must not let an older export reach the backend
/// after a newer one.
final class AsyncMutex: @unchecked Sendable {
    private let lock = NSLock()
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    private func acquire() async {
        lock.lock()
        if !held { held = true; lock.unlock(); return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            waiters.append(continuation)
            lock.unlock()
        }
    }

    private func release() {
        lock.lock()
        if waiters.isEmpty { held = false; lock.unlock(); return }
        let next = waiters.removeFirst()   // ownership passes straight to the next waiter
        lock.unlock()
        next.resume()
    }

    func withLock<T>(_ body: () async throws -> T) async rethrows -> T {
        await acquire()
        defer { release() }
        return try await body()
    }
}
