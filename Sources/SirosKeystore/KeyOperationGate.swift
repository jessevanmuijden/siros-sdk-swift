// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Orders signing-key creation against an erase of the signer's keys.
///
/// Key-producing operations run inside `run`, which refuses them once an
/// erase has begun; `beginErase()` stops new ones and waits for the ones
/// already admitted, so the erase's snapshot of the key list cannot miss a
/// key that is still being created. `reopen()` (the wallet's next
/// session, never an unlock) admits operations again.
final class KeyOperationGate: @unchecked Sendable {
    private let lock = NSLock()
    private var erasing = false
    private var active = 0
    private var drainWaiters: [CheckedContinuation<Void, Never>] = []

    func run<T>(_ body: () async throws -> T) async throws -> T {
        try enter()
        defer { leave() }
        return try await body()
    }

    private func enter() throws {
        lock.lock(); defer { lock.unlock() }
        if erasing { throw KeystoreError.locked }
        active += 1
    }

    private func leave() {
        lock.lock()
        active -= 1
        var waiters: [CheckedContinuation<Void, Never>] = []
        if active == 0 { waiters = drainWaiters; drainWaiters = [] }
        lock.unlock()
        for waiter in waiters { waiter.resume() }
    }

    /// Refuses new key-producing operations and returns once the admitted ones finished.
    func beginErase() async {
        lock.lock()
        erasing = true
        if active == 0 { lock.unlock(); return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            drainWaiters.append(continuation)
            lock.unlock()
        }
    }

    func reopen() {
        lock.lock(); erasing = false; lock.unlock()
    }
}
