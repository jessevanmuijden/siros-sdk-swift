// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The single owner of write admission around an account wipe.
///
/// Everything that can persist or create account state (credential saves,
/// presentation history, flow completions) holds a `Ticket` taken before its
/// first `await` and writes only through `admit`. The wipe `close()`s the gate
/// FIRST, synchronously, before any await of its own (engine disconnect,
/// keystore erase, metadata fetches), then `drain()`s the writes already
/// admitted before anything is snapshotted or cleared. Nothing is admitted
/// again until a new session starts: `reopen()` is called by login, register and
/// resume only, and waits for a wipe in progress to finish.
final class TeardownGate: @unchecked Sendable {
    struct Ticket: Equatable {
        let epoch: UInt64
    }

    private let lock = NSLock()
    private var closed = false
    private var wiping = false
    private var epoch: UInt64 = 0
    private var active = 0
    private var drainWaiters: [CheckedContinuation<Void, Never>] = []
    private var reopenWaiters: [CheckedContinuation<Void, Never>] = []

    /// A ticket for a write that is about to start, or nil while the gate is closed.
    func ticket() -> Ticket? {
        lock.lock(); defer { lock.unlock() }
        return closed ? nil : Ticket(epoch: epoch)
    }

    func isValid(_ ticket: Ticket) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return !closed && epoch == ticket.epoch
    }

    /// Runs `body` as an admitted write, or returns nil without running it when
    /// the ticket is no longer valid. The check and the start of the write are
    /// one step; the wipe waits for the write to finish.
    func admit<T>(_ ticket: Ticket, _ body: () async throws -> T) async rethrows -> T? {
        lock.lock()
        guard !closed, epoch == ticket.epoch else { lock.unlock(); return nil }
        active += 1
        lock.unlock()
        defer { leave() }
        return try await body()
    }

    private func leave() {
        lock.lock()
        active -= 1
        var waiters: [CheckedContinuation<Void, Never>] = []
        if active == 0 { waiters = drainWaiters; drainWaiters = [] }
        lock.unlock()
        for waiter in waiters { waiter.resume() }
    }

    /// Closes admission. Synchronous; the caller holds the wallet lock.
    func close() {
        lock.lock()
        closed = true
        wiping = true
        epoch &+= 1
        lock.unlock()
    }

    /// Returns once every admitted write has finished.
    func drain() async {
        lock.lock()
        if active == 0 { lock.unlock(); return }
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            drainWaiters.append(continuation)
            lock.unlock()
        }
    }

    /// The wipe is over; the gate stays closed until `reopen()`.
    func endWipe() {
        lock.lock()
        wiping = false
        let waiters = reopenWaiters
        reopenWaiters = []
        lock.unlock()
        for waiter in waiters { waiter.resume() }
    }

    /// Admits writes again for a new session, after any wipe in progress has
    /// finished. Returns whether the gate had been closed.
    @discardableResult
    func reopen() async -> Bool {
        lock.lock()
        if wiping {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                reopenWaiters.append(continuation)
                lock.unlock()
            }
            lock.lock()
        }
        let wasClosed = closed
        closed = false
        epoch &+= 1
        lock.unlock()
        return wasClosed
    }
}
