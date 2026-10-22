// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Resumes a continuation exactly once, whichever racer gets there first.
private final class OnceResumer<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T, Never>?

    init(_ continuation: CheckedContinuation<T, Never>) { self.continuation = continuation }

    func resume(_ value: T) {
        lock.lock()
        let c = continuation
        continuation = nil
        lock.unlock()
        c?.resume(returning: value)
    }
}

private final class DeadlineHandles<T: Sendable>: @unchecked Sendable {
    let lock = NSLock()
    var once: OnceResumer<T>?
    var work: Task<Void, Never>?
    var cancelled = false
    func cancel(_ fallback: T) {
        lock.lock(); cancelled = true; let o = once; let w = work; lock.unlock()
        o?.resume(fallback)
        w?.cancel()
    }
}

/// Runs `operation` and answers `fallback` if it has not finished within
/// `seconds`.
///
/// Unlike a task-group race this returns on time even when `operation` never
/// finishes and ignores cancellation (a UI that never answers, a transport
/// that never times out): the abandoned work is left to finish on its own.
/// Callers that hand in work they do not control (metadata sources) document
/// that it must end on cancellation, so abandoned work cannot pile up.
func withDeadline<T: Sendable>(
    _ seconds: TimeInterval, fallback: T, _ operation: @escaping @Sendable () async -> T
) async -> T {
    let handles = DeadlineHandles<T>()
    return await withTaskCancellationHandler {
        await withCheckedContinuation { (continuation: CheckedContinuation<T, Never>) in
            let once = OnceResumer(continuation)
            let work = Task { once.resume(await operation()) }
            handles.lock.lock()
            handles.once = once
            handles.work = work
            let alreadyCancelled = handles.cancelled
            handles.lock.unlock()
            if alreadyCancelled { once.resume(fallback); work.cancel(); return }
            Task {
                try? await Task.sleep(nanoseconds: UInt64(max(seconds, 0) * 1_000_000_000))
                once.resume(fallback)
                work.cancel()
            }
        }
    } onCancel: {
        handles.cancel(fallback)
    }
}
