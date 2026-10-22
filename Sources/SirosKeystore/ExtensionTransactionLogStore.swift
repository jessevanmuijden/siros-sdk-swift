// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials

/// A ``TransactionLogStore`` that persists in the wallet's synchronised
/// container as one extension entry per log record (privatedata-spec §6.1,
/// namespace `org.siros.transaction_log`), the SDK's existing storage.
///
/// Records are also kept in memory, so a locked container or a failed write
/// loses nothing for the running session. The oldest records beyond
/// `capacity` are removed.
public final class ExtensionTransactionLogStore: TransactionLogStore, @unchecked Sendable {
    public static let namespace = "org.siros.transaction_log"

    private let store: any ExtensionStore
    private let capacity: Int
    private let refusedCapacity: Int
    private let persisted: (@Sendable () async throws -> Void)?
    private let writesAllowed: (@Sendable () -> Bool)?
    private let memory: InMemoryTransactionLogStore

    /// - Parameter persisted: called after a successful write so the owner
    ///   can export and sync the container (the wallet's `persistAndSyncKeystore`).
    ///   - writesAllowed: asked immediately before each durable write; `false`
    ///     (the account the store belongs to is gone) skips it and the append throws.
    public init(store: any ExtensionStore, capacity: Int = 500, refusedCapacity: Int = 100,
                persisted: (@Sendable () async throws -> Void)? = nil, writesAllowed: (@Sendable () -> Bool)? = nil) {
        self.writesAllowed = writesAllowed
        self.store = store
        self.capacity = max(1, capacity)
        self.refusedCapacity = max(1, refusedCapacity)
        self.persisted = persisted
        self.memory = InMemoryTransactionLogStore(capacity: self.capacity, refusedCapacity: self.refusedCapacity)
    }

    /// Records are kept in memory for the session regardless; a write that did
    /// not reach the container throws `TransactionLogError`.
    public func append(_ entries: [TransactionLogEntry]) async throws {
        try await memory.append(entries)
        let encoder = JSONEncoder()
        var failed = 0
        for entry in entries {
            guard writesAllowed?() ?? true, let data = try? encoder.encode(entry), let json = String(data: data, encoding: .utf8),
                  (try? await store.setExtensionEntry(namespace: Self.namespace, key: entry.id, value: json)) != nil else {
                failed += 1
                continue
            }
            // `writesAllowed` is checked before an asynchronous write that the keystore executes later,
            // so an account change can land in between. Check again once it has run and take the record
            // back out of a container that is no longer this store's (best effort: the removal is itself
            // such a write; the record stays in this store's own session memory).
            if !(writesAllowed?() ?? true) {
                _ = try? await store.removeExtensionEntry(namespace: Self.namespace, key: entry.id)
                failed += 1
            }
        }
        var pruneFailures = 0
        var persistFailure: Error?
        if failed < entries.count {
            pruneFailures = await prune()
            // The container is exported only if the account is still the one this store belongs to.
            if writesAllowed?() ?? true {
                do { try await persisted?() } catch { persistFailure = error }
            } else {
                persistFailure = TransactionLogError("the account changed before the container was exported")
            }
        }
        if failed > 0 { throw TransactionLogError("\(failed) of \(entries.count) records were not stored") }
        if pruneFailures > 0 { throw TransactionLogError("\(pruneFailures) old records could not be removed") }
        if persistFailure != nil { throw TransactionLogError("the records were stored but the container could not be saved or synchronized") }
    }

    public func entries() async -> [TransactionLogEntry] {
        var byId: [String: TransactionLogEntry] = [:]
        for entry in await persistedEntries() { byId[entry.id] = entry }
        for entry in await memory.entries() { byId[entry.id] = entry }
        // Bounded like the container: a session-only record plus the durable history must not
        // read back as roughly twice the configured capacity.
        let newestFirst = byId.values.sorted { $0.timestamp > $1.timestamp }
        return InMemoryTransactionLogStore.bounded(newestFirst, capacity: capacity, refusedCapacity: refusedCapacity)
    }

    /// The records actually present in the container (decoded). Retention is
    /// decided from these alone: a session-only record whose write failed must
    /// never push durable history out.
    private func persistedEntries() async -> [TransactionLogEntry] {
        let decoder = JSONDecoder()
        return (await store.extensionEntries(namespace: Self.namespace)).values.compactMap {
            try? decoder.decode(TransactionLogEntry.self, from: Data($0.utf8))
        }.sorted { $0.timestamp > $1.timestamp }   // newest first: retention keeps the head
    }

    /// Removes the oldest records beyond each class's capacity. Only ever
    /// deletes entries it has read and decoded: a failed or partial read
    /// removes nothing.
    private func prune() async -> Int {
        let all = await persistedEntries()
        let keep = Set(InMemoryTransactionLogStore.bounded(all, capacity: capacity, refusedCapacity: refusedCapacity).map(\.id))
        var failures = 0
        for old in all where !keep.contains(old.id) {
            // Revalidated before every removal: never touch a container that is no longer ours.
            guard writesAllowed?() ?? true else { failures += 1; continue }
            if (try? await store.removeExtensionEntry(namespace: Self.namespace, key: old.id)) == nil { failures += 1 }
        }
        return failures
    }
}
