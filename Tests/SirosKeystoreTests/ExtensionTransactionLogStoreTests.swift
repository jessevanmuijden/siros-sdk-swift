// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore
import SirosCredentials

private final class FakeExtensionStore: ExtensionStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: [String: [String: String]] = [:]
    var locked = false
    var failRemovals = false

    func extensionEntries(namespace: String) async -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        return data[namespace] ?? [:]
    }
    func setExtensionEntry(namespace: String, key: String, value: String) async throws {
        if locked { throw KeystoreError.locked }
        lock.lock(); data[namespace, default: [:]][key] = value; lock.unlock()
    }
    func removeExtensionEntry(namespace: String, key: String) async throws {
        if locked || failRemovals { throw KeystoreError.locked }
        lock.lock(); data[namespace]?[key] = nil; lock.unlock()
    }
}

final class ExtensionTransactionLogStoreTests: XCTestCase {
    private func entry(_ i: Int, outcome: TransactionLogEntry.Outcome = .consented) -> TransactionLogEntry {
        TransactionLogEntry(id: "e\(i)", timestamp: Int64(i),
                            subject: TransactionLogSubject(transactionId: "tx\(i)", typeName: "Payment Confirmation", entities: ["payee": "Shop"]),
                            verifier: "v", credential: "c", outcome: outcome, reason: outcome == .refused ? "invalidEntry" : nil)
    }

    func testRecordsPersistInTheNamespaceAndSurviveANewInstance() async throws {
        let ext = FakeExtensionStore()
        let first = ExtensionTransactionLogStore(store: ext)
        try await first.append([entry(1), entry(2)])
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys, ["e1", "e2"])
        let second = ExtensionTransactionLogStore(store: ext)
        let ids = await second.entries().map(\.id)
        XCTAssertEqual(ids, ["e2", "e1"], "newest first, read back from the container")
        let restored = await second.entries()
        XCTAssertEqual(restored.last, entry(1))
    }

    func testPersistCallbackRunsOnlyWhenSomethingWasWritten() async throws {
        let ext = FakeExtensionStore()
        let calls = Counter()
        let store = ExtensionTransactionLogStore(store: ext, persisted: { calls.bump() })
        try await store.append([entry(1)])
        XCTAssertEqual(calls.value, 1)
        ext.locked = true
        do { try await store.append([entry(2)]) } catch {}
        XCTAssertEqual(calls.value, 1, "a failed write is not reported as persisted")
    }

    /// A write that does not reach the container is SURFACED, while the record is still kept for the session.
    func testAFailedWriteThrowsButTheSessionKeepsTheRecord() async {
        let ext = FakeExtensionStore()
        ext.locked = true
        let store = ExtensionTransactionLogStore(store: ext)
        do { try await store.append([entry(1)]); XCTFail("must surface the failure") }
        catch let error as TransactionLogError { XCTAssertTrue(error.detail.contains("1 of 1")) }
        catch { XCTFail("\(error)") }
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e1"])
    }

    func testOldestRecordsBeyondCapacityAreRemoved() async throws {
        let ext = FakeExtensionStore()
        let store = ExtensionTransactionLogStore(store: ext, capacity: 2)
        for i in 1...4 { try await store.append([entry(i)]) }
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys, ["e3", "e4"])
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e4", "e3"])
    }

    /// Refusals can be provoked by anyone who can send a request: they must not push the user's own history out.
    func testRefusalsDoNotEvictConsentedOrDeclinedRecords() async throws {
        let ext = FakeExtensionStore()
        let store = ExtensionTransactionLogStore(store: ext, capacity: 3, refusedCapacity: 2)
        try await store.append([entry(1), entry(2, outcome: .declined)])
        for i in 10..<30 { try await store.append([entry(i, outcome: .refused)]) }
        let all = await store.entries()
        XCTAssertEqual(all.filter { $0.outcome != .refused }.map(\.id).sorted(), ["e1", "e2"], "the user's own records survive a flood of refusals")
        XCTAssertEqual(all.filter { $0.outcome == .refused }.count, 2, "refusals are bounded on their own")
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys.count, 4)
    }

    /// A pruning failure leaves records beyond capacity: the host is told.
    /// The account can change between the check and the keystore executing the write: the record is taken back out.
    func testARecordWrittenAcrossAnAccountChangeIsTakenBackOut() async throws {
        let ext = FakeExtensionStore()
        final class Gate: @unchecked Sendable { var calls = 0 }
        let gate = Gate()
        let store = ExtensionTransactionLogStore(store: ext, writesAllowed: { gate.calls += 1; return gate.calls == 1 })   // allowed before the write, gone after
        do { try await store.append([entry(1)]); XCTFail("must report the record as not stored") } catch is TransactionLogError {}
        let keys = await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys
        XCTAssertTrue(keys.isEmpty, "the record did not stay in the new account's container")
    }

    func testAFailedPruneIsSurfaced() async throws {
        let ext = FakeExtensionStore()
        let store = ExtensionTransactionLogStore(store: ext, capacity: 1)
        try await store.append([entry(1)])
        ext.failRemovals = true
        do { try await store.append([entry(2)]); XCTFail("must surface") }
        catch let e as TransactionLogError { XCTAssertTrue(e.detail.contains("could not be removed")) }
    }

    /// Once the account is gone, nothing more is written (the check is made immediately before each write).
    func testWritesStopWhenTheAccountIsGone() async throws {
        final class Flag: @unchecked Sendable { var open = true }
        let flag = Flag()
        let ext = FakeExtensionStore()
        let store = ExtensionTransactionLogStore(store: ext, writesAllowed: { flag.open })
        try await store.append([entry(1)])
        flag.open = false
        do { try await store.append([entry(2)]); XCTFail() } catch is TransactionLogError {}
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys, ["e1"], "the late record never reached the container")
    }

    /// A newer record whose write failed (session-only) must not push durable history out.
    func testASessionOnlyRecordNeverEvictsDurableHistory() async throws {
        let ext = FakeExtensionStore()
        let store = ExtensionTransactionLogStore(store: ext, capacity: 2)
        try await store.append([entry(1)])
        ext.locked = true
        do { try await store.append([entry(2)]) } catch {}       // kept in memory only: never durable
        ext.locked = false
        try await store.append([entry(3)])
        // Durable: e1, e3 (capacity 2). The session-only e2 is newer than e1 but must not count towards retention.
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertEqual(keys, ["e1", "e3"], "retention is decided from what is durable")
    }

    /// Durable e1 plus a session-only e2 must not read back as more than the capacity.
    func testReadsAreBoundedByCapacityEvenWithSessionOnlyRecords() async throws {
        let ext = FakeExtensionStore()
        let store = ExtensionTransactionLogStore(store: ext, capacity: 1)
        try await store.append([entry(1)])
        ext.locked = true
        do { try await store.append([entry(2)]) } catch {}
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e2"], "bounded to the capacity, newest first")
    }

    func testAPersistFailureIsSurfacedAndTheCallbackIsNotRunForAGoneAccount() async throws {
        struct SyncFailed: Error {}
        let ext = FakeExtensionStore()
        let failing = ExtensionTransactionLogStore(store: ext, persisted: { throw SyncFailed() })
        do { try await failing.append([entry(1)]); XCTFail() }
        catch let e as TransactionLogError { XCTAssertTrue(e.detail.contains("could not be saved")) }

        final class State: @unchecked Sendable { var open = true; var exported = 0; var checks = 0 }
        let state = State()
        let store = ExtensionTransactionLogStore(
            store: FakeExtensionStore(),
            persisted: { state.exported += 1 },
            writesAllowed: { state.checks += 1; return state.checks <= 1 }   // allowed for the write, gone by the export
        )
        do { try await store.append([entry(1)]); XCTFail() } catch is TransactionLogError {}
        XCTAssertEqual(state.exported, 0, "never exports a container that is no longer this account's")
    }

    func testPruningRechecksTheAccountBeforeEveryRemoval() async throws {
        final class Gate: @unchecked Sendable { var calls = 0 }
        let gate = Gate()
        let ext = FakeExtensionStore()
        let seed = ExtensionTransactionLogStore(store: ext)
        try await seed.append([entry(1), entry(2), entry(3)])
        // The account is gone by the time pruning wants to remove anything.
        let store = ExtensionTransactionLogStore(store: ext, capacity: 1, writesAllowed: { gate.calls += 1; return gate.calls <= 1 })
        do { try await store.append([entry(4)]); XCTFail() } catch is TransactionLogError {}
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertTrue(keys.isSuperset(of: ["e1", "e2", "e3"]), "nothing was removed from a container that is not ours: \(keys)")
    }

    func testUndecodableEntriesAreIgnoredAndNeverDeleted() async throws {
        let ext = FakeExtensionStore()
        try await ext.setExtensionEntry(namespace: ExtensionTransactionLogStore.namespace, key: "junk", value: "not json")
        let store = ExtensionTransactionLogStore(store: ext, capacity: 1)
        try await store.append([entry(1), entry(2)])
        let ids = await store.entries().map(\.id)
        XCTAssertEqual(ids, ["e2"])
        let keys = Set(await ext.extensionEntries(namespace: ExtensionTransactionLogStore.namespace).keys)
        XCTAssertTrue(keys.contains("junk"), "pruning only removes records it decoded")
    }
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    func bump() { lock.lock(); n += 1; lock.unlock() }
}
