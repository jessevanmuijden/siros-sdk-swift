// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// `ZkProverResidency` itself is `#if os(iOS)`-gated (see that file) - its
// tests follow suit.
#if os(iOS)

import XCTest
@testable import SirosKeystore

/// Port of Kotlin's `ZkProverResidencyTest` - same scenarios (same-key
/// reuse, key-mismatch eviction, release-while-idle, release-while-in-flight,
/// load failure), adapted to how Swift's `ZkProverResidency` actually
/// reclaims a prover.
///
/// **Why these tests exist at all**: Copilot review on PR #182 flagged that
/// this actor shipped with zero tests despite its correctness depending
/// entirely on suspension ordering across `await` points (see
/// `ZkProverResidency`'s own doc comment on why actor isolation alone is
/// NOT enough) - exactly the kind of bug that stays invisible until a race
/// actually bites in production.
///
/// **Why these don't assert a `.closed`/`AutoCloseable` flag the way
/// Kotlin's do**: the generated UniFFI object types this actor actually
/// holds have no explicit close/destroy call (see `ZkProverResidency`'s doc
/// comment) - eviction is "drop the reference and let ARC free it", not "call
/// a method". So instead of a `closed` flag, these tests track deallocation
/// with a `weak var`: hold no other strong reference to the resident prover,
/// and assert the weak reference goes `nil` exactly when the actor's own
/// `resident` property stops pointing at it (eviction, `release()`, or
/// nothing else holding it alive).
final class ZkProverResidencyTests: XCTestCase {

    /// A plain reference type standing in for a loaded prover - `AnyObject`
    /// is all `ZkProverResidency.use` requires of `T`.
    private final class FakeProver {
        let name: String
        init(name: String) { self.name = name }
    }

    private struct LoadFailure: Error, Equatable { let message: String }

    func testSameKeyReusesTheResidentProverWithoutReloading() async throws {
        let residency = ZkProverResidency()
        var loads = 0
        let first: FakeProver = try await residency.use(key: "a", load: {
            loads += 1
            return FakeProver(name: "a")
        }) { $0 }
        let second: FakeProver = try await residency.use(key: "a", load: {
            loads += 1
            return FakeProver(name: "a")
        }) { $0 }

        XCTAssertTrue(first === second, "the same key must reuse the already-resident prover instance")
        XCTAssertEqual(loads, 1, "load must only run once across both calls")
        let residentKey = await residency.residentKey
        XCTAssertEqual(residentKey, "a")
    }

    func testADifferentKeyEvictsAndDeallocatesTheResidentProverOneAtATime() async throws {
        let residency = ZkProverResidency()

        weak var weakA: FakeProver?
        do {
            let a: FakeProver = try await residency.use(key: "a", load: { FakeProver(name: "a") }) { $0 }
            weakA = a
        }
        // `a` has no outside strong reference any more - only the actor's
        // own `resident` property keeps it alive.
        XCTAssertNotNil(weakA, "the residency itself must keep the resident prover alive with nothing else referencing it")

        weak var weakB: FakeProver?
        do {
            let b: FakeProver = try await residency.use(key: "b", load: { FakeProver(name: "b") }) { $0 }
            weakB = b
        }
        XCTAssertNil(weakA, "loading 'b' must drop the residency's only reference to 'a', deallocating it")
        XCTAssertNotNil(weakB)
        let residentKeyAfterB = await residency.residentKey
        XCTAssertEqual(residentKeyAfterB, "b")

        // Coming back to "a" reloads it (and evicts "b"): the bound is ONE
        // resident prover, not a set that happens to shrink to one.
        var reloadedA = false
        _ = try await residency.use(key: "a", load: {
            reloadedA = true
            return FakeProver(name: "a")
        }) { (_: FakeProver) in () }
        XCTAssertTrue(reloadedA, "returning to a previously-evicted key must load it again, not resurrect the old instance")
        XCTAssertNil(weakB, "evicting 'b' to reload 'a' must drop the residency's only reference to 'b'")
    }

    func testReleaseDropsAnIdleProverAndForgetsIt() async throws {
        let residency = ZkProverResidency()

        weak var weakA: FakeProver?
        do {
            let a: FakeProver = try await residency.use(key: "a", load: { FakeProver(name: "a") }) { $0 }
            weakA = a
        }
        XCTAssertNotNil(weakA)

        await residency.release()
        XCTAssertNil(weakA, "release() must drop the residency's only reference to the idle prover")
        let residentKey = await residency.residentKey
        XCTAssertNil(residentKey)

        // Nothing resident: a no-op, must not throw/crash/hang.
        await residency.release()
    }

    /// The scenario `ZkProverResidency`'s own doc comment calls out by name:
    /// actor isolation alone does not serialize `use`'s critical section
    /// across its own `await` points, so a `release()` call queued WHILE a
    /// `use(...)` is suspended inside `block` must wait for that `use` to
    /// finish, not interleave and destroy the prover out from under it.
    func testReleaseQueuedDuringAnInFlightUseWaitsForItThenDestroys() async throws {
        let residency = ZkProverResidency()
        let proofStarted = expectation(description: "proof started")
        let letProofFinish = expectation(description: "let the proof finish")
        weak var weakProver: FakeProver?

        let proofTask = Task {
            try await residency.use(key: "a", load: { FakeProver(name: "a") }) { (p: FakeProver) -> String in
                weakProver = p
                proofStarted.fulfill()
                // A real suspension point, exactly like the native
                // prepProve/prove calls this models - this is where
                // release(), queued on the same actor, gets a chance to run
                // if (and only if) the actor's own isolation were
                // sufficient on its own.
                await self.fulfillment(of: [letProofFinish], timeout: 5)
                return "done"
            }
        }

        await fulfillment(of: [proofStarted], timeout: 5)
        XCTAssertNotNil(weakProver)

        // Queue release() behind the in-flight use(). Run detached so this
        // test can observe that it has NOT completed (and NOT destroyed the
        // prover) while the proof is still running.
        let releaseTask = Task { await residency.release() }

        // Give release() a real chance to run if the gate were not
        // enforcing exclusion.
        //
        // NOT checked here via `weakProver`, on purpose: `use`'s own local
        // `prover` variable AND `block`'s own local `p` both hold a strong
        // reference to the FakeProver for the entire time `block` is
        // suspended (right here, inside this very closure) - so even if the
        // gate failed completely and `release()` raced ahead and cleared
        // `resident` right now, `weakProver` would NOT go `nil` yet; those
        // two local references, not the actor's `resident` property alone,
        // are what keeps it alive mid-proof. A `weakProver`-based assertion
        // here would therefore pass whether or not the gate actually
        // excludes `release()` - it cannot distinguish "the gate worked"
        // from "release() raced ahead but nothing deallocated the object
        // yet" (Copilot review, PR #194). `residentKey` is actor state
        // `release()` mutates directly and immediately if it runs, with no
        // such ARC timing ambiguity - checking it is the real assertion.
        try await Task.sleep(nanoseconds: 100_000_000)
        let keyWhileProofStillRunning = await residency.residentKey
        XCTAssertEqual(keyWhileProofStillRunning, "a", "release() must not clear the resident key while a use() is still running")
        XCTAssertNotNil(weakProver, "sanity check: the prover is still reachable through the suspended use()/block call frame")

        letProofFinish.fulfill()
        let result = try await proofTask.value
        XCTAssertEqual(result, "done")

        // Now that `use()`'s own call frame has returned, its local
        // references are gone - `weakProver` going `nil` here (once
        // `release()`, having waited its turn, also finishes and drops the
        // actor's own reference) is the real deallocation signal.
        await releaseTask.value
        XCTAssertNil(weakProver, "release(), having waited its turn, must destroy the prover once the proof completes")
        let residentKey = await residency.residentKey
        XCTAssertNil(residentKey)
    }

    func testALoadFailureLeavesNothingResidentAndTheNextUseLoadsAgain() async throws {
        let residency = ZkProverResidency()

        do {
            _ = try await residency.use(key: "a", load: { () throws -> FakeProver in
                throw LoadFailure(message: "no network")
            }) { (_: FakeProver) in () }
            XCTFail("expected load to throw")
        } catch let failure as LoadFailure {
            XCTAssertEqual(failure.message, "no network")
        }

        let residentKeyAfterFailure = await residency.residentKey
        XCTAssertNil(residentKeyAfterFailure, "a failed load must not leave anything resident")

        var reloaded = false
        let p: FakeProver = try await residency.use(key: "a", load: {
            reloaded = true
            return FakeProver(name: "a")
        }) { $0 }
        XCTAssertTrue(reloaded)
        XCTAssertEqual(p.name, "a")
        let residentKey = await residency.residentKey
        XCTAssertEqual(residentKey, "a")
    }
}

#endif // os(iOS)
