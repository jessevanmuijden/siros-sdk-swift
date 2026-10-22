// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import Foundation
import SirosAuth
import SirosCredentials
import SirosKeystore
@testable import SirosWallet

/// The one cache for `/v1/evaluate` decisions (Kotlin SDK #276, item 4): only
/// successful decisions (allow and deny) are remembered, for a bounded time,
/// keyed by the whole request; an error, a timeout or an expired entry is never
/// served, and nothing survives a change of backend connection.
final class TrustDecisionCacheTests: XCTestCase {
    /// A clock the test moves by hand.
    private final class TestClock: @unchecked Sendable {
        private let lock = NSLock()
        private var offset: Duration = .zero
        private let base = ContinuousClock.now
        func now() -> ContinuousClock.Instant { lock.lock(); defer { lock.unlock() }; return base.advanced(by: offset) }
        func advance(_ d: Duration) { lock.lock(); offset += d; lock.unlock() }
    }

    private final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var _n = 0
        var n: Int { lock.lock(); defer { lock.unlock() }; return _n }
        @discardableResult func bump() -> Int { lock.lock(); defer { lock.unlock() }; _n += 1; return _n }
    }

    private struct Boom: Error {}

    private func makeCache(ttl: TimeInterval = 300, maxSize: Int = 256, clock: TestClock = TestClock()) -> (TrustDecisionCache, TestClock) {
        (TrustDecisionCache(ttl: ttl, maxSize: maxSize, now: { clock.now() }), clock)
    }

    private func allow() -> [String: Any] { ["decision": true] }

    // MARK: - What is cached, and for how long

    func testASecondIdenticalQueryIsAnsweredFromTheCache() async throws {
        let (cache, _) = makeCache()
        let calls = Counter()
        for _ in 0..<3 {
            let r = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() }
            XCTAssertEqual(r["decision"] as? Bool, true)
        }
        XCTAssertEqual(calls.n, 1)
    }

    func testADenyIsCachedToo() async throws {
        let (cache, _) = makeCache()
        let calls = Counter()
        for _ in 0..<2 {
            let r = try await cache.getOrEvaluate(key: "k") { calls.bump(); return ["decision": false] }
            XCTAssertEqual(r["decision"] as? Bool, false)
        }
        XCTAssertEqual(calls.n, 1)
    }

    func testAnEntryIsNotServedPastItsTtl() async throws {
        let (cache, clock) = makeCache(ttl: 300)
        let calls = Counter()
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() }
        clock.advance(.seconds(299))
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() }
        XCTAssertEqual(calls.n, 1, "still fresh")
        clock.advance(.seconds(2))
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() }
        XCTAssertEqual(calls.n, 2, "expired: asked again")
    }

    func testAnExpiredEntryIsNotUsedWhenTheBackendIsUnreachable() async throws {
        let (cache, clock) = makeCache(ttl: 300)
        _ = try await cache.getOrEvaluate(key: "k") { self.allow() }
        clock.advance(.seconds(301))
        do {
            _ = try await cache.getOrEvaluate(key: "k") { throw URLError(.notConnectedToInternet) }
            XCTFail("a stale answer must not stand in for an unreachable backend")
        } catch {
            XCTAssertTrue(error is URLError)
        }
    }

    func testErrorsAndNonDecisionsAreNotCached() async throws {
        let (cache, _) = makeCache()
        let calls = Counter()
        do { _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); throw Boom() } } catch {}
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return ["context": ["reason": "x"]] }
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return ["decision": "true"] }
        XCTAssertEqual(calls.n, 3, "none of an error, a body without a decision or a non-boolean decision is remembered")
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() }
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() }
        XCTAssertEqual(calls.n, 4)
    }

    func testNumericDecisionsAreNotBooleansAndAreNotCached() async throws {
        let (cache, _) = makeCache()
        let calls = Counter()
        // As BackendApiClient decodes them: JSONSerialization yields NSNumber for 1/0 and for true/false.
        for json in [#"{"decision":1}"#, #"{"decision":0}"#] {
            let decoded = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
            for _ in 0..<2 { _ = try await cache.getOrEvaluate(key: json) { calls.bump(); return decoded } }
        }
        XCTAssertEqual(calls.n, 4, "a number is not a decision")
        for json in [#"{"decision":true}"#, #"{"decision":false}"#] {
            let decoded = try JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
            for _ in 0..<2 { _ = try await cache.getOrEvaluate(key: json) { calls.bump(); return decoded } }
        }
        XCTAssertEqual(calls.n, 6, "real booleans are cached")
    }

    func testACancelledFollowerGetsCancellationNotTheLeadersResultAndTheLeaderIsUnaffected() async throws {
        let (cache, _) = makeCache()
        let entered = expectation(description: "leader started")
        let gate = AsyncStream<Void>.makeStream()
        let leader = Task {
            try await cache.getOrEvaluate(key: "k") {
                entered.fulfill()
                for await _ in gate.stream { break }
                return self.allow()
            }
        }
        await fulfillment(of: [entered], timeout: 5)
        let follower = Task { try await cache.getOrEvaluate(key: "k") { XCTFail("followers do not evaluate"); return self.allow() } }
        try await Task.sleep(nanoseconds: 100_000_000)
        follower.cancel()
        do {
            _ = try await follower.value
            XCTFail("a cancelled follower must not receive a result")
        } catch {
            XCTAssertTrue(error is CancellationError)
        }
        gate.continuation.yield()
        let result = try await leader.value
        XCTAssertEqual(result["decision"] as? Bool, true)
        XCTAssertEqual(cache.size, 1, "the leader's decision was still cached")
    }

    func testACancelledCallerDoesNotReceiveACachedDecisionEither() async throws {
        let (cache, _) = makeCache()
        _ = try await cache.getOrEvaluate(key: "k") { self.allow() }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await cache.getOrEvaluate(key: "k") { self.allow() }
        }
        do { _ = try await task.value; XCTFail("expected cancellation") } catch { XCTAssertTrue(error is CancellationError) }
    }

    func testATtlOfZeroDisablesTheCache() async throws {
        let (cache, _) = makeCache(ttl: 0)
        XCTAssertFalse(cache.enabled)
        let calls = Counter()
        for _ in 0..<3 { _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() } }
        XCTAssertEqual(calls.n, 3)
        XCTAssertEqual(cache.size, 0)
    }

    func testTheLeastRecentlyUsedEntryIsEvicted() async throws {
        let (cache, _) = makeCache(maxSize: 2)
        let calls = Counter()
        func ask(_ k: String) async throws { _ = try await cache.getOrEvaluate(key: k) { calls.bump(); return self.allow() } }
        try await ask("a"); try await ask("b")
        try await ask("a") // a is now the most recently used
        try await ask("c") // evicts b
        XCTAssertEqual(calls.n, 3)
        try await ask("a"); try await ask("c")
        XCTAssertEqual(calls.n, 3, "a and c survived")
        try await ask("b")
        XCTAssertEqual(calls.n, 4, "b was evicted")
        XCTAssertLessThanOrEqual(cache.size, 2)
    }

    // MARK: - clear() and single flight

    func testClearDropsEverything() async throws {
        let (cache, _) = makeCache()
        let calls = Counter()
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() }
        cache.clear()
        XCTAssertEqual(cache.size, 0)
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() }
        XCTAssertEqual(calls.n, 2)
    }

    func testAnEvaluationInFlightAcrossClearDoesNotStoreItsResult() async throws {
        let (cache, _) = makeCache()
        let entered = expectation(description: "evaluation started")
        let gate = AsyncStream<Void>.makeStream()
        let calls = Counter()
        let first = Task {
            try await cache.getOrEvaluate(key: "k") {
                calls.bump()
                entered.fulfill()
                for await _ in gate.stream { break }
                return self.allow()
            }
        }
        await fulfillment(of: [entered], timeout: 5)
        cache.clear() // the backend connection was replaced meanwhile
        gate.continuation.yield()
        _ = try await first.value
        XCTAssertEqual(cache.size, 0, "a result obtained before clear() must not be stored")
        _ = try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() }
        XCTAssertEqual(calls.n, 2)
    }

    func testConcurrentIdenticalQueriesShareOneEvaluation() async throws {
        let (cache, _) = makeCache()
        let entered = expectation(description: "leader started")
        let gate = AsyncStream<Void>.makeStream()
        let calls = Counter()
        let leader = Task {
            try await cache.getOrEvaluate(key: "k") {
                calls.bump()
                entered.fulfill()
                for await _ in gate.stream { break }
                return self.allow()
            }
        }
        await fulfillment(of: [entered], timeout: 5)
        let followers = (0..<4).map { _ in
            Task { try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() } }
        }
        try await Task.sleep(nanoseconds: 100_000_000) // let the followers reach the flight
        gate.continuation.yield()
        _ = try await leader.value
        for f in followers { _ = try await f.value }
        XCTAssertEqual(calls.n, 1, "one backend request for five identical callers")
    }

    func testACancelledLeaderDoesNotFailItsFollowers() async throws {
        let (cache, _) = makeCache()
        let entered = expectation(description: "leader started")
        let calls = Counter()
        let leader = Task {
            try await cache.getOrEvaluate(key: "k") {
                calls.bump()
                entered.fulfill()
                try await Task.sleep(nanoseconds: 60_000_000_000) // until cancelled
                return self.allow()
            }
        }
        await fulfillment(of: [entered], timeout: 5)
        let follower = Task { try await cache.getOrEvaluate(key: "k") { calls.bump(); return self.allow() } }
        try await Task.sleep(nanoseconds: 100_000_000)
        leader.cancel()
        let result = try await follower.value
        XCTAssertEqual(result["decision"] as? Bool, true, "the follower asked again instead of inheriting the cancellation")
        XCTAssertEqual(calls.n, 2)
    }

    // MARK: - The key

    func testTheKeyCoversTheWholeRequestAndTheClient() {
        let client = NSObject(), other = NSObject()
        let base: [String: Any] = [
            "subject": ["type": "key", "id": "s"],
            "resource": ["type": "x5c", "id": "s", "key": ["AAA"]],
            "action": ["name": "mdoc-issuer-auth"],
            "context": ["doc_type": "a"],
        ]
        func key(_ r: [String: Any], _ c: AnyObject? = nil) -> String? { TrustDecisionCache.key(for: r, client: c ?? client) }
        XCTAssertEqual(key(base), key(base), "stable")
        var differentCert = base; differentCert["resource"] = ["type": "x5c", "id": "s", "key": ["BBB"]]
        var differentContext = base; differentContext["context"] = ["doc_type": "b"]
        var differentAction = base; differentAction["action"] = ["name": "mdoc-reader-auth"]
        XCTAssertNotEqual(key(base), key(differentCert))
        XCTAssertNotEqual(key(base), key(differentContext))
        XCTAssertNotEqual(key(base), key(differentAction))
        XCTAssertNotEqual(key(base), key(base, other), "another backend client never shares an entry")
        XCTAssertNil(key(["bad": Date()]), "a request that cannot be serialised is simply not cached")
    }

    // MARK: - Wired into the wallet

    private final class NoopAuthProvider: AuthProvider {
        struct NotImplemented: Error {}
        func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
    }

    private final class StubKeystoreManager: KeystoreManager, @unchecked Sendable {
        var isUnlocked: Bool { false }
        func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
        func lock() {}
        func generateKey(algorithm: String) async throws -> String { "key" }
        func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
        func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "proof" }
        func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
        func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
        func exportEncryptedContainer() async throws -> Data { Data() }
        func listKeys() -> [KeyInfo] { [] }
        func saveCredential(id: Int64, json: String) async throws {}
        func getCredential(id: Int64) async throws -> String? { nil }
        func getAllCredentials() async throws -> [Int64: String] { [:] }
        func deleteCredential(id: Int64) async throws {}
        func clearCredentials() async throws {}
        func savePresentationRecord(id: Int64, json: String) async throws {}
        func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
        func clearPresentationRecords() async throws {}
        func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    }

    private func makeWallet(ttl: TimeInterval = 300, answer: @escaping @Sendable () throws -> [String: Any], calls: Counter) -> SirosWallet {
        let config = WalletConfig(backendUrl: "https://example.invalid", trustDecisionCacheTtl: ttl)
        let wallet = SirosWallet(config: config, authProvider: NoopAuthProvider(), keystore: StubKeystoreManager())!
        wallet.apiClient = client(answer: answer, calls: calls)
        return wallet
    }

    private func client(answer: @escaping @Sendable () throws -> [String: Any], calls: Counter) -> BackendApiClient {
        BackendApiClient(baseUrl: "https://example.invalid", httpFn: { _, _, _, _ in
            calls.bump()
            return try JSONSerialization.data(withJSONObject: try answer())
        })
    }

    func testTheWalletAsksTheBackendOnceForTheSameCertificate() async {
        let calls = Counter()
        let wallet = makeWallet(answer: { ["decision": true] }, calls: calls)
        for _ in 0..<3 {
            let r = await wallet.evaluateIssuerTrust([[1, 2, 3]], docType: "d")
            XCTAssertTrue(r.trusted)
        }
        XCTAssertEqual(calls.n, 1)
        _ = await wallet.evaluateIssuerTrust([[9, 9, 9]], docType: "d")
        XCTAssertEqual(calls.n, 2, "another certificate is another question")
        _ = await wallet.evaluateIssuerTrust([[1, 2, 3]], docType: "other")
        XCTAssertEqual(calls.n, 3, "another doc type is another question")
    }

    func testTheWalletTtlOfZeroAsksEveryTime() async {
        let calls = Counter()
        let wallet = makeWallet(ttl: 0, answer: { ["decision": true] }, calls: calls)
        _ = await wallet.evaluateIssuerTrust([[1, 2, 3]], docType: "d")
        _ = await wallet.evaluateIssuerTrust([[1, 2, 3]], docType: "d")
        XCTAssertEqual(calls.n, 2)
    }

    func testABackendFailureIsNotCachedAndNoEarlierAnswerStandsInForIt() async {
        let calls = Counter()
        let failing = Counter()
        let wallet = makeWallet(answer: {
            if failing.n > 0 { throw URLError(.notConnectedToInternet) }
            return ["decision": true]
        }, calls: calls)
        let first = await wallet.evaluateIssuerTrust([[1, 2, 3]], docType: "d")
        XCTAssertTrue(first.trusted)
        // Same question with the backend down: served from the fresh cache...
        failing.bump()
        let cached = await wallet.evaluateIssuerTrust([[1, 2, 3]], docType: "d")
        XCTAssertTrue(cached.trusted)
        // ...but a DIFFERENT question can only fail (no roots configured), never be answered by the earlier positive.
        let other = await wallet.evaluateIssuerTrust([[4, 5, 6]], docType: "d")
        XCTAssertFalse(other.trusted)
        let again = await wallet.evaluateIssuerTrust([[4, 5, 6]], docType: "d")
        XCTAssertFalse(again.trusted)
        XCTAssertEqual(calls.n, 3, "the failure was asked again, not remembered")
    }

    func testReplacingTheBackendConnectionClearsTheCache() async {
        let calls = Counter()
        let wallet = makeWallet(answer: { ["decision": true] }, calls: calls)
        _ = await wallet.evaluateIssuerTrust([[1, 2, 3]], docType: "d")
        XCTAssertEqual(wallet.trustDecisionCache.size, 1)
        wallet.apiClient = nil // logout / reconnect
        XCTAssertEqual(wallet.trustDecisionCache.size, 0)
    }
}
