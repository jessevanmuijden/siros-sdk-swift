// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosAuth
import SirosCredentials
import SirosTransport
@testable import SirosWallet

// `SirosWallet.init` needs a real `JweKeystore` (CryptoKit): Apple platforms
// and the CI macOS runner only, like `SirosWalletIssuanceGuardTests`.
#if canImport(CryptoKit)

private final class StubAuthProvider: AuthProvider, @unchecked Sendable {
    struct NotImplemented: Error {}
    func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
    func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
    func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
}

/// The wallet half of the pending issuance state: what a start publishes, what
/// a failure or a cancel takes away. Kotlin twin: `SirosWalletTest` in
/// siros-sdk-kotlin PR 277. The engine connect itself is not exercised (a
/// real engine needs a reachable backend); a wallet with an engine but no
/// tokens fails at the first step, which is enough to see what precedes it.
final class SirosWalletIssuanceStartStateTests: XCTestCase {
    private func makeWallet() -> SirosWallet {
        let wallet = SirosWallet(config: WalletConfig(backendUrl: "https://example.invalid"), authProvider: StubAuthProvider())!
        wallet.setState(.ready(userId: "u1", displayName: "Alice", credentials: []))
        return wallet
    }

    private let offer = CredentialOffer(
        credentialConfigurationId: "pid",
        credentialIssuerIdentifier: "https://issuer.invalid",
        credentialName: "PID",
        issuerName: "Issuer"
    )

    /// States published while `body` runs, as `(flowId, flowType, status)`.
    private func recordedFlowStates(
        _ wallet: SirosWallet, during body: () async -> Void
    ) async -> [(String, String, String)] {
        var seen: [(String, String, String)] = []
        let stream = wallet.stateStream()
        let collector = Task {
            for await state in stream {
                if case .flowActive(_, _, let id, let type, let status, _) = state { seen.append((id, type, status)) }
            }
        }
        await body()
        try? await Task.sleep(nanoseconds: 100_000_000)
        collector.cancel()
        // `cancel()` only requests cancellation: wait for the collector to
        // finish before `seen` is read, or the read races its last append.
        await collector.value
        return seen
    }

    func testAStartPublishesTheFlowBeforeAnyNetworkWorkAndRestoresReadyOnFailure() async {
        let wallet = makeWallet()
        wallet.engineSession = WalletEngineSession(baseUrl: "https://example.invalid", tenantId: "t")

        let states = await recordedFlowStates(wallet) {
            do {
                try await wallet.startIssuanceByOffer(offer)
                XCTFail("no tokens: the engine connect must fail")
            } catch {
                XCTAssertFalse(error is CancellationError)
            }
        }

        XCTAssertEqual(states.map { $0.2 }, ["initializing", "connecting_engine"])
        XCTAssertTrue(states.allSatisfy { $0.0 == WalletState.FlowActive.pendingFlowId && $0.1 == "issuance" })
        guard case .ready = wallet.state else { return XCTFail("a failed start must return to ready, got \(wallet.state)") }
        XCTAssertFalse(wallet.issuanceInFlight, "a failed start must clear the guard so a retry is not refused")
        XCTAssertNil(wallet.activeOffer)
    }

    func testStartFromOfferUriPublishesTheSamePendingState() async {
        let wallet = makeWallet()
        wallet.engineSession = WalletEngineSession(baseUrl: "https://example.invalid", tenantId: "t")

        let states = await recordedFlowStates(wallet) {
            try? await wallet.startIssuance(offerUri: "openid-credential-offer://?credential_offer_uri=https://issuer.invalid/o")
        }

        XCTAssertEqual(states.map { $0.2 }, ["initializing", "connecting_engine"])
        guard case .ready = wallet.state else { return XCTFail("got \(wallet.state)") }
        XCTAssertFalse(wallet.issuanceInFlight)
    }

    func testCancelDuringAPendingStartResetsAtOnceAndStalesTheStart() {
        let wallet = makeWallet()
        let epoch = try! wallet.admitIssuanceStart()
        XCTAssertTrue(wallet.state.isPendingFlow)

        wallet.cancelCurrentFlow()

        guard case .ready = wallet.state else { return XCTFail("got \(wallet.state)") }
        XCTAssertFalse(wallet.issuanceInFlight)
        XCTAssertThrowsError(try wallet.advanceIssuanceStart(epoch, WalletState.FlowActive.stepPreparingIssuance)) {
            XCTAssertTrue($0 is CancellationError, "the suspended start must unwind, not carry on to the engine")
        }
        guard case .ready = wallet.state else { return XCTFail("a stale start must not touch state, got \(wallet.state)") }
    }

    func testACancelledStartCannotClobberANewerOne() {
        let wallet = makeWallet()
        let cancelled = try! wallet.admitIssuanceStart()
        wallet.cancelCurrentFlow()
        let newer = try! wallet.admitIssuanceStart()

        // The cancelled attempt's late network failure arrives now.
        let error = wallet.failIssuanceStart(cancelled, URLError(.timedOut))

        XCTAssertTrue(error is CancellationError, "a stale failure must not surface over the newer attempt")
        XCTAssertTrue(wallet.state.isPendingFlow, "the newer attempt's pending state must survive")
        XCTAssertTrue(wallet.issuanceInFlight, "the newer attempt's guard must survive")
        XCTAssertNoThrow(try wallet.advanceIssuanceStart(newer, WalletState.FlowActive.stepConnectingEngine))
    }

    func testAFailureOfTheCurrentStartRethrowsTheOriginalError() {
        let wallet = makeWallet()
        let epoch = try! wallet.admitIssuanceStart()

        let error = wallet.failIssuanceStart(epoch, URLError(.notConnectedToInternet))

        XCTAssertEqual((error as? URLError)?.code, .notConnectedToInternet)
        guard case .ready = wallet.state else { return XCTFail("got \(wallet.state)") }
        XCTAssertFalse(wallet.issuanceInFlight)
    }

    func testAFailureDoesNotClearARealEngineFlow() {
        let wallet = makeWallet()
        let epoch = try! wallet.admitIssuanceStart()
        wallet.setState(.flowActive(
            userId: "u1", displayName: "Alice", flowId: "f1", flowType: "issuance",
            status: "parsing_offer", credentials: []
        ))

        _ = wallet.failIssuanceStart(epoch, URLError(.timedOut))

        XCTAssertFalse(wallet.state.isPendingFlow)
        guard case .flowActive(_, _, "f1", _, _, _) = wallet.state else { return XCTFail("got \(wallet.state)") }
    }

    func testAStartFromANonReadyStateShowsNoFlow() {
        let wallet = makeWallet()
        wallet.setState(.keystoreLocked(userId: "u1", displayName: "Alice"))
        _ = try! wallet.admitIssuanceStart()
        guard case .keystoreLocked = wallet.state else { return XCTFail("got \(wallet.state)") }
    }

    // MARK: - Controlled interleavings
    //
    // Each test parks one thread inside a critical section of the start state
    // machine (via `issuanceStartHook`) and runs the racing operation on
    // another. With one synchronisation boundary the racer is held off until the
    // parked thread is done, so the hook simply times out; if the boundary were
    // split, the racer gets through the window and the assertions fail.

    /// Runs `parked` on a thread whose hook for `window` signals and then waits
    /// (bounded) for `release`; `racer` runs on another thread once the hook was
    /// reached and signals `release` when it is finished.
    private func interleave(
        _ wallet: SirosWallet, window: String, parked: @escaping () -> Void, racer: @escaping () -> Void
    ) {
        let reached = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        wallet.issuanceStartHook = { name in
            guard name == window else { return }
            wallet.issuanceStartHook = nil
            reached.signal()
            _ = release.wait(timeout: .now() + 0.5)
        }
        let done = DispatchGroup()
        DispatchQueue.global().async(group: done) { parked() }
        _ = reached.wait(timeout: .now() + 5)
        DispatchQueue.global().async(group: done) { racer(); release.signal() }
        XCTAssertEqual(done.wait(timeout: .now() + 10), .success)
    }

    /// A failure that passed its currency check must not clear a NEWER
    /// attempt's guard, metadata and pending state.
    func testAFailureThatPassedItsCheckCannotClearANewerAttempt() throws {
        let wallet = makeWallet()
        let a = try wallet.admitIssuanceStart()
        var newer = 0
        interleave(wallet, window: "fail.afterCheck", parked: {
            _ = wallet.failIssuanceStart(a, URLError(.timedOut))
        }, racer: {
            wallet.cancelCurrentFlow()
            newer = (try? wallet.admitIssuanceStart()) ?? -1
        })
        XCTAssertGreaterThan(newer, 0, "the newer attempt must have been admitted")
        XCTAssertTrue(wallet.issuanceInFlight, "the newer attempt's guard was cleared by the older failure")
        XCTAssertTrue(wallet.state.isPendingFlow, "the newer attempt's pending state was cleared by the older failure")
        XCTAssertNoThrow(try wallet.advanceIssuanceStart(newer, WalletState.FlowActive.stepConnectingEngine))
    }

    /// A stale advance must not resurrect the spinner after a cancel.
    func testAnAdvanceThatPassedItsCheckCannotResurrectTheSpinnerAfterACancel() throws {
        let wallet = makeWallet()
        let a = try wallet.admitIssuanceStart()
        interleave(wallet, window: "advance.afterCheck", parked: {
            try? wallet.advanceIssuanceStart(a, WalletState.FlowActive.stepConnectingEngine)
        }, racer: {
            wallet.cancelCurrentFlow()
        })
        guard case .ready = wallet.state else { return XCTFail("the spinner was resurrected: \(wallet.state)") }
        XCTAssertFalse(wallet.issuanceInFlight)
    }

    /// A cancel arriving while admission is claiming the guard must not leave
    /// the cancelled call with a live epoch and a pending state.
    func testACancelDuringAdmissionLeavesNoLiveAttempt() {
        let wallet = makeWallet()
        var epoch = -1
        interleave(wallet, window: "admit.afterGuard", parked: {
            epoch = (try? wallet.admitIssuanceStart()) ?? -1
        }, racer: {
            wallet.cancelCurrentFlow()
        })
        XCTAssertGreaterThan(epoch, 0)
        XCTAssertFalse(wallet.issuanceInFlight)
        XCTAssertFalse(wallet.state.isPendingFlow, "the cancelled call left a pending state behind")
        XCTAssertThrowsError(try wallet.advanceIssuanceStart(epoch, WalletState.FlowActive.stepConnectingEngine)) {
            XCTAssertTrue($0 is CancellationError, "the cancelled call would carry on to the engine")
        }
    }

    /// The commit of a step's work is under the same check: a stale attempt's
    /// fields never reach a newer attempt.
    func testAStaleCommitNeverRunsAgainstANewerAttempt() throws {
        let wallet = makeWallet()
        let a = try wallet.admitIssuanceStart()
        wallet.cancelCurrentFlow()
        _ = try wallet.admitIssuanceStart()
        var ran = false
        XCTAssertThrowsError(try wallet.advanceIssuanceStart(a, WalletState.FlowActive.stepStartingFlow) { ran = true })
        XCTAssertFalse(ran)
        XCTAssertNil(wallet.activeOffer)
    }

    /// A second start is refused while one is in flight, atomically with the claim.
    func testASecondStartIsRefusedWhileOneIsInFlight() throws {
        let wallet = makeWallet()
        _ = try wallet.admitIssuanceStart()
        XCTAssertThrowsError(try wallet.admitIssuanceStart())
    }

    /// Order of effects as seen by a log: the parked thread's engine action and
    /// the racer's cancel. With one critical section the action (inside it)
    /// always completes before the racer's cancel can run.
    private func engineActionVersusCancel(
        _ action: @escaping (SirosWallet, Int, @escaping () -> Void) throws -> Void, window: String = "advance.afterCheck"
    ) throws -> [String] {
        let wallet = makeWallet()
        let epoch = try wallet.admitIssuanceStart()
        let log = NSLock(); var events: [String] = []
        func record(_ e: String) { log.lock(); events.append(e); log.unlock() }
        interleave(wallet, window: window, parked: {
            try? action(wallet, epoch) { record("engine") }
        }, racer: {
            wallet.cancelCurrentFlow()
            record("cancel")
        })
        return events
    }

    /// A cancel after the final epoch check must not be followed by `flow_start`.
    func testFlowStartIsSentInsideTheEpochCheckedCommit() throws {
        let events = try engineActionVersusCancel { wallet, epoch, send in
            try wallet.dispatchIssuanceStart(epoch: epoch, send: send)
        }
        XCTAssertEqual(events, ["engine", "cancel"], "flow_start was sent after the cancel")
    }

    /// A stale attempt must not replace (close) the engine socket after a cancel.
    func testTheSocketIsReplacedInsideTheEpochCheckedCommit() throws {
        let events = try engineActionVersusCancel { wallet, epoch, reconnect in
            try wallet.replaceEngineSocketForIssuance(epoch: epoch, reconnect: reconnect)
        }
        XCTAssertEqual(events, ["engine", "cancel"], "the socket was replaced after the cancel")
    }

    func testAStaleAttemptNeitherSendsNorReplacesTheSocket() throws {
        let wallet = makeWallet()
        let a = try wallet.admitIssuanceStart()
        wallet.cancelCurrentFlow()
        _ = try wallet.admitIssuanceStart()
        var ran = 0
        XCTAssertThrowsError(try wallet.dispatchIssuanceStart(epoch: a) { ran += 1 })
        XCTAssertThrowsError(try wallet.replaceEngineSocketForIssuance(epoch: a) { ran += 1 })
        XCTAssertEqual(ran, 0)
    }
}

#endif
