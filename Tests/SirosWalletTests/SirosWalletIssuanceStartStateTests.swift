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
        wallet.issuanceInFlight = true
        let epoch = wallet.beginIssuanceStart()
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
        let cancelled = wallet.beginIssuanceStart()
        wallet.cancelCurrentFlow()
        wallet.issuanceInFlight = true
        let newer = wallet.beginIssuanceStart()

        // The cancelled attempt's late network failure arrives now.
        let error = wallet.failIssuanceStart(cancelled, URLError(.timedOut))

        XCTAssertTrue(error is CancellationError, "a stale failure must not surface over the newer attempt")
        XCTAssertTrue(wallet.state.isPendingFlow, "the newer attempt's pending state must survive")
        XCTAssertTrue(wallet.issuanceInFlight, "the newer attempt's guard must survive")
        XCTAssertNoThrow(try wallet.advanceIssuanceStart(newer, WalletState.FlowActive.stepConnectingEngine))
    }

    func testAFailureOfTheCurrentStartRethrowsTheOriginalError() {
        let wallet = makeWallet()
        wallet.issuanceInFlight = true
        let epoch = wallet.beginIssuanceStart()

        let error = wallet.failIssuanceStart(epoch, URLError(.notConnectedToInternet))

        XCTAssertEqual((error as? URLError)?.code, .notConnectedToInternet)
        guard case .ready = wallet.state else { return XCTFail("got \(wallet.state)") }
        XCTAssertFalse(wallet.issuanceInFlight)
    }

    func testAFailureDoesNotClearARealEngineFlow() {
        let wallet = makeWallet()
        let epoch = wallet.beginIssuanceStart()
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
        _ = wallet.beginIssuanceStart()
        guard case .keystoreLocked = wallet.state else { return XCTFail("got \(wallet.state)") }
    }
}

#endif
