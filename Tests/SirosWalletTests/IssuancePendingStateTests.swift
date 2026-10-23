// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet
import SirosCredentials

/// The pure half of the pending issuance state (no CryptoKit, so it runs on
/// Linux). Kotlin twin: `SirosWalletTest` in siros-sdk-kotlin PR 277.
final class IssuancePendingStateTests: XCTestCase {
    private typealias Step = WalletState.FlowActive

    private let cred = StoredCredential(id: 1, format: "dc+sd-jwt", raw: "raw", batchId: 1, instanceId: 0)

    private func ready() -> WalletState {
        .ready(userId: "u1", displayName: "Alice", credentials: [cred])
    }

    private func flow(_ flowId: String, type: String, status: String) -> WalletState {
        .flowActive(userId: "u1", displayName: "Alice", flowId: flowId, flowType: type, status: status, credentials: [cred])
    }

    // MARK: begin

    func testBeginPublishesPendingIssuanceFromReady() {
        XCTAssertEqual(
            ready().beginningIssuanceStart(),
            flow(Step.pendingFlowId, type: "issuance", status: "initializing")
        )
    }

    func testBeginPublishesNothingFromAnyOtherState() {
        XCTAssertNil(WalletState.disconnected().beginningIssuanceStart())
        XCTAssertNil(WalletState.keystoreLocked(userId: "u1", displayName: nil).beginningIssuanceStart())
        XCTAssertNil(flow("f1", type: "issuance", status: "parsing_offer").beginningIssuanceStart())
    }

    func testPendingStateIsRecognisedAndARealFlowIsNot() {
        XCTAssertTrue(flow(Step.pendingFlowId, type: "issuance", status: "initializing").isPendingFlow)
        XCTAssertFalse(flow("f1", type: "issuance", status: "parsing_offer").isPendingFlow)
        XCTAssertFalse(ready().isPendingFlow)
    }

    // MARK: advance

    func testAdvanceStepsThroughEveryClientSideStep() {
        var state = ready().beginningIssuanceStart()!
        let steps = [
            Step.stepConnectingEngine, Step.stepEstablishingSession, Step.stepCheckingEntitlement,
            Step.stepPreparingIssuance, Step.stepStartingFlow,
        ]
        for step in steps {
            state = state.advancingPendingStep(to: step)!
            XCTAssertEqual(state, flow(Step.pendingFlowId, type: "issuance", status: step))
        }
        XCTAssertEqual(
            steps,
            ["connecting_engine", "establishing_session", "checking_entitlement", "preparing_issuance", "starting_flow"]
        )
    }

    func testAdvanceIsNilWhenAlreadyOnThatStepOrNotPending() {
        let pending = ready().beginningIssuanceStart()!
        XCTAssertNil(pending.advancingPendingStep(to: Step.stepInitializing))
        XCTAssertNil(ready().advancingPendingStep(to: Step.stepConnectingEngine))
        // A real engine flow's status is the engine's to change, never this start's.
        XCTAssertNil(flow("f1", type: "issuance", status: "parsing_offer").advancingPendingStep(to: Step.stepStartingFlow))
    }

    // MARK: failure

    func testFailureRestoresReadyOnlyForAPendingStart() {
        let pending = ready().beginningIssuanceStart()!
        XCTAssertEqual(pending.abandoningPendingStart(), ready())
        XCTAssertNil(flow("f1", type: "issuance", status: "parsing_offer").abandoningPendingStart())
        XCTAssertNil(ready().abandoningPendingStart())
    }

    // MARK: flow type across the first engine event

    func testIssuanceKeepsItsFlowTypeWhenTheEngineSpeaks() {
        let pending = flow(Step.pendingFlowId, type: "issuance", status: "starting_flow")
        XCTAssertEqual(pending.flowTypeForEngineProgress(flowId: "f1", step: "parsing_offer"), "issuance")
        // Later events of the same flow keep it as well.
        let engineFlow = flow("f1", type: "issuance", status: "parsing_offer")
        XCTAssertEqual(engineFlow.flowTypeForEngineProgress(flowId: "f1", step: "offer_parsed"), "issuance")
    }

    func testFlowTypeIsTheStepWhenNoIssuanceStartIsBehindIt() {
        // Unchanged behaviour for every flow this SDK did not start this way.
        XCTAssertEqual(ready().flowTypeForEngineProgress(flowId: "f1", step: "parsing_request"), "parsing_request")
        let other = flow("f0", type: "issuance", status: "parsing_offer")
        XCTAssertEqual(other.flowTypeForEngineProgress(flowId: "f1", step: "parsing_request"), "parsing_request")
        let presentation = flow(Step.pendingFlowId, type: "presentation", status: "x")
        XCTAssertEqual(presentation.flowTypeForEngineProgress(flowId: "f1", step: "parsing_request"), "parsing_request")
    }

    // MARK: epoch

    func testNewAttemptMakesTheOldOneStale() {
        let epochs = IssuanceStartEpoch()
        let first = epochs.begin()
        XCTAssertNoThrow(try epochs.checkCurrent(first))
        let second = epochs.begin()
        XCTAssertThrowsError(try epochs.checkCurrent(first)) { XCTAssertTrue($0 is CancellationError) }
        XCTAssertNoThrow(try epochs.checkCurrent(second))
    }

    func testInvalidateMakesTheCurrentAttemptStale() {
        let epochs = IssuanceStartEpoch()
        let epoch = epochs.begin()
        epochs.invalidate()
        XCTAssertFalse(epochs.isCurrent(epoch))
        XCTAssertThrowsError(try epochs.checkCurrent(epoch))
    }
}
