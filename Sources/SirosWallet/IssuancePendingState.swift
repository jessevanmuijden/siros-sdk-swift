// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// The wallet's own, pre-engine part of an issuance start.
//
// `startIssuance` / `startIssuanceByOffer` do several seconds of network work
// (engine reconnect, entitlement check, metadata fetches) before the engine
// can send its first progress event, and only that event names a flow. Until
// the wallet published `.flowActive` on that event it stayed `.ready`, so a
// host showed nothing after the user chose a credential type. The wallet now
// publishes `.flowActive` itself, synchronously, with a placeholder flow id
// (`WalletState.FlowActive.pendingFlowId`) and a client-side step, and the
// engine's own events take over from there. Mirrors the Kotlin SDK's
// `WalletState.FlowActive.PENDING_FLOW_ID` / `STEP_*`
// (https://github.com/sirosfoundation/siros-sdk-kotlin/pull/277).
//
// Everything here is pure (no CryptoKit, no network), so it is unit-tested on
// Linux too; `SirosWallet+Issuance.swift` only wires it to the wallet.

extension WalletState {
    /// Constants of the `.flowActive` state.
    public enum FlowActive {
        /// `flowId` of the synchronous pre-engine state; never a real engine flow id.
        public static let pendingFlowId = ""

        /// `flowType` of an issuance flow.
        public static let flowTypeIssuance = "issuance"

        /// Client-side `status` tokens emitted before the engine reports its
        /// first progress step (`parsing_offer`), in order. The wallet does
        /// this work itself, so they are not part of the engine's step
        /// vocabulary. Steps that do not apply to a start path are skipped (an
        /// offer URI has no entitlement check).
        public static let stepInitializing = "initializing"
        public static let stepConnectingEngine = "connecting_engine"
        public static let stepEstablishingSession = "establishing_session"
        public static let stepCheckingEntitlement = "checking_entitlement"
        public static let stepPreparingIssuance = "preparing_issuance"
        public static let stepStartingFlow = "starting_flow"
    }

    /// True while the wallet is still doing the local work that precedes the
    /// engine's first progress event: a `.flowActive` whose `flowId` is
    /// ``FlowActive/pendingFlowId``. There is no engine flow to cancel or
    /// correlate yet.
    public var isPendingFlow: Bool {
        if case .flowActive(_, _, let flowId, _, _, _) = self {
            return flowId == FlowActive.pendingFlowId
        }
        return false
    }

    /// The pending state an issuance start publishes first, or nil when the
    /// wallet is not `.ready` (from any other state the start proceeds as
    /// before, with no visible flow state).
    func beginningIssuanceStart() -> WalletState? {
        guard case .ready(let userId, let displayName, let credentials, _) = self else { return nil }
        return .flowActive(
            userId: userId,
            displayName: displayName,
            flowId: FlowActive.pendingFlowId,
            flowType: FlowActive.flowTypeIssuance,
            status: FlowActive.stepInitializing,
            credentials: credentials
        )
    }

    /// This pending state with `step` as its status, or nil when it is not
    /// pending or already shows `step`.
    func advancingPendingStep(to step: String) -> WalletState? {
        guard case .flowActive(let userId, let displayName, let flowId, let flowType, let status, let credentials) = self,
              flowId == FlowActive.pendingFlowId, status != step else { return nil }
        return .flowActive(
            userId: userId, displayName: displayName, flowId: flowId,
            flowType: flowType, status: step, credentials: credentials
        )
    }

    /// `.ready` again for a pending state whose start failed, or nil when this
    /// is not a pending state (a real engine flow is not this start's to clear).
    func abandoningPendingStart() -> WalletState? {
        guard isPendingFlow,
              case .flowActive(let userId, let displayName, _, _, _, let credentials) = self else { return nil }
        return .ready(userId: userId, displayName: displayName, credentials: credentials)
    }

    /// The `flowType` the engine's progress event for `flowId` should publish.
    /// An issuance that began with the wallet's own pre-engine steps keeps its
    /// flow type, so the host does not see the flow turn into something else
    /// when the engine speaks (before, it became the step name). Otherwise the
    /// step is the flow type, as it always was.
    func flowTypeForEngineProgress(flowId: String, step: String) -> String {
        if case .flowActive(_, _, let currentId, let currentType, _, _) = self,
           currentType == FlowActive.flowTypeIssuance,
           currentId == FlowActive.pendingFlowId || currentId == flowId {
            return currentType
        }
        return step
    }
}

/// Identifies the current issuance start attempt, so a start still suspended in
/// network work notices that the user cancelled in the meantime and does not go
/// on to send the engine a flow they already cancelled - and so a cancelled
/// start can never clobber a newer one.
final class IssuanceStartEpoch: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    /// Begin a new attempt; every earlier attempt is stale from here on.
    func begin() -> Int {
        lock.lock(); defer { lock.unlock() }
        value += 1
        return value
    }

    /// Make every attempt in progress stale (the user cancelled).
    func invalidate() {
        lock.lock(); value += 1; lock.unlock()
    }

    /// The attempt that is current now (for a cleanup that must not outlive it).
    var current: Int { lock.lock(); defer { lock.unlock() }; return value }

    func isCurrent(_ epoch: Int) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return value == epoch
    }

    /// Throws `CancellationError` when `epoch` is no longer current.
    func checkCurrent(_ epoch: Int) throws {
        if !isCurrent(epoch) { throw CancellationError() }
    }
}
