// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A pluggable extension to WMP. Profiles define additional capabilities,
/// flow types, resolve handlers, and custom methods.
///
/// Register profiles with ``WmpPeer/use(_:)`` before connecting.
public protocol WmpProfile: AnyObject {
    /// Profile identifier (e.g., "openid4x").
    var name: String { get }

    /// Capability names this profile provides for session negotiation.
    var capabilities: [String] { get }

    /// Called when the profile is registered with a Peer.
    func initialize(ctx: WmpPeerContext)
}

/// Provides profiles with the ability to send messages and access session state.
public protocol WmpPeerContext: AnyObject {
    /// Send a JSON-RPC 2.0 notification (fire-and-forget).
    func notify(method: String, params: [String: AnyCodable]?) async throws

    /// Send a JSON-RPC 2.0 request and wait for the response.
    func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse

    /// The codec used for encoding/decoding messages.
    var codec: WmpCodec { get }

    /// Stop routing a flow that this side has finished (it sent its terminal `wmp.flow.complete` or
    /// `wmp.flow.error`): the peer only forgets a flow on an INCOMING terminal message, so a locally
    /// finished child would otherwise stay tracked for the session.
    func releaseFlow(flowId: String)
}

public extension WmpPeerContext {
    func releaseFlow(flowId: String) {}
}

/// Handles profile-specific flow types. The Peer dispatches flow operations
/// to the handler whose ``flowTypes`` contains the incoming flow_type.
public protocol WmpFlowHandler: AnyObject {
    /// Flow type identifiers this handler manages (e.g., "oid4vci", "oid4vp").
    var flowTypes: [String] { get }

    /// Called for wmp.flow.start with a matching flow_type.
    func startFlow(params: FlowStartParams) async throws -> FlowStartResult

    /// Called for wmp.flow.action on a flow managed by this handler.
    func handleAction(params: FlowActionParams) async throws -> FlowActionResult

    /// Called for wmp.flow.progress on a flow managed by this handler.
    func handleProgress(params: FlowProgressParams) async

    /// Called for wmp.flow.complete on a flow managed by this handler.
    func handleComplete(params: FlowCompleteParams) async

    /// Called for wmp.flow.error on a flow managed by this handler.
    func handleError(params: FlowErrorParams) async

    /// Called for wmp.flow.cancel on a flow managed by this handler.
    func handleCancel(params: FlowCancelParams) async
}

/// Handles custom JSON-RPC methods defined by a profile.
public protocol WmpMethodHandler: AnyObject {
    /// Method names this handler supports.
    var methods: [String] { get }

    /// Process an incoming method call. Returns the result or throws.
    func handleMethod(method: String, params: AnyCodable?) async throws -> AnyCodable?
}

/// Handles profile-specific resolution types for wmp.resolve.
public protocol WmpResolveHandler: AnyObject {
    /// Resolution type identifiers this handler supports.
    var resolveTypes: [String] { get }

    /// Process a resolve request for a supported type.
    func handleResolve(params: ResolveParams) async throws -> ResolveResult
}

/// A profile with work of its own in flight (child flows running application handlers) that the peer must be
/// able to stop when the session ends.
public protocol WmpShutdownProfile: AnyObject {
    /// Cancel everything in flight and answer nothing more.
    func shutdown()
}

/// A profile that holds answers it could not send while the connection was down.
public protocol WmpResumeProfile: AnyObject {
    /// The session resumed: send what could not be sent.
    func sessionResumed()
}

/// A profile that can stop its own work for one flow at once, without the asynchronous cancel path (which also
/// runs application callbacks later, when a replacement flow may already be running).
public protocol WmpLocalCancelProfile: AnyObject {
    /// Stop the work in flight for `flowId` and its children; answer nothing more for them.
    func cancelLocally(flowId: String)
}
