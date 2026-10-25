// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Internal registry that maps flow types, methods, and resolve types
/// to their respective handlers. Used by ``WmpPeer`` for dispatch.
final class WmpRegistry: @unchecked Sendable {
    private var profiles: [WmpProfile] = []
    private var flowHandlers: [String: WmpFlowHandler] = [:]
    private var methodHandlers: [String: WmpMethodHandler] = [:]
    private var resolveHandlers: [String: WmpResolveHandler] = [:]
    private let lock = NSLock()

    /// Register a profile and index its handlers.
    func register(_ profile: WmpProfile) {
        lock.lock()
        defer { lock.unlock() }

        profiles.append(profile)

        if let fh = profile as? WmpFlowHandler {
            for ft in fh.flowTypes {
                assert(flowHandlers[ft] == nil, "Flow type '\(ft)' already registered")
                flowHandlers[ft] = fh
            }
        }
        if let mh = profile as? WmpMethodHandler {
            for m in mh.methods {
                assert(methodHandlers[m] == nil, "Method '\(m)' already registered")
                methodHandlers[m] = mh
            }
        }
        if let rh = profile as? WmpResolveHandler {
            for rt in rh.resolveTypes {
                assert(resolveHandlers[rt] == nil, "Resolve type '\(rt)' already registered")
                resolveHandlers[rt] = rh
            }
        }
    }

    func flowHandler(for flowType: String) -> WmpFlowHandler? {
        lock.lock()
        defer { lock.unlock() }
        return flowHandlers[flowType]
    }

    func methodHandler(for method: String) -> WmpMethodHandler? {
        lock.lock()
        defer { lock.unlock() }
        return methodHandlers[method]
    }

    func resolveHandler(for resolveType: String) -> WmpResolveHandler? {
        lock.lock()
        defer { lock.unlock() }
        return resolveHandlers[resolveType]
    }

    /// Stops every profile's in-flight work (session teardown).
    func shutdownProfiles() {
        lock.lock()
        let all = profiles
        lock.unlock()
        for case let profile as WmpShutdownProfile in all { profile.shutdown() }
    }

    /// Tells every profile the session resumed after a loss.
    func resumeProfiles() {
        lock.lock()
        let all = profiles
        lock.unlock()
        for case let profile as WmpResumeProfile in all { profile.sessionResumed() }
    }

    /// Stops every profile's in-flight work for one flow, synchronously.
    func cancelLocally(flowId: String) {
        lock.lock()
        let all = profiles
        lock.unlock()
        for case let profile as WmpLocalCancelProfile in all { profile.cancelLocally(flowId: flowId) }
    }

    func allCapabilities() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return profiles.flatMap { $0.capabilities }
    }
}
