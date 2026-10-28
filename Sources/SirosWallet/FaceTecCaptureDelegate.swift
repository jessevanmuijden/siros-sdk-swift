// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// FaceTec biometric capture delegate for the session → liveness → document
/// flow (``RemoteIDVClient``).
///
/// - Important: Deprecated and no longer functional. It was written against the
///   FaceTec **9** API (`createSessionVC`, `FaceTecFaceScanProcessorDelegate`),
///   which FaceTec 10 removed, so with a FaceTec 10 SDK linked its body no longer
///   compiled and broke the build of the whole package. It also called
///   `IDVError.cancelled(reason:)`, which has no associated value, so it never
///   compiled with any FaceTec SDK. Every method now throws
///   ``IDVError/unavailable(reason:)``. Use ``FaceTecIDVProvider``, which drives
///   FaceTec 10 through facetec-api's `/process-request`.
@available(*, deprecated, message: "Written against the FaceTec 9 API, which FaceTec 10 removed, and it no longer works. Use FaceTecIDVProvider.")
public final class FaceTecCaptureDelegate: @unchecked Sendable, BiometricCaptureDelegate {

    public var name: String { "FaceTec" }

    public init() {}

    public func isAvailable() async -> Bool {
        false
    }

    public func captureLiveness(presentingViewController: Any, sessionToken: String) async throws -> [String: Any] {
        throw Self.unavailable
    }

    public func captureDocument(presentingViewController: Any, sessionToken: String, livenessSessionId: String) async throws -> [String: Any] {
        throw Self.unavailable
    }

    private static var unavailable: IDVError {
        IDVError.unavailable(reason: "FaceTecCaptureDelegate targets the FaceTec 9 API and no longer works. Use FaceTecIDVProvider.")
    }
}
