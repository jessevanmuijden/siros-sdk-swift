// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(UIKit)
import UIKit
#endif
#if canImport(CoreNFC) && os(iOS)
import CoreNFC
#endif
#if canImport(FaceTecSDK)
import FaceTecSDK
#endif

/// Identity verification with the FaceTec **10** SDK and facetec-api.
///
/// Runs FaceTec's 3D liveness, document scan (with NFC chip read) and 3D:2D
/// photo match as one session. Every request blob of the session goes to
/// facetec-api's `/process-request`, which proxies it to FaceTec Server and,
/// once the match succeeds and the document's chip was authenticated, issues a
/// credential: the session's ``IDVResult`` carries that credential offer.
///
/// ```swift
/// let provider = FaceTecIDVProvider(config: FaceTecIDVConfig(
///     processRequestUrl: URL(string: "https://idv.example.com/v1/process-request")!,
///     authToken: "Bearer \(token)",
///     deviceKeyIdentifier: "<from FaceTec>"
/// ))
/// try await wallet.verifyIdentityAndIssue(provider: provider, presentingViewController: vc)
/// ```
///
/// ## What facetec-api requires of its clients (v0.16.0)
///
/// - The **same `externalDatabaseRefID` on every `/process-request` of one
///   FaceTec session**. facetec-api records FaceTec Server's liveness verdict
///   under it and refuses the final result with `liveness_failed` unless that
///   session's liveness was proven; a request without the ID is refused too.
///   The provider mints one ID per session (one `FaceTecSessionRelay` per
///   ``startVerification(presentingViewController:)`` call), so a retry inside
///   FaceTec's UI keeps it and a new scan gets a fresh one.
/// - A liveness proof is single-use and expires (15 minutes by default), so a
///   refused or abandoned session cannot be resumed: start a new one.
/// - Every request of a session must reach the same facetec-api instance
///   (sticky routing, or a single instance).
///
/// ## Cancellation
///
/// Cancelling the Swift `Task` that awaits ``startVerification(presentingViewController:)``
/// does not close FaceTec's UI: the call returns once the user (or FaceTec)
/// ends the session.
///
/// ## App requirements
///
/// - The FaceTec iOS SDK 10 xcframework linked into the app. This package has
///   no dependency on it (it is distributed privately); without it
///   ``isAvailable()`` is `false` and ``startVerification(presentingViewController:)``
///   throws ``IDVError/unavailable(reason:)``.
/// - `NSCameraUsageDescription`, and for the chip read the "NFC Tag Reading"
///   capability with `NFCReaderUsageDescription` and the ISO 7816 application
///   identifiers FaceTec documents. ``HostAppRequirements`` (`.identityVerification`)
///   lists them and `audit` checks them.
///
/// ## Errors
///
/// - ``IDVError/cancelled``: the user left the face or ID scan.
/// - ``IDVError/documentChipNotVerified(reason:message:)``: facetec-api refused
///   because the document's chip was not read and authenticated (`nfc_*`).
/// - ``IDVError/livenessFailed(message:)``, ``IDVError/verificationFailed(message:)``:
///   liveness, face match, policy or unreadable-document refusals.
/// - ``IDVError/chipUntrusted(message:)``, ``IDVError/chipPhotoMismatch(message:)``,
///   ``IDVError/documentExpired(message:)``, ``IDVError/sessionExpired(message:)``:
///   facetec-api's `chip_untrusted`, `chip_photo_mismatch`, `document_expired`
///   and `session_expired`.
/// - ``IDVError/providerError(code:message:)``: any other refusal code
///   (`issuance_failed`, `internal_error`, ...) or FaceTec status, with the
///   code kept.
/// - ``IDVError/networkError(underlying:)``: facetec-api could not be reached
///   during the session.
/// - ``IDVError/unavailable(reason:)``: no FaceTec SDK, no device key
///   identifier, no camera permission, or (with ``FaceTecIDVConfig/requireNfc``)
///   a device that cannot read NFC.
public final class FaceTecIDVProvider: @unchecked Sendable, IdentityVerificationProvider {

    private let config: FaceTecIDVConfig
    private let client: FaceTecProcessRequestClient
    private let configureSession: (@MainActor @Sendable () -> Void)?

    /// - Parameters:
    ///   - config: Where facetec-api is and which FaceTec device key to use.
    ///   - configureSession: Called on the main actor once FaceTec has
    ///     initialized and before the session starts: the place for
    ///     `FaceTec.sdk.setCustomization(...)` and string localization, which
    ///     FaceTec only accepts after initialization.
    public init(config: FaceTecIDVConfig, configureSession: (@MainActor @Sendable () -> Void)? = nil) {
        self.config = config
        self.client = FaceTecProcessRequestClient(config: config)
        self.configureSession = configureSession
    }

    public var name: String { "FaceTec" }

    /// Whether a FaceTec 10 SDK is linked, a device key identifier is set and,
    /// with ``FaceTecIDVConfig/requireNfc``, the device can read NFC: the same
    /// conditions ``startVerification(presentingViewController:)`` checks first.
    public func isAvailable() async -> Bool {
        #if canImport(FaceTecSDK) && canImport(UIKit)
        return !config.deviceKeyIdentifier.isEmpty && (!config.requireNfc || Self.isNFCReadingAvailable)
        #else
        return false
        #endif
    }

    public func startVerification(presentingViewController: Any) async throws -> IDVResult {
        #if canImport(FaceTecSDK) && canImport(UIKit)
        guard !config.deviceKeyIdentifier.isEmpty else {
            throw IDVError.unavailable(reason: "no FaceTec device key identifier configured")
        }
        guard let viewController = presentingViewController as? UIViewController else {
            throw IDVError.unavailable(reason: "presentingViewController must be a UIViewController")
        }
        if config.requireNfc, !Self.isNFCReadingAvailable {
            throw IDVError.unavailable(reason: "this device cannot read NFC, which reading the document's chip requires")
        }
        return try await runSession(presenting: viewController)
        #else
        throw IDVError.unavailable(reason: "FaceTec SDK not linked. Add the FaceTec 10 xcframework to your app target.")
        #endif
    }

    #if canImport(FaceTecSDK) && canImport(UIKit)

    private static var isNFCReadingAvailable: Bool {
        #if canImport(CoreNFC) && os(iOS)
        return NFCTagReaderSession.readingAvailable
        #else
        return false
        #endif
    }

    @MainActor
    private func runSession(presenting viewController: UIViewController) async throws -> IDVResult {
        let client = self.client
        let relay = FaceTecSessionRelay { blob, refID in
            try await client.post(requestBlob: blob, externalDatabaseRefID: refID)
        }
        let exit = FaceTecSessionExit()
        let processor = FaceTecSessionRequestRelayProcessor(relay: relay, exit: exit)

        // Not a `CheckedContinuation<FaceTecSDKInstance, Error>`: specializing a
        // generic over FaceTecSDKInstance makes the compiler reference
        // `_OBJC_CLASS_$_FaceTecSDKInstance`, which FaceTec's xcframework does not
        // export. Plain, non-generic use resolves.
        let holder = FaceTecInstanceHolder()
        let deviceKey = config.deviceKeyIdentifier
        // FaceTec calls back exactly once; the guard keeps a surprise second call
        // from resuming the continuation twice (a crash).
        let once = ResumeOnce()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            FaceTec.sdk.initializeWithSessionRequest(
                deviceKeyIdentifier: deviceKey,
                sessionRequestProcessor: processor,
                completion: FaceTecInitializeCallbackBox(
                    // These may arrive on any thread. The holder is lock-protected,
                    // and the error path hops to the main actor before touching
                    // `FaceTec.sdk`.
                    onSuccess: { sdkInstance in
                        guard once.claim() else { return }
                        holder.instance = sdkInstance
                        continuation.resume()
                    },
                    onError: { error in
                        guard once.claim() else { return }
                        Task { @MainActor in
                            continuation.resume(throwing: IDVError.providerError(
                                code: "initialization_failed",
                                message: "FaceTec SDK could not be initialized: \(FaceTec.sdk.description(for: error))"
                            ))
                        }
                    }
                )
            )
        }
        guard let sdkInstance = holder.instance else {
            throw IDVError.providerError(code: "initialization_failed", message: "FaceTec SDK could not be initialized")
        }

        // FaceTec accepts customization only after initialization succeeded;
        // earlier it crashes inside the SDK.
        configureSession?()

        let sessionViewController = sdkInstance.start3DLivenessThen3D2DPhotoIDMatch(with: processor)
        viewController.present(sessionViewController, animated: true)

        return try sessionOutcome(status: await exit.wait(), relay: relay)
    }

    #endif
}

/// Lets exactly one of several callers through.
final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    /// `true` for the first call, `false` for every later one.
    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}

/// A one-shot hand-off of the session's end status from FaceTec's exit
/// callback to the awaiting provider. Whichever of ``fire(_:)`` and ``wait()``
/// comes first, the other still sees the value, so a session that exits before
/// the provider starts waiting is not lost.
final class FaceTecSessionExit: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false
    private var value: FaceTecSessionEnd?
    private var waiter: CheckedContinuation<FaceTecSessionEnd?, Never>?

    func fire(_ end: FaceTecSessionEnd?) {
        lock.lock()
        if fired { lock.unlock(); return }
        fired = true
        value = end
        let waiting = waiter
        waiter = nil
        lock.unlock()
        waiting?.resume(returning: end)
    }

    func wait() async -> FaceTecSessionEnd? {
        await withCheckedContinuation { (continuation: CheckedContinuation<FaceTecSessionEnd?, Never>) in
            lock.lock()
            if fired {
                let result = value
                lock.unlock()
                continuation.resume(returning: result)
            } else {
                waiter = continuation
                lock.unlock()
            }
        }
    }
}

#if canImport(FaceTecSDK) && canImport(UIKit)

/// FaceTec's `FaceTecSessionRequestProcessor` for one session, delegating to a
/// ``FaceTecSessionRelay``.
///
/// Per FaceTec's integration contract, `onSessionRequest` only performs the
/// network call and the minimum bookkeeping needed to hand its result back to
/// the SDK. Request and response blobs are never logged.
private final class FaceTecSessionRequestRelayProcessor: NSObject, FaceTecSessionRequestProcessor, @unchecked Sendable {
    private let relay: FaceTecSessionRelay
    private let exit: FaceTecSessionExit

    init(relay: FaceTecSessionRelay, exit: FaceTecSessionExit) {
        self.relay = relay
        self.exit = exit
    }

    func onSessionRequest(sessionRequestBlob: String, sessionRequestCallback: FaceTecSessionRequestProcessorCallback) {
        // FaceTec expects every call back into the callback on the main thread
        // (its own sample pins the URLSession delegate queue to .main).
        // `await` resumes on an arbitrary executor, so hop back explicitly.
        Task { @MainActor in
            if let responseBlob = await relay.onSessionRequest(sessionRequestBlob) {
                sessionRequestCallback.processResponse(responseBlob)
            } else {
                sessionRequestCallback.abortOnCatastrophicError()
            }
        }
    }

    func onFaceTecExit(sessionResult: FaceTecSessionResult) {
        exit.fire(Self.end(of: sessionResult.sessionStatus))
    }

    private static func end(of status: FaceTecSessionStatus) -> FaceTecSessionEnd? {
        switch status {
        case .sessionCompleted: return .sessionCompleted
        case .requestAborted: return .requestAborted
        case .userCancelledFaceScan: return .userCancelledFaceScan
        case .userCancelledIDScan: return .userCancelledIdScan
        case .lockedOut: return .lockedOut
        case .cameraError: return .cameraError
        case .cameraPermissionsDenied: return .cameraPermissionsDenied
        case .unknownInternalError: return .unknownInternalError
        @unknown default: return nil
        }
    }
}

/// Hands the initialized SDK instance from FaceTec's callback to the awaiting
/// session. A plain, non-generic holder (see the comment where it is used), safe
/// to set from whichever thread FaceTec calls back on.
private final class FaceTecInstanceHolder: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: FaceTecSDKInstance?

    var instance: FaceTecSDKInstance? {
        get { lock.lock(); defer { lock.unlock() }; return stored }
        set { lock.lock(); defer { lock.unlock() }; stored = newValue }
    }
}

/// Bridges FaceTec's `FaceTecInitializeCallback` delegate protocol to a pair of
/// closures so `initializeWithSessionRequest` can be awaited.
private final class FaceTecInitializeCallbackBox: NSObject, FaceTecInitializeCallback {
    private let onSuccess: (FaceTecSDKInstance) -> Void
    private let onError: (FaceTecInitializationError) -> Void

    init(onSuccess: @escaping (FaceTecSDKInstance) -> Void, onError: @escaping (FaceTecInitializationError) -> Void) {
        self.onSuccess = onSuccess
        self.onError = onError
    }

    func onFaceTecSDKInitializeSuccess(sdkInstance: FaceTecSDKInstance) {
        onSuccess(sdkInstance)
    }

    func onFaceTecSDKInitializeError(error: FaceTecInitializationError) {
        onError(error)
    }
}

#endif
