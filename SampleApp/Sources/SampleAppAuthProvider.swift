// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosKeystore
#if canImport(siros_wscd_managerFFI)
import siros_wscd_managerFFI
#endif

#if canImport(siros_wscd_managerFFI)
// MARK: - SampleAppAuthProvider

/// Bridges `WscdAuthProvider`'s synchronous, FFI-thread-blocking callbacks
/// (see its doc comment) to the sample app's SwiftUI PIN-entry sheet, using
/// the same `DispatchSemaphore` + `Task { @MainActor in ... }` technique as
/// `Ctap2TransportBridge.ctap2SendCommand` - `requestPin` is called
/// synchronously from the FFI queue, not `async`, so `requestWscdChoice`'s
/// plain `withCheckedContinuation` bridge (for the genuinely async
/// `RequestWscdChoice` callback) doesn't apply here.
final class SampleAppAuthProvider: WscdAuthProvider, @unchecked Sendable {
    private weak var viewModel: WalletViewModel?

    init(viewModel: WalletViewModel) {
        self.viewModel = viewModel
    }

    func requestPin(pluginId: String) throws -> Data {
        try requestPin(pluginId: pluginId, request: PinRequest(kind: .enterPin))
    }

    /// The SDK's PIN interface with a kind: it owns the choose/confirm/compare logic for a NEW PIN and calls this
    /// once per prompt; this app only shows the sheet.
    func requestPin(pluginId: String, request: PinRequest) throws -> Data {
        guard pluginId == "fido2" else {
            // Every non-FIDO2 plugin (currently just "r2ps") uses a fixed
            // debug-only test PIN in this sample app - matches the Kotlin
            // sample app's `AuthProvider.requestPin` fallback exactly. See
            // `WscdAuthProvider.requestPin`'s doc comment for why dispatch
            // MUST be on `pluginId` and not ambient state: a real hardware
            // PIN was silently sent to the wrong plugin for an entire
            // hardware-testing session before that fix.
            return Data("test-pin-1234".utf8)
        }

        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<Data, Error> = .failure(FfiWscdError.AuthCancelled(msg: "No WalletViewModel"))

        Task { @MainActor in
            guard let viewModel else {
                semaphore.signal()
                return
            }
            let entryId = UUID()
            let answered = OnceFlag()
            viewModel.pendingFido2PinEntry = PendingFido2PinEntry(id: entryId, request: request, respond: { pin in
                // Single-use: the first answer wins, later ones (a duplicate tap, a late dismissal) do nothing.
                guard answered.setOnce() else { return }
                // Clear the sheet only if it still shows THIS prompt; the SDK may already have installed the next
                // one (confirmation, retry) the moment the semaphore below is signalled.
                if viewModel.pendingFido2PinEntry?.id == entryId { viewModel.pendingFido2PinEntry = nil }
                if let pin, !pin.isEmpty {
                    result = .success(Data(pin.utf8))
                } else {
                    result = .failure(FfiWscdError.AuthCancelled(msg: "User cancelled PIN entry"))
                }
                semaphore.signal()
            })
        }

        semaphore.wait()
        switch result {
        case .success(let data): return data
        case .failure(let error): throw error
        }
    }

    func requestWebauthnAssertion(
        pluginId: String,
        challenge: Data,
        rpId: String,
        allowedCredentials: [Data]
    ) throws -> Data {
        // No WebAuthn-assertion-based plugin ceremony is exercised by this
        // sample app today (R2PS uses OPAQUE, FIDO2 uses ClientPin above).
        throw FfiWscdError.AuthCancelled(msg: "WebAuthn assertion not implemented in sample app")
    }
}
#endif

#if canImport(siros_wscd_managerFFI)
/// A flag that can be set once, thread-safely: the first `setOnce()` returns true, every later one false.
final class OnceFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func setOnce() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if done { return false }
        done = true
        return true
    }
}
#endif
