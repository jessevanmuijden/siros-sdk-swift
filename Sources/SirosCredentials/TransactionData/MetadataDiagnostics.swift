// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(os)
import os
private let diagnosticsLogger = Logger(subsystem: "org.siros.sdk", category: "TransactionData")
#endif

/// Records whether metadata that was actually USED for an accepted SCA validation had no integrity
/// pin (`vct#integrity`, or the `...#integrity` of a fetched referenced
/// document), so that exactly one warning is emitted per validation.
final class MetadataAuthenticationNote: @unchecked Sendable {
    private let lock = NSLock()
    private var unpinned = false

    func noteUnpinned() { lock.lock(); unpinned = true; lock.unlock() }

    var isUnpinned: Bool { lock.lock(); defer { lock.unlock() }; return unpinned }

    /// Emits the single warning if anything was unpinned.
    func emitIfNeeded() {
        guard isUnpinned else { return }
        TransactionDataDiagnostics.warnUnpinnedMetadata()
    }
}

/// The SDK's warnings for TS12 handling. Messages are FIXED sentences: no
/// type, URL, host, issuer, verifier, credential, transaction field, raw
/// string, hash or error text is ever interpolated, because that a user holds
/// a particular card type is itself private and device logs are read by other tooling.
enum TransactionDataDiagnostics {
    static let unpinnedMessage =
        "SCA transaction handling relied on metadata that is not integrity-pinned"

    /// Where warnings go; tests replace it to capture them.
    nonisolated(unsafe) static var sink: @Sendable (String) -> Void = { message in
        #if canImport(os)
        diagnosticsLogger.warning("\(message, privacy: .public)")
        #endif
    }

    static func warnUnpinnedMetadata() { sink(unpinnedMessage) }
}
