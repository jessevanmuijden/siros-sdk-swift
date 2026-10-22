// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosWallet
import SirosCredentials

/// The EC TS12 surface of the view model: bridging the SDK's consent handler
/// to a sheet, and the transaction log screen. No TS12 logic lives here.
extension WalletViewModel {

    /// Bridges the SDK's `TransactionConsentHandler.confirm` to
    /// `TransactionConsentSheet`: suspends until the user confirms or
    /// declines. A prompt still pending when another arrives is declined, and
    /// cancelling the awaiting task (the SDK's deadline passing) withdraws the
    /// prompt and declines.
    nonisolated func requestTransactionConsent(_ request: TransactionConsentRequest) async -> Bool {
        let box = TransactionConsentContinuationBox()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                guard box.set(continuation) else { return }   // already cancelled: resumed with false
                Task { @MainActor in
                    // Cancelled or answered before this ran: nothing to show.
                    guard box.isPending else { return }
                    self.transactionConsentBox?.resumeOnce(false)
                    self.transactionConsentBox = box
                    self.pendingTransactionConsent = PendingTransactionConsent(request: request, respond: { answer in
                        self.finishTransactionConsent(box)
                        box.resumeOnce(answer)
                    })
                }
            }
        } onCancel: {
            box.cancel()
            Task { @MainActor in self.finishTransactionConsent(box) }
        }
    }

    /// Clears the prompt and box, but only if `box` is still the current one: a
    /// response from an outgoing prompt must not clear a newer one.
    func finishTransactionConsent(_ box: TransactionConsentContinuationBox) {
        guard transactionConsentBox === box else { return }
        pendingTransactionConsent = nil
        transactionConsentBox = nil
    }

    /// Declines whatever prompt is pending.
    func dismissTransactionConsent() {
        pendingTransactionConsent = nil
        transactionConsentBox?.resumeOnce(false)
        transactionConsentBox = nil
    }

    func openTransactionLog() {
        showTransactionLog = true
        // Every load takes its own generation, so a slower older read can never overwrite a newer one.
        transactionLogGeneration += 1
        let generation = transactionLogGeneration
        Task {
            defer { transactionLogLoadFinished?() }
            let entries = await wallet?.transactionLog() ?? []
            // Only publish if the session it was read for is still the active one.
            guard generation == transactionLogGeneration else { return }
            transactionLog = entries
        }
    }

    func closeTransactionLog() {
        showTransactionLog = false
    }

    /// Account-scoped state must not outlive the session: the log entries, the
    /// screen and any prompt still showing.
    func resetTransactionDataState() {
        transactionLogGeneration += 1
        showTransactionLog = false
        transactionLog = []
        dismissTransactionConsent()
    }
}
