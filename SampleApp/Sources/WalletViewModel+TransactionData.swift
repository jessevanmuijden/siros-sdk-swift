// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosWallet
import SirosCredentials

/// The EC TS12 surface of the view model: bridging the SDK's consent handler
/// to a sheet, and the transaction log screen. No TS12 logic lives here.
extension WalletViewModel {

    /// Puts a transaction to the user through the SDK's `ConsentPrompt` (exactly one answer; declined on dismiss,
    /// supersede and task cancellation) and shows it in `TransactionConsentSheet`.
    nonisolated func requestTransactionConsent(_ request: TransactionConsentRequest) async -> Bool {
        await transactionConsent.ask(request)
    }

    /// Declines whatever prompt is pending.
    func dismissTransactionConsent() { transactionConsent.dismiss() }

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
