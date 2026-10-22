// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

extension SirosWallet {
    /// `wmp.flow.complete` for an issuance or presentation. A wallet-encrypted issuance is paired and stored exactly
    /// like the WebSocket's `flow_complete`; a plain completion that carries a credential entry without its value
    /// is refused whole, as on the WebSocket, rather than reported as a success.
    func handleWmpFlowComplete(flowId: String, result: AnyCodable?) async {
        lock.lock(); let offeredKey = credentialResponseKeys[flowId] != nil; lock.unlock()
        if offeredKey, !Self.claimsEncryptedResponse(result) {
            let ids = result?.objectValue?["credentials"]?.arrayValue?.compactMap { $0.objectValue?["notification_id"]?.stringValue } ?? []
            await refusePlainCompletion(flowId: flowId, notificationIds: ids)
            return
        }
        // Encrypted-to-the-wallet issuance: same pairing as the WebSocket's flow_complete.
        if Self.claimsEncryptedResponse(result) {
            guard let message = Self.encryptedFlowComplete(flowId: flowId, result: result) else {
                // Encrypted but unreadable: an error, not a plain completion that drops what was decrypted.
                await failIssuanceLocally(flowId: flowId, message: "The completion could not be read")
                return
            }
            await handleFlowComplete(msg: message)
            return
        }
        if let entries = result?.objectValue?["credentials"]?.arrayValue,
           entries.contains(where: { ($0.objectValue?["credential"]?.stringValue ?? "").isEmpty }) {
            await failIssuanceLocally(flowId: flowId, message: "The issuer's credential did not arrive")
            return
        }
        // Terminal path for this issuance over the WMP transport too - see `resetIssuanceGuards()`.
        resetIssuanceGuards()
        cancelTransactionTasks(flowId: flowId)
        eventListener?.onFlowComplete(flowId: flowId, redirectUri: nil)
    }
}
