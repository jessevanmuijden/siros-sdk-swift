// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport

extension SirosWallet {
    /// `wmp.flow.complete` for an issuance or presentation. A wallet-encrypted issuance is paired and stored exactly
    /// like the WebSocket's `flow_complete`; a plain completion that carries a credential entry without its value
    /// is refused whole, as on the WebSocket, rather than reported as a success.
    func handleWmpFlowComplete(flowId: String, result: AnyCodable?) async {
        if flowAlreadyEnded(flowId) { return }          // a late completion does not revive a failed or cancelled flow
        lock.lock(); let offeredKey = offeredResponseKeyFlows.contains(flowId); lock.unlock()
        if offeredKey, !Self.claimsEncryptedResponse(result) {
            let ids = result?.objectValue?["credentials"]?.arrayValue?.compactMap { $0.objectValue?["notification_id"]?.stringValue } ?? []
            await refusePlainCompletion(flowId: flowId, notificationIds: ids)
            return
        }
        // Encrypted-to-the-wallet issuance: same pairing as the WebSocket's flow_complete.
        if Self.claimsEncryptedResponse(result) {
            guard let message = Self.encryptedFlowComplete(flowId: flowId, result: result) else {
                // Encrypted but unreadable: an error, not a plain completion that drops what was decrypted.
                let decrypted = takeDecryptedCredentialResponses(flowId: flowId)
                await rejectDecryptedCompletion(flowId: flowId, responses: decrypted, message: "The completion could not be read")
                return
            }
            // A WMP completion has no wire start tag: it is processed under the issuance epoch captured when its
            // flow first asked for the response key. Without one the issuance cannot be established, and the
            // gate would drop the completion silently AFTER the decrypted responses are gone - so refuse it here.
            lock.lock(); let epoch = wmpFlowIssuanceEpochs.removeValue(forKey: flowId); lock.unlock()
            guard let epoch else {
                let decrypted = takeDecryptedCredentialResponses(flowId: flowId)
                await rejectDecryptedCompletion(
                    flowId: flowId, responses: decrypted, message: "The completion's issuance could not be established"
                )
                return
            }
            var tagged = message
            tagged.startTag = epoch
            await handleFlowComplete(msg: tagged)
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
