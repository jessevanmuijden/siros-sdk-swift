// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosCredentials
import SirosTransport
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "SirosWallet")
#endif

extension SirosWallet {
    /// The issuance trust gate (fail closed), run on `flow_complete` before
    /// ANYTHING is stored, superseded, captured or synced. See
    /// `issuanceTrustRefusal` for the policy.
    ///
    /// - Returns: true when the completion has been dealt with and the caller
    ///   must stop (the issuance was refused, or the session ended while the
    ///   trust check was awaiting the network); false to carry on and store.
    func issuanceTrustGateHandled(_ msg: FlowCompleteMessage, offer: CredentialOffer?) async -> Bool {
        guard let credentials = msg.credentials, !credentials.isEmpty else { return false }
        lock.lock(); let generation = sessionGeneration; lock.unlock()
        let refusal = await issuanceTrustRefusal(
            credentials: credentials,
            engineTrust: msg.issuerTrust,
            mdocTrust: { await self.mdocIssuanceTrustResult($0) }
        )
        lock.lock(); let sessionEnded = sessionGeneration != generation; lock.unlock()
        if sessionEnded {
            // The trust check awaited the network and the session ended meanwhile
            // (logout / account deletion): this completion no longer owns any state.
            #if canImport(os)
            logger.warning("Flow \(msg.flowId, privacy: .public) completed after its session ended; dropping it")
            #endif
            return true
        }
        guard let refusal else { return false }
        await refuseUntrustedIssuance(msg: msg, offer: offer, reason: refusal)
        return true
    }

    /// Decodes an issued `mso_mdoc` credential and evaluates its issuer; nil
    /// if it cannot be verified (unparseable, no x5chain, bad signature, or a
    /// platform without the Security framework).
    func mdocIssuanceTrustResult(_ credential: CredentialResult) async -> TrustResult? {
        if let hook = mdocIssuanceTrustHook { return await hook(credential) }
        guard let document = CredentialUtils.parseMdocDocument(credential.credential) else {
            #if canImport(os)
            logger.warning("Issued mdoc credential could not be parsed for the issuer trust check")
            #endif
            return nil
        }
        return await verifyAndEvaluateIssuerTrust(document.issuerSigned.issuerAuth, docType: document.docType)
    }

    /// Ends an issuance whose issuer trust was not established: nothing is
    /// stored, no refresh token is captured, nothing is synced, a renewal's old
    /// batch is left untouched, and the issuer is told the wallet did not
    /// accept the credential (OID4VCI `credential_failure`, best effort, a
    /// fixed code and no detail).
    private func refuseUntrustedIssuance(msg: FlowCompleteMessage, offer: CredentialOffer?, reason: String) async {
        let issuer = offer?.credentialIssuerIdentifier ?? msg.credentialIssuer ?? msg.issuerTrust?.issuer
        #if canImport(os)
        logger.error("Refusing issuance for flow \(msg.flowId, privacy: .public) from \(issuer ?? "unknown issuer", privacy: .public): \(reason, privacy: .public)")
        #endif
        lock.lock(); let notifier = credentialNotifier; lock.unlock()
        for notificationId in (msg.credentials ?? []).compactMap({ $0.notificationId }) {
            notifier?.sendCredentialNotification(
                flowId: msg.flowId,
                notificationId: notificationId,
                event: CredentialNotificationEvent.failure,
                eventDescription: "issuer_not_trusted"
            )
        }
        resetIssuanceGuards()
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onIssuerNotTrusted(flowId: msg.flowId, issuer: issuer, reason: reason)
        listener?.onFlowError(flowId: msg.flowId, errorMessage: issuerNotTrustedMessage, redirectUri: msg.redirectUri)
        switch state {
        case .flowActive(let userId, let displayName, _, _, _, _),
             .ready(let userId, let displayName, _, _):
            let creds = await credentialStore.getAll()
            setState(.ready(userId: userId, displayName: displayName, credentials: creds))
        default:
            break
        }
    }
}
