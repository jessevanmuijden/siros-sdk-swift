// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Transport-independent protocol for sending OID4VCI §10 credential
/// lifecycle notifications.
///
/// Both ``WalletEngineSession`` (legacy WebSocket) and
/// ``FlowClient`` (WMP) conform, allowing callers to send
/// notifications without knowing which transport is active.
public protocol CredentialNotifier: AnyObject, Sendable {
    /// Send a credential lifecycle notification.
    ///
    /// Implementations are fire-and-forget: errors are logged, never thrown.
    /// Calling this when the transport is disconnected is a safe no-op.
    func sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String,
        eventDescription: String?
    )
}

/// Default parameter for eventDescription.
public extension CredentialNotifier {
    func sendCredentialNotification(
        flowId: String,
        notificationId: String,
        event: String
    ) {
        sendCredentialNotification(
            flowId: flowId,
            notificationId: notificationId,
            event: event,
            eventDescription: nil
        )
    }
}

/// Sends OID4VCI section 10 notifications over a WMP peer (`wmp.credential.notification`), so the
/// wallet's acceptance or `credential_failure` reaches the issuer on this transport as it does on the
/// engine WebSocket. A failed send is dropped, as there: the notification is best effort.
public final class WmpCredentialNotifier: CredentialNotifier, @unchecked Sendable {
    private let peer: WmpPeerContext

    public init(peer: WmpPeerContext) {
        self.peer = peer
    }

    public func sendCredentialNotification(flowId: String, notificationId: String, event: String, eventDescription: String?) {
        var params: [String: AnyCodable] = [
            "flow_id": .string(flowId),
            "notification_id": .string(notificationId),
            "event": .string(event),
        ]
        if let eventDescription { params["event_description"] = .string(eventDescription) }
        let peer = self.peer
        Task { try? await peer.notify(method: WmpMethods.credentialNotification, params: params) }
    }
}
