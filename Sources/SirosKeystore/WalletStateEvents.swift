// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit

/// The events a client without an event log of its own still has to append
/// (privatedata-spec section 6.1.3): "a client that keeps no event log MUST still
/// append a `set_extension` event to `events`, chained by `parentHash` as
/// `wallet-frontend` chains events, whenever it changes `S.extensions`".
///
/// The chain is `wallet-frontend`'s (`WalletStateSchemaVersion1.ts`,
/// `calculateEventHash`; `WalletStateSchema.ts`, `createWalletSessionEvent`): an
/// event's `parentHash` is the SHA-256 (lowercase hex) of the previous event's
/// JSON with every object's keys sorted and no whitespace, or, for the first event
/// of the log, the container's `lastEventHash`. A `new_keypair` event is hashed
/// with `keypair.wrappedPrivateKey` set to null, since that member changes with
/// every change of the keystore.
enum WalletStateEvents {

    static func hash(_ event: [String: Any]) -> String {
        var hashed = event
        if event["type"] as? String == "new_keypair", var keypair = event["keypair"] as? [String: Any] {
            keypair["wrappedPrivateKey"] = NSNull()
            hashed["keypair"] = keypair
        }
        let data = (try? JSONSerialization.data(
            withJSONObject: hashed, options: [.sortedKeys, .withoutEscapingSlashes]
        )) ?? Data()
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    /// The `parentHash` for an event appended to `events`.
    static func parentHash(after events: [Any], lastEventHash: String) -> String {
        guard let last = events.last else { return lastEventHash }
        return (last as? [String: Any]).map(hash) ?? lastEventHash
    }

    /// A `set_extension` event, version 4 (a writer emits 4 whatever the container was).
    /// `value` nil is the tombstone.
    static func setExtension(
        namespace: String, key: String, value: String?, eventId: Int, timestampSeconds: Int, parentHash: String
    ) -> [String: Any] {
        [
            "type": "set_extension",
            "schemaVersion": WalletStateSchema.currentVersion,
            "eventId": eventId,
            "parentHash": parentHash,
            "timestampSeconds": timestampSeconds,
            "namespace": namespace,
            "key": key,
            "value": value.map { $0 as Any } ?? NSNull(),
        ]
    }
}

/// A change to `S.extensions` waiting to be written as a `set_extension` event at the next export.
struct PendingExtensionEvent {
    let namespace: String
    let key: String
    let value: String?
    let eventId: Int
    let timestampSeconds: Int

    init(namespace: String, key: String, value: String?) {
        self.namespace = namespace
        self.key = key
        self.value = value
        // wallet-frontend's `getRandomUint32`: never 0.
        self.eventId = Int(UInt32.random(in: 1...UInt32.max))
        self.timestampSeconds = Int(Date().timeIntervalSince1970)
    }

    /// `events` followed by one chained event per pending change, in order.
    static func appending(_ pending: [PendingExtensionEvent], to events: [Any], lastEventHash: String) -> [Any] {
        var result = events
        for change in pending {
            result.append(WalletStateEvents.setExtension(
                namespace: change.namespace, key: change.key, value: change.value,
                eventId: change.eventId, timestampSeconds: change.timestampSeconds,
                parentHash: WalletStateEvents.parentHash(after: result, lastEventHash: lastEventHash)
            ))
        }
        return result
    }
}
#endif
