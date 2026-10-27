// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Remembers the presentation request links the wallet has just started, so the SAME link delivered again within a
/// short window is not answered a second time.
///
/// Why: an issuer that wants a presentation before it issues sends the OpenID4VP request to the wallet's redirect
/// URI from its own web page. When the user is returned to that page (the browser tab is still open) it can fire
/// the same request again, and the host app receives the identical link a second time - after the first
/// presentation was already answered. A second flow for it is a duplicate Credential Request screen for a request
/// that is done (and one the verifier would refuse anyway: its nonce is spent). Confirmed on a Pixel against the
/// gdc nym_auth issuer on the Kotlin SDK (siros-sdk-kotlin #333); ported here since Swift's `startPresentation` has
/// the identical gap (no dedup at all).
///
/// Mirrors Kotlin's `PresentationLinkLedger` at the level that applies to this SDK's own flow-lifecycle model:
/// a flat time-and-capacity-bounded ledger of link digests. Swift's engine session has no analogue of the
/// connection-generation sweep that drove Kotlin's later, flow-id-aware releases (`SirosWallet+Engine.swift`'s
/// `cleanupAfterSocketReplacement` only ever touches response-encryption keys, never reports a flow lost), so there
/// is nothing here to coordinate with beyond the link's own admission window.
///
/// Only a SHA-256 digest of the link is kept (it can carry a nonce or other query parameters), never the link
/// itself, bounded to at most `capacity` entries (oldest evicted first).
final class PresentationLinkLedger: @unchecked Sendable {
    private let lock = NSLock()
    private var admittedAt: [String: Date] = [:]
    private var order: [String] = []
    private let window: TimeInterval
    private let capacity: Int
    private let now: () -> Date

    /// - Parameters:
    ///   - window: how long an admitted link is refused again (one minute: long enough for a page to re-fire the
    ///     request on the way back, short enough that a deliberate retry of the SAME link is not blocked for ever).
    ///   - capacity: the most entries kept at once (oldest evicted first).
    init(window: TimeInterval = 60, capacity: Int = 16, now: @escaping () -> Date = Date.init) {
        self.window = window
        self.capacity = capacity
        self.now = now
    }

    /// Whether `link` may start a presentation now: true the first time, or once `window` has passed since it was
    /// last admitted; false for one still within its window. Records it as admitted either way the answer is true.
    func admit(_ link: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let key = Self.digest(link)
        let at = now()
        if let last = admittedAt[key], at.timeIntervalSince(last) < window {
            return false
        }
        if admittedAt[key] == nil {
            order.append(key)
            while order.count > capacity {
                let evicted = order.removeFirst()
                admittedAt.removeValue(forKey: evicted)
            }
        }
        admittedAt[key] = at
        return true
    }

    /// Forgets `link`: a retry of it is admitted again immediately. Used when starting it failed before anything
    /// was sent to the engine (not connected, a token refresh failure, an error from the send itself) - the
    /// admission bought nothing, and a deliberate retry of the SAME link must not wait out the window.
    func release(_ link: String) {
        lock.lock(); defer { lock.unlock() }
        let key = Self.digest(link)
        admittedAt.removeValue(forKey: key)
        order.removeAll { $0 == key }
    }

    /// Forgets every link.
    func releaseAll() {
        lock.lock(); defer { lock.unlock() }
        admittedAt.removeAll()
        order.removeAll()
    }

    private static func digest(_ link: String) -> String {
        SHA256.hash(data: Data(link.utf8)).map { String(format: "%02x", $0) }.joined()
    }
}
