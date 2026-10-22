// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// What a log record says about the transaction itself (TS12 5.3).
public struct TransactionLogSubject: Sendable, Equatable {
    public let transactionId: String?
    public let typeName: String?
    public let entities: [String: String]

    public init(transactionId: String?, typeName: String?, entities: [String: String] = [:]) {
        self.transactionId = transactionId
        self.typeName = typeName
        self.entities = entities
    }
}

/// One transaction-log record for an SCA presentation attempt (TS12 v1.0.1
/// section 5.3), written whether it succeeded, was declined or was refused.
///
/// Holds only the fields section 5.3 names; never the full payload.
public struct TransactionLogEntry: Codable, Sendable, Equatable, Identifiable {
    public enum Outcome: String, Codable, Sendable {
        case consented, declined, refused
    }

    public let id: String
    /// Milliseconds since the Unix epoch.
    public let timestamp: Int64
    /// `payload.transaction_id`, when the entry could be decoded.
    public let transactionId: String?
    /// The transaction type name (`transaction_data_types.name` in section 5.3
    /// terms): "Payment Confirmation" and so on, else the type URI.
    public let typeName: String?
    /// Relevant entity names as present: `payee`, `pisp`, `service`, `aisp`.
    public let entities: [String: String]
    public let verifier: String
    public let credential: String
    public let outcome: Outcome
    /// The `TransactionDataError.Reason` raw value when `outcome == .refused`.
    public let reason: String?

    public init(
        id: String = UUID().uuidString.lowercased(),
        timestamp: Int64 = Int64(Date().timeIntervalSince1970 * 1000),
        subject: TransactionLogSubject,
        verifier: String, credential: String, outcome: Outcome, reason: String? = nil
    ) {
        self.id = id
        self.timestamp = timestamp
        self.transactionId = subject.transactionId.map { Self.capped(Self.displaySafe($0), Self.maxFieldLength) }
        self.typeName = subject.typeName.map { Self.capped(Self.displaySafe($0), Self.maxFieldLength) }
        self.entities = Dictionary(uniqueKeysWithValues: subject.entities.prefix(8).map { ($0.key, Self.capped(Self.displaySafe($0.value), Self.maxFieldLength)) })
        self.verifier = Self.capped(Self.displaySafe(verifier), Self.maxFieldLength)
        self.credential = Self.capped(Self.displaySafe(credential), Self.maxFieldLength)
        self.outcome = outcome
        self.reason = reason
    }

    /// Text taken from a request (a custom type URI, a payee name, ...) with every control,
    /// newline, bidirectional or other format character replaced by U+FFFD. Applied when an entry
    /// is created; a UI should apply it again when it renders an entry read back from storage.
    public static func displaySafe(_ text: String) -> String { TextSafety.neutralized(text) }

    /// Each logged field is capped: the values come from the verifier and an
    /// unbounded one could flood the log. A cut value ends in a marker.
    public static let maxFieldLength = 200
    public static let truncationMarker = "[truncated]"

    static func capped(_ text: String, _ limit: Int) -> String {
        // By Unicode scalars: a run of combining marks is one character but many scalars.
        let scalars = text.unicodeScalars
        guard scalars.count > limit else { return text }
        let keep = limit - truncationMarker.unicodeScalars.count
        var cut = String.UnicodeScalarView()
        cut.append(contentsOf: scalars.prefix(keep))
        return String(cut) + truncationMarker
    }

    /// Builds the records for a request's raw entries. Decodes leniently: a
    /// refusal may be BECAUSE an entry is malformed, and it must still be
    /// logged, with whatever fields could be read.
    ///
    /// A consented or declined request gets one record per entry. A REFUSED
    /// request gets ONE record (for its first entry), whatever it carried: an
    /// unauthenticated sender must not be able to multiply records.
    /// - Parameter credentialLabel: the credential's display name for the entry's
    ///   first `credential_ids` element (so each record names the credential
    ///   its own transaction was bound to).
    public static func records(
        rawEntries: [String], verifier: String, credentialLabel: (_ queryId: String?) -> String, outcome: Outcome, reason: String? = nil
    ) -> [TransactionLogEntry] {
        var raws = rawEntries.isEmpty ? [""] : rawEntries
        if outcome == .refused { raws = [raws[0]] }
        return raws.map { raw in
            let fields = TransactionLogFields(raw: raw)
            return TransactionLogEntry(
                subject: TransactionLogSubject(transactionId: fields.transactionId, typeName: fields.typeName, entities: fields.entities),
                verifier: verifier, credential: credentialLabel(fields.firstCredentialId), outcome: outcome, reason: reason
            )
        }
    }
}

/// The section 5.3 fields read from a raw entry.
struct TransactionLogFields {
    static let maxRawBytes = 64 * 1024
    var transactionId: String?
    var typeName: String?
    var entities: [String: String] = [:]
    var firstCredentialId: String?

    init(raw: String) {
        // Same bound as the pipeline's: refusal logging must not decode what validation would not.
        guard raw.utf8.count <= TransactionLogFields.maxRawBytes,
              let bytes = TransactionDataHashing.base64UrlDecode(raw),
              let object = (try? StrictJSON.parse(bytes))?.objectValue else { return }
        let type = object["type"]?.stringValue
        firstCredentialId = object["credential_ids"]?.arrayValue?.first?.stringValue
        typeName = type.map { TransactionDataBuiltIns.displayName(forType: $0) }
        let payload = object["payload"]
        transactionId = payload?["transaction_id"]?.stringValue
        func name(_ path: [String]) -> String? {
            var node = payload
            for key in path { node = node?[key] }
            return node?.stringValue
        }
        switch type {
        case TransactionDataBuiltIns.paymentType:
            entities["payee"] = name(["payee", "name"])
            entities["pisp"] = name(["pisp", "legal_name"])
        case TransactionDataBuiltIns.loginRiskType:
            entities["service"] = name(["service"])
        case TransactionDataBuiltIns.accountAccessType:
            entities["aisp"] = name(["aisp", "legal_name"])
        case TransactionDataBuiltIns.emandateType:
            entities["payee"] = name(["payment_payload", "payee", "name"])
            entities["pisp"] = name(["payment_payload", "pisp", "legal_name"])
        default: break
        }
        entities = entities.compactMapValues { $0 }
    }
}

/// Why a log write did not reach durable storage.
public struct TransactionLogError: Error, Sendable, Equatable {
    public let detail: String
    public init(_ detail: String) { self.detail = detail }
}

/// Where transaction-log records are kept.
public protocol TransactionLogStore: Sendable {
    /// Throws when the records could not be made durable (they may still be
    /// held for the running session); the caller surfaces that.
    func append(_ entries: [TransactionLogEntry]) async throws
    /// Newest first.
    func entries() async -> [TransactionLogEntry]
}

/// A bounded in-memory log. Lost on restart: the wallet uses a persistent
/// store when its keystore offers one and falls back to this otherwise.
///
/// Refused attempts are kept apart from consented and declined ones, each with
/// its own capacity: refusals can be provoked by anyone who can send a request
/// and must not push the user's own history out.
public final class InMemoryTransactionLogStore: TransactionLogStore, @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [TransactionLogEntry] = []
    private let capacity: Int
    private let refusedCapacity: Int

    public init(capacity: Int = 500, refusedCapacity: Int = 100) {
        self.capacity = max(1, capacity)
        self.refusedCapacity = max(1, refusedCapacity)
    }

    public func append(_ entries: [TransactionLogEntry]) async throws {
        lock.lock(); defer { lock.unlock() }
        stored.insert(contentsOf: entries.reversed(), at: 0)
        stored = Self.bounded(stored, capacity: capacity, refusedCapacity: refusedCapacity)
    }

    public func entries() async -> [TransactionLogEntry] {
        lock.lock(); defer { lock.unlock() }
        return stored
    }

    /// Keeps the newest `capacity` user-driven records and the newest `refusedCapacity` refusals.
    public static func bounded(_ entries: [TransactionLogEntry], capacity: Int, refusedCapacity: Int) -> [TransactionLogEntry] {
        var kept = 0
        var refused = 0
        return entries.filter { entry in
            if entry.outcome == .refused { refused += 1; return refused <= refusedCapacity }
            kept += 1
            return kept <= capacity
        }
    }
}
