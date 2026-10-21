// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A container this build must not rewrite, because rewriting it could lose or
/// corrupt what a newer (or unknown) schema put there.
///
/// privatedata-spec section 6: "A reader MUST refuse to rewrite a container that
/// has a `schemaVersion` it does not implement, in `S` or in any event, or an
/// event type that its versions do not define. It MUST report this as an
/// unsupported version, not as a failed merge."
///
/// This is its own type, carried by `KeystoreError.unsupportedSchemaVersion`,
/// so a caller can tell "update the app" from "the sync failed, retry": the
/// first is permanent for this build, the second is not.
public struct UnsupportedSchemaVersion: Error, Sendable, Equatable {

    /// Which part of the container carries the thing this build cannot handle.
    public enum Subject: Sendable, Equatable {
        /// `S.schemaVersion`.
        case state
        /// `events[index].schemaVersion`.
        case event(index: Int)
        /// `events[index].type`, a type no implemented version defines.
        case eventType(index: Int, type: String)
    }

    public let subject: Subject
    /// What the container carries, as text (`"5"`, `"\"4\""`, an event type name).
    public let found: String
    /// The schema versions this build can rewrite.
    public let supported: ClosedRange<Int>

    public init(subject: Subject, found: String, supported: ClosedRange<Int> = WalletStateSchema.rewritableVersions) {
        self.subject = subject
        self.found = found
        self.supported = supported
    }
}

extension UnsupportedSchemaVersion: LocalizedError {
    public var errorDescription: String? {
        let range = "\(supported.lowerBound) to \(supported.upperBound)"
        switch subject {
        case .state:
            return "Unsupported wallet state schema version \(found); this build rewrites versions \(range). Update the app."
        case .event(let index):
            return "Unsupported schema version \(found) in event \(index); this build rewrites versions \(range). Update the app."
        case .eventType(let index, let type):
            return "Event \(index) has type \"\(type)\", which no schema version this build implements defines. Update the app."
        }
    }
}

/// The schema-version rules of privatedata-spec section 6, on plain JSON
/// (`JSONSerialization` output) so they hold and are tested on every platform,
/// not only where `JweKeystore` (CryptoKit) exists.
public enum WalletStateSchema {

    /// `S.schemaVersion` for newly written state, and `schemaVersion` of new events.
    public static let currentVersion = 4

    /// Versions a reader MUST read (spec section 6): 1 to 4.
    public static let readableVersions = 1...4

    /// Versions this build rewrites. Narrower than `readableVersions` on purpose:
    /// versions 1 and 2 store keypairs differently from version 3 (the change
    /// version 3 makes), and this SDK only understands the version 3 shape. It
    /// reads what it can of an older container, but rewriting it would drop
    /// keypairs it could not parse, so it refuses instead. Migrating 3 to 4
    /// only sets `schemaVersion` (spec section 6), which is why 3 and 4 are rewritable.
    public static let rewritableVersions = 3...4

    /// Event types that versions 1 to 3 define, as `wallet-frontend`
    /// (`WalletStateSchemaVersion1.ts`, `WalletStateSchemaVersion3.ts`) defines them.
    static let eventTypesFromVersion1: Set<String> = [
        "new_credential",
        "delete_credential",
        "new_keypair",
        "delete_keypair",
        "new_presentation",
        "delete_presentation",
        "alter_settings",
        "save_credential_issuance_session",
        "delete_credential_issuance_session",
    ]

    /// Event types that version 4 adds (spec section 6.1.3).
    static let eventTypesFromVersion4: Set<String> = ["set_extension"]

    /// Every event type some implemented version defines.
    public static let knownEventTypes: Set<String> = eventTypesFromVersion1.union(eventTypesFromVersion4)

    // MARK: - The refusal check

    /// The refusal for rewriting this decrypted `WalletStateContainer`, or nil
    /// when it may be rewritten.
    ///
    /// - `S.schemaVersion` is read the way `wallet-frontend` reads it: absent
    ///   means 1. It must be an integral JSON number inside `rewritableVersions`.
    /// - Every event must carry an integral `schemaVersion` inside
    ///   `rewritableVersions`, and its `type` must be one of the ten types the
    ///   implemented versions define.
    /// - An event with no integer `schemaVersion` is refused (spec section 6: every
    ///   event MUST carry one).
    ///
    /// A container without `S` is the legacy Kotlin-only layout, which has no
    /// schema version at all; it is accepted, as it always was.
    public static func rewriteRefusal(of container: [String: Any]) -> UnsupportedSchemaVersion? {
        // Only an ABSENT `S` is the legacy layout; a present `S` that is not an object
        // (`null`, an array) would otherwise be replaced by an empty one on export.
        if let rawS = container["S"], !(rawS is [String: Any]) {
            return UnsupportedSchemaVersion(subject: .state, found: describe(rawS))
        }
        if let s = container["S"] as? [String: Any] {
            if s["schemaVersion"] == nil {
                // Absent reads as version 1 (wallet-frontend), which this build does not rewrite.
                return UnsupportedSchemaVersion(subject: .state, found: "absent")
            }
            guard let version = integer(s["schemaVersion"]), rewritableVersions.contains(version) else {
                return UnsupportedSchemaVersion(subject: .state, found: describe(s["schemaVersion"]))
            }
        }

        guard let events = container["events"] else { return nil }
        guard let list = events as? [Any] else {
            return UnsupportedSchemaVersion(subject: .event(index: 0), found: "events is not an array")
        }
        for (index, element) in list.enumerated() {
            guard let event = element as? [String: Any] else {
                return UnsupportedSchemaVersion(subject: .event(index: index), found: "event is not an object")
            }
            // Every event MUST carry an integer schemaVersion (spec section 6); an
            // unversioned one cannot be attributed to an implemented version.
            let rawVersion = event["schemaVersion"]
            guard let version = integer(rawVersion), rewritableVersions.contains(version) else {
                return UnsupportedSchemaVersion(subject: .event(index: index), found: describe(rawVersion))
            }
            // `set_extension` stamped 3 is accepted (spec section 6: pre-3.0 containers have it); a writer never emits one.
            guard let type = event["type"] as? String, knownEventTypes.contains(type) else {
                return UnsupportedSchemaVersion(
                    subject: .eventType(index: index, type: (event["type"] as? String) ?? describe(event["type"])),
                    found: describe(event["type"])
                )
            }
        }
        return nil
    }

    /// Throwing form of `rewriteRefusal(of:)`.
    public static func requireRewritable(_ container: [String: Any]) throws {
        if let refusal = rewriteRefusal(of: container) {
            throw KeystoreError.unsupportedSchemaVersion(refusal)
        }
    }

    // MARK: - The writer rules

    /// `S.credentials[].metadata`, `S.extensions` and `set_extension` events are
    /// version 4 only: "A writer MUST NOT emit them in a version 3 container"
    /// (spec sections 6.0 and 6.1). Returns the offending member names; empty
    /// when `s` is consistent. `JweKeystore` always writes version 4, so this is
    /// the invariant it checks before encrypting rather than a branch it takes.
    public static func versionFourMembers(in container: [String: Any]) -> [String] {
        var found: [String] = []
        if let s = container["S"] as? [String: Any] {
            if s["extensions"] != nil { found.append("S.extensions") }
            if let credentials = s["credentials"] as? [Any],
               credentials.contains(where: { ($0 as? [String: Any])?["metadata"] != nil }) {
                found.append("S.credentials[].metadata")
            }
        }
        if let events = container["events"] as? [Any],
           events.contains(where: { ($0 as? [String: Any])?["type"] as? String == "set_extension" }) {
            found.append("set_extension")
        }
        return found
    }

    /// Throws when a container about to be written declares a version below 4 but
    /// carries a version 4 member.
    public static func requireWriterRules(_ container: [String: Any]) throws {
        let declared = integer((container["S"] as? [String: Any])?["schemaVersion"]) ?? 0
        let offending = versionFourMembers(in: container)
        if declared < currentVersion, !offending.isEmpty {
            throw KeystoreError.invalidContainer(
                "refusing to write \(offending.joined(separator: ", ")) in a version \(declared) container"
            )
        }
    }

    // MARK: - Credential entries

    /// `metadata` as a writer may emit it: `nil` for absent, `null` or an empty
    /// array (spec section 6.0: a writer MUST NOT emit null or an empty array);
    /// anything else is returned untouched, including a value this build cannot
    /// read, because preservation applies to the JSON value.
    public static func writableMetadata(_ value: Any?) -> Any? {
        guard let value, !(value is NSNull) else { return nil }
        if let array = value as? [Any], array.isEmpty { return nil }
        return value
    }

    // MARK: - JSON helpers

    /// An integral JSON number, or nil for anything else (a string, a boolean,
    /// a fraction, a value outside `Int`).
    static func integer(_ value: Any?) -> Int? {
        guard let number = value as? NSNumber, !ContainerJSON.isBoolean(number) else { return nil }
        let double = number.doubleValue
        guard double == double.rounded(), abs(double) < 9_007_199_254_740_992 else { return nil }
        return number.intValue
    }

    private static func describe(_ value: Any?) -> String {
        switch value {
        case nil: return "absent"
        case let string as String: return "\"\(string)\""
        case let number as NSNumber where ContainerJSON.isBoolean(number): return number.boolValue ? "true" : "false"
        case let number as NSNumber: return "\(number)"
        case is NSNull: return "null"
        case is [Any]: return "an array"
        case is [String: Any]: return "an object"
        default: return "\(value!)"
        }
    }
}

/// `NSNumber` out of `JSONSerialization` cannot tell a boolean from a number by
/// type alone; `true` must not read as schema version 1.
enum ContainerJSON {
    static func isBoolean(_ number: NSNumber) -> Bool {
        #if canImport(Darwin)
        return CFGetTypeID(number) == CFBooleanGetTypeID()
        #else
        return String(cString: number.objCType) == "c"
        #endif
    }
}
