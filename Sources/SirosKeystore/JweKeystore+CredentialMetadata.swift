// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

#if canImport(CryptoKit)

extension JweKeystore {

    /// The `{type, value}` metadata entries of one credential (privatedata-spec `S.credentials[].metadata`,
    /// version 4), or nil when there are none or what is stored is not that shape. The result is a deep
    /// copy: the caller can neither alter the keystore's state through it nor see it change.
    public func credentialMetadata(id: Int64) async -> [[String: Any]]? {
        mutex.lock()
        defer { mutex.unlock() }
        guard let raw = credentialMetadata[id] as? [Any], !raw.isEmpty else { return nil }
        var entries: [[String: Any]] = []
        for element in raw {
            guard let entry = element as? [String: Any],
                  let type = entry["type"] as? String, !type.isEmpty,
                  entry["value"] != nil else { return nil }
            entries.append(entry)
        }
        return Self.jsonCopy(entries) as? [[String: Any]]
    }

    /// Replace (or, with nil or empty, remove) one credential's metadata. It is stored exactly as given, as an
    /// independent copy, so a later change to the caller's objects cannot alter what is written to the container.
    /// - Throws: `KeystoreError.locked`, `.unsupportedSchemaVersion` for a container this build must not
    ///   rewrite, and `.invalidParameter` for an unknown credential or a malformed entry.
    public func setCredentialMetadata(id: Int64, _ entries: [[String: Any]]?) async throws {
        mutex.lock()
        defer { mutex.unlock() }
        try requireUnlocked()
        try requireRewritable()
        guard credentials[id] != nil else {
            throw KeystoreError.invalidParameter("no credential \(id)")
        }
        guard let entries, !entries.isEmpty else {
            credentialMetadata.removeValue(forKey: id)
            return
        }
        for entry in entries {
            guard let type = entry["type"] as? String, !type.isEmpty, entry["value"] != nil else {
                throw KeystoreError.invalidParameter("metadata entries need a non-empty string `type` and a `value`")
            }
        }
        guard JSONSerialization.isValidJSONObject(entries), let copy = Self.jsonCopy(entries) else {
            throw KeystoreError.invalidParameter("metadata is not valid JSON")
        }
        credentialMetadata[id] = copy
    }

    /// An independent copy of a JSON value: no shared (possibly mutable) Foundation objects.
    static func jsonCopy(_ value: Any) -> Any? {
        guard JSONSerialization.isValidJSONObject(value),
              let data = try? JSONSerialization.data(withJSONObject: value) else { return nil }
        return try? JSONSerialization.jsonObject(with: data)
    }
}

#endif
