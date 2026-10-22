// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

/// How `S.credentials[]` and `S.keypairs[]` are rebuilt on export.
///
/// Both lists are driven by the keystore's in-memory state (that is the source
/// of truth once unlocked), but each entry starts from the entry the loaded
/// container carried, so that everything this build does not own is written back
/// with an identical value (privatedata-spec section 6: "unknown members and
/// metadata MUST be preserved"), and the array order is the loaded container's,
/// with new entries appended. Taking these as plain arguments, rather than as
/// `JweKeystore` members, keeps them free of the keystore's lock and testable
/// without one.
enum WalletStateEntries {

    // MARK: - Credentials

    static func credentialEntries(credentials: [Int64: String], existingS: [String: Any]?) -> [[String: Any]] {
        var originals: [Int64: [String: Any]] = [:]
        for case let entry as [String: Any] in (existingS?["credentials"] as? [Any]) ?? [] {
            if let id = int64(entry["credentialId"]) { originals[id] = entry }
        }
        let order = positions(of: existingS?["credentials"]) { int64($0["credentialId"]) }
        return credentials.keys.sorted { inOrder($0, $1, order) }.compactMap { id in
            credentials[id].map { credentialEntry(id: id, data: $0, original: originals[id]) }
        }
    }

    /// One entry. The eight members of section 6.0 come from the original entry
    /// when there is one, else from the credential's own saved JSON (a credential
    /// added THIS session has no entry in the loaded container yet; without that
    /// fallback its batchId/instanceId would reset to 0 on every export until the
    /// container is reloaded once). Every other member is the original's, as is.
    private static func credentialEntry(id: Int64, data: String, original: [String: Any]?) -> [String: Any] {
        let parsed = (try? JSONSerialization.jsonObject(with: Data(data.utf8))) as? [String: Any]
        var entry: [String: Any] = original ?? [:]
        entry["credentialId"] = id
        entry["format"] = (original?["format"] as? String) ?? (parsed?["format"] as? String) ?? ""
        entry["data"] = (original?["data"] as? String) ?? (parsed?["raw"] as? String) ?? data
        entry["kid"] = (original?["kid"] as? String) ?? (parsed?["kid"] as? String) ?? ""
        entry["instanceId"] = int(original?["instanceId"]) ?? int(parsed?["instance_id"]) ?? 0
        entry["batchId"] = int64(original?["batchId"]) ?? int64(parsed?["batch_id"]) ?? 0
        entry["credentialIssuerIdentifier"] = (original?["credentialIssuerIdentifier"] as? String)
            ?? (parsed?["credential_issuer_identifier"] as? String) ?? ""
        entry["credentialConfigurationId"] = (original?["credentialConfigurationId"] as? String)
            ?? (parsed?["credential_configuration_id"] as? String) ?? ""
        // `metadata: null` and `metadata: []` read as "no metadata", and a writer MUST NOT emit either.
        entry["metadata"] = WalletStateSchema.writableMetadata(entry["metadata"])
        return entry
    }

    // MARK: - Presentations

    /// `S.presentations[]`, driven by the in-memory records (a record removed from
    /// memory is removed). A presentation the container already had is written
    /// back as it was, in place: rebuilding it from the record would blank `data`
    /// and replace a distinct `transactionId`, which a version 3 to 4 migration
    /// must not change. An entry this build cannot read is carried verbatim. A
    /// record recorded THIS session has no VP and no transaction of its own, so it
    /// is written as its own single-VP transaction (`transactionId` = id, `data`
    /// = ""), a known, deliberate gap (see `PresentationRecord`).
    static func presentationEntries(records: [Int64: String], modified: Set<Int64> = [], existingS: [String: Any]?) -> [Any] {
        var entries: [Any] = []
        var seen = Set<Int64>()
        for element in (existingS?["presentations"] as? [Any]) ?? [] {
            guard let entry = element as? [String: Any], let id = int64(entry["presentationId"]) else {
                entries.append(element)
                continue
            }
            guard records[id] != nil, seen.insert(id).inserted else { continue }
            // Saved again this session: the record's current fields replace the entry's,
            // and what the record cannot express (`data`, `transactionId`, unknown members) stays.
            entries.append(modified.contains(id) ? presentationEntry(id: id, record: records[id], original: entry) : entry)
        }
        for id in records.keys.sorted() where !seen.contains(id) {
            entries.append(presentationEntry(id: id, record: records[id], original: nil))
        }
        return entries
    }

    private static func presentationEntry(id: Int64, record: String?, original: [String: Any]?) -> [String: Any] {
        let parsed = record.flatMap { try? JSONSerialization.jsonObject(with: Data($0.utf8)) } as? [String: Any]
        var entry = original ?? ["transactionId": id, "data": ""]
        entry["presentationId"] = id
        entry["usedCredentialIds"] = (parsed?["credential_ids"] as? [Any])?.compactMap { int64($0) } ?? []
        entry["presentationTimestampSeconds"] = (int64(parsed?["timestamp"]) ?? 0) / 1000
        entry["audience"] = (parsed?["verifier_name"] as? String) ?? ""
        return entry
    }

    // MARK: - Keypairs

    #if canImport(CryptoKit)
    static func keypairEntries(
        keys: [String: P256.Signing.PrivateKey],
        keyDids: [String: String],
        existingS: [String: Any]?
    ) -> [Any] {
        // Elements, not objects: an entry that is not an object (or not parseable) is
        // preserved verbatim too (spec section 6).
        let existing: [Any] = (existingS?["keypairs"] as? [Any]) ?? []
        func kid(_ entry: [String: Any]) -> String? { (entry["keypair"] as? [String: Any])?["kid"] as? String }
        // Existing entries stay where they were, rebuilt when this build loaded the
        // key and carried verbatim when it could not (not a P-256 JWK, say; nothing
        // removes keys, so such an entry is not dropped). Keys new this session
        // follow, by kid.
        var seen = Set<String>()
        var entries: [Any] = existing.map { element in
            guard let entry = element as? [String: Any], let k = kid(entry), let key = keys[k] else { return element }
            seen.insert(k)
            return keypairEntry(kid: k, key: key, did: keyDids[k], original: entry)
        }
        for k in keys.keys.sorted() where !seen.contains(k) {
            if let key = keys[k] { entries.append(keypairEntry(kid: k, key: key, did: keyDids[k], original: nil)) }
        }
        return entries
    }

    private static func keypairEntry(
        kid: String, key: P256.Signing.PrivateKey, did: String?, original: [String: Any]?
    ) -> [String: Any] {
        let x963 = key.publicKey.x963Representation
        let x = EncryptedContainer.base64UrlEncode(Data(x963[1..<33]))
        let y = EncryptedContainer.base64UrlEncode(Data(x963[33..<65]))
        let originalKeypair = original?["keypair"] as? [String: Any]
        // A key generated this session knows its own DID; otherwise preserve
        // whatever the loaded container recorded. Never recomputed, so a wallet
        // reconfigured to a different `didKeyVersion` cannot re-identify a key.
        var keypair = originalKeypair ?? [:]
        keypair["kid"] = kid
        keypair["did"] = did ?? originalKeypair?["did"] as? String ?? ""
        keypair["alg"] = "ES256"
        // Each JWK starts from the original, so members this build does not know
        // (`key_ops`, `use`, peer-defined ones) survive; only the key material is set.
        var publicJwk = originalKeypair?["publicKey"] as? [String: Any] ?? [:]
        publicJwk["kty"] = "EC"; publicJwk["crv"] = "P-256"; publicJwk["x"] = x; publicJwk["y"] = y
        var privateJwk = originalKeypair?["privateKey"] as? [String: Any] ?? [:]
        privateJwk["kty"] = "EC"; privateJwk["crv"] = "P-256"; privateJwk["x"] = x; privateJwk["y"] = y
        privateJwk["d"] = EncryptedContainer.base64UrlEncode(key.rawRepresentation)
        keypair["publicKey"] = publicJwk
        keypair["privateKey"] = privateJwk
        var entry = original ?? [:]
        entry["kid"] = kid
        entry["keypair"] = keypair
        return entry
    }
    #endif

    // MARK: - Order and number coercion

    /// Position of each keyed element of a JSON array, first occurrence winning.
    private static func positions<Key: Hashable>(of array: Any?, key: ([String: Any]) -> Key?) -> [Key: Int] {
        var result: [Key: Int] = [:]
        for (index, element) in ((array as? [Any]) ?? []).enumerated() {
            if let object = element as? [String: Any], let k = key(object), result[k] == nil { result[k] = index }
        }
        return result
    }

    /// Entries the container already had come first, in its order; new ones follow, by key.
    private static func inOrder<Key: Comparable & Hashable>(_ lhs: Key, _ rhs: Key, _ order: [Key: Int]) -> Bool {
        switch (order[lhs], order[rhs]) {
        case let (l?, r?): return l < r
        case (.some, nil): return true
        case (nil, .some): return false
        case (nil, nil): return lhs < rhs
        }
    }

    /// A JSON number, or a number-as-string (a not-yet-migrated container may
    /// still quote a privatedata-spec `number` field).
    private static func int64(_ value: Any?) -> Int64? {
        if let n = value as? NSNumber { return n.int64Value }
        if let s = value as? String { return Int64(s) }
        return nil
    }

    private static func int(_ value: Any?) -> Int? { int64(value).flatMap { Int(exactly: $0) } }
}
