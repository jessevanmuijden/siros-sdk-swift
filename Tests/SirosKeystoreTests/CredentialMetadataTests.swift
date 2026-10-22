// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
import SirosCredentials
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

/// `S.credentials[].metadata` (privatedata-spec, optional core member):
/// `[{"type": <non-empty string>, "value": <any JSON>}]`, kept exactly as
/// received, plus the rule that a rewriting client preserves per-credential
/// and top-level members it does not know.
///
/// Besides local fixtures, the spec's own vectors (verbatim `vectors.jsonl`,
/// SPEC 2.6) are run through the keystore.
final class CredentialMetadataTests: XCTestCase {

    private let prf = Data(0..<32)
    private let salt = Data((0..<32).map { UInt8($0 + 0x10) })
    private let info = Data("SIROS Wallet PRF".utf8)
    private let seedHex = "00112233445566778899aabbccddeeff"

    /// The storage form of a delivered seed (privatedata-spec 2.5 section
    /// 5A.2): one entry per response-level `credential_metadata` member,
    /// `type` the member name and `value` the member's OBJECT verbatim
    /// (namespace -> 32 lowercase hex), not a string.
    private func seedEntry() -> [String: Any] {
        ["type": "org.siros.secret_seed", "value": ["org.siros.nym_auth": seedHex] as [String: Any]]
    }

    // The vendored privatedata-spec vectors are pinned by digest in PrivateDataSchemaVectorTests.

    private func specVector(_ id: String) throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "vectors", withExtension: "jsonl", subdirectory: "privatedata-spec"))
        for line in try String(contentsOf: url, encoding: .utf8).split(separator: "\n") {
            guard let obj = try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  obj["id"] as? String == id else { continue }
            return obj
        }
        XCTFail("vector \(id) not in the vendored vectors.jsonl")
        throw KeystoreError.invalidContainer("vector not found")
    }

    private func credEntry(_ id: Int, extra: [String: Any] = [:]) -> [String: Any] {
        var e: [String: Any] = [
            "credentialId": id, "format": "dc+sd-jwt", "data": "raw-\(id)", "kid": "kid-\(id)",
            "instanceId": 0, "batchId": id, "credentialIssuerIdentifier": "https://iss.example",
            "credentialConfigurationId": "cfg",
        ]
        e.merge(extra) { _, new in new }
        return e
    }

    private func container(credentials: [[String: Any]], extraS: [String: Any] = [:]) throws -> Data {
        var s: [String: Any] = [
            "schemaVersion": 3, "keypairs": [] as [Any], "credentials": credentials,
            "presentations": [] as [Any], "settings": ["openidRefreshTokenMaxAgeInSeconds": "0"],
            "credentialIssuanceSessions": [] as [Any],
        ]
        s.merge(extraS) { _, new in new }
        return try ContainerTestSupport.buildContainer(
            prfOutput: prf, hkdfSalt: salt, hkdfInfo: info,
            plaintextState: ["lastEventHash": "", "events": [] as [Any], "S": s]
        )
    }

    private func reopen(_ c: Data) async throws -> JweKeystore {
        let k = JweKeystore()
        try await k.unlock(prfOutput: prf, encryptedContainer: c, hkdfSalt: salt, hkdfInfo: info)
        return k
    }

    private func creds(of k: JweKeystore) async throws -> [[String: Any]] {
        let state = try ContainerTestSupport.plaintext(
            of: try await k.exportEncryptedContainer(), prfOutput: prf, hkdfSalt: salt)
        return ((state["S"] as? [String: Any])?["credentials"] as? [[String: Any]]) ?? []
    }

    private func entry(_ id: Int, in list: [[String: Any]]) -> [String: Any]? {
        list.first { ($0["credentialId"] as? Int) == id }
    }

    private func fresh() async throws -> JweKeystore {
        let k = JweKeystore()
        try await k.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: salt, hkdfInfo: info)
        return k
    }

    // MARK: -

    func testSetMetadataSurvivesExportAndReimport() async throws {
        let k = try await fresh()
        try await k.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}")
        let entries: [[String: Any]] = [
            seedEntry(),
            ["type": "org.example.tok", "value": ["n": 9007199254740993, "f": 1.5, "b": true, "z": NSNull(), "l": [1, "x"]] as [String: Any]],
        ]
        try await k.setCredentialMetadata(id: 1, entries)

        let exported = try await creds(of: k)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(entries, entry(1, in: exported)?["metadata"]))

        let reopened = try await reopen(try await k.exportEncryptedContainer())
        let back = await reopened.credentialMetadata(id: 1)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(entries, back))
        XCTAssertEqual(((back?[0]["value"] as? [String: Any])?["org.siros.nym_auth"] as? String), seedHex)
        let big = ((back?[1]["value"] as? [String: Any])?["n"] as? NSNumber)?.int64Value
        XCTAssertEqual(big, 9007199254740993, "integers beyond 2^53 must stay exact")
    }

    /// The spec's own round-trip vectors (SPEC 2.6 entry shape), run whole:
    /// decrypt `inputs.plaintextState`, re-export, and the written `S` must equal
    /// `expected.roundTripState.S` (metadata kept in order with duplicates, no
    /// `metadata: []` or null written, unknown members kept).
    func testSpecRoundTripVectors() async throws {
        let ids = ["credential-metadata-001", "credential-metadata-absent-001", "credential-metadata-empty-array-001",
                   "credential-unknown-member-001", "container-unknown-top-level-member-001"]
        for id in ids {
            let v = try specVector(id)
            let inputs = try XCTUnwrap(v["inputs"] as? [String: Any], id)
            let vPrf = EncryptedContainer.base64UrlDecode(try XCTUnwrap(inputs["prfOutput"] as? String))
            let vSalt = EncryptedContainer.base64UrlDecode(try XCTUnwrap(inputs["hkdfSalt"] as? String))
            let vInfo = Data(try XCTUnwrap(inputs["hkdfInfo"] as? String).utf8)
            let state = try XCTUnwrap(inputs["plaintextState"] as? [String: Any], id)
            let c = try ContainerTestSupport.buildContainer(prfOutput: vPrf, hkdfSalt: vSalt, hkdfInfo: vInfo, plaintextState: state)
            let k = JweKeystore()
            try await k.unlock(prfOutput: vPrf, encryptedContainer: c, hkdfSalt: vSalt, hkdfInfo: vInfo)
            let out = try ContainerTestSupport.plaintext(
                of: try await k.exportEncryptedContainer(), prfOutput: vPrf, hkdfSalt: vSalt)
            let expected = try XCTUnwrap(
                ((v["expected"] as? [String: Any])?["roundTripState"] as? [String: Any])?["S"] as? [String: Any], id)
            let written = try XCTUnwrap(out["S"] as? [String: Any], id)
            // Only the members the vector speaks about: the keystore adds its own
            // bookkeeping (e.g. keypairs) that these vectors do not model.
            for key in expected.keys {
                XCTAssertTrue(ContainerTestSupport.jsonEqual(expected[key], written[key]), "\(id): S.\(key)")
            }
        }
    }

    func testSpecDeliveredSecretStorageFormIsAccepted() async throws {
        let v = try specVector("delivered-secret-commitment-001")
        let after = try XCTUnwrap((v["expected"] as? [String: Any])?["credentialAfterAccept"] as? [String: Any])
        let metadata = try XCTUnwrap(after["metadata"] as? [[String: Any]])
        XCTAssertEqual(metadata.count, 1)
        XCTAssertTrue(metadata[0]["value"] is [String: Any], "the seed value is an object, not a string")
        let k = try await fresh()
        try await k.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}")
        try await k.setCredentialMetadata(id: 1, metadata)
        let out = try await creds(of: try await reopen(try await k.exportEncryptedContainer()))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(metadata, entry(1, in: out)?["metadata"]))
    }

    /// Members of a metadata entry other than `type`/`value` are preserved too
    /// (spec section 6: "likewise every member of a `metadata` entry").
    func testUnknownMembersOfAMetadataEntrySurvive() async throws {
        let entryWithExtra: [String: Any] = ["type": "t", "value": "v", "x-future": ["a": [1, 2]] as [String: Any]]
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [entryWithExtra]])]))
        let got = await k.credentialMetadata(id: 1)
        XCTAssertTrue(ContainerTestSupport.jsonEqual([entryWithExtra], got))
        let out = try await creds(of: try await reopen(try await k.exportEncryptedContainer()))
        XCTAssertTrue(ContainerTestSupport.jsonEqual([entryWithExtra], entry(1, in: out)?["metadata"]))
    }

    func testUnknownPerCredentialMemberSurvivesAndOwnedFieldsStillWin() async throws {
        let future: [String: Any] = ["a": [1, 2], "b": ["c": false]]
        let c = try container(credentials: [credEntry(1, extra: ["futureMember": future, "format": "dc+sd-jwt"])],
                              extraS: ["unknownTop": ["x": 1]])
        let k = try await reopen(c)
        let once = try await creds(of: k)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(future, entry(1, in: once)?["futureMember"]))
        // Second hop through a fresh client.
        let twice = try await creds(of: try await reopen(try await k.exportEncryptedContainer()))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(future, entry(1, in: twice)?["futureMember"]))
        XCTAssertNil(entry(1, in: twice)?["metadata"], "absent metadata must be omitted, not null or []")
    }

    func testMetadataSurvivesAddingDeletingAndPresentationRecord() async throws {
        let c = try container(credentials: [
            credEntry(1, extra: ["metadata": [seedEntry()]]),
            credEntry(2, extra: ["metadata": [["type": "t", "value": "other"]]]),
        ])
        let k = try await reopen(c)
        try await k.saveCredential(id: 3, json: "{\"id\":3,\"format\":\"dc+sd-jwt\",\"raw\":\"r3\",\"batch_id\":3,\"instance_id\":0}")
        try await k.deleteCredential(id: 2)
        try await k.savePresentationRecord(id: 5, json: "{\"credential_ids\":[1],\"timestamp\":1000,\"verifier_name\":\"v\"}")

        let out = try await creds(of: try await reopen(try await k.exportEncryptedContainer()))
        XCTAssertTrue(ContainerTestSupport.jsonEqual([seedEntry()], entry(1, in: out)?["metadata"]))
        XCTAssertNil(entry(2, in: out), "deleted credential must be gone")
        XCTAssertNil(entry(3, in: out)?["metadata"])
    }

    func testDeletedCredentialsMetadataIsGoneEvenWhenSameIdReturns() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        try await k.deleteCredential(id: 1)
        try await k.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}")
        let out = try await creds(of: k)
        XCTAssertNil(entry(1, in: out)?["metadata"])
        let none = await k.credentialMetadata(id: 1)
        XCTAssertNil(none)
    }

    func testClearCredentialsDropsMetadata() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        try await k.clearCredentials()
        try await k.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}")
        let none = await k.credentialMetadata(id: 1)
        XCTAssertNil(none)
        let after = try await creds(of: k)
        XCTAssertNil(entry(1, in: after)?["metadata"])
    }

    /// Review: unlocking the same instance with a newer container must not keep metadata the
    /// newer container no longer has (a removed secret seed would otherwise come back on export).
    func testReunlockingTheSameInstanceDropsMetadataTheNewContainerOmits() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        let before = await k.credentialMetadata(id: 1)
        XCTAssertNotNil(before)
        try await k.unlock(prfOutput: prf, encryptedContainer: try container(credentials: [credEntry(1)]), hkdfSalt: salt, hkdfInfo: info)
        let after = await k.credentialMetadata(id: 1)
        XCTAssertNil(after, "stale metadata must be cleared on reload")
        let exported = try await creds(of: k)
        XCTAssertNil(entry(1, in: exported)?["metadata"], "and must not be restored by export")
        // An absent credentials array clears it too.
        let k2 = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        try await k2.unlock(prfOutput: prf, encryptedContainer: try container(credentials: []), hkdfSalt: salt, hkdfInfo: info)
        let gone = await k2.credentialMetadata(id: 1)
        XCTAssertNil(gone)
    }

    /// Review: a deleted credential's unknown members must not attach to a later credential
    /// that reuses its id.
    func testDeletedOrClearedCredentialsUnknownMembersDoNotReattach() async throws {
        let json = "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}"
        for clear in [false, true] {
            let k = try await reopen(try container(credentials: [credEntry(1, extra: ["futureMember": ["a": 1]])]))
            if clear { try await k.clearCredentials() } else { try await k.deleteCredential(id: 1) }
            try await k.saveCredential(id: 1, json: json)
            let out = try await creds(of: k)
            XCTAssertNil(entry(1, in: out)?["futureMember"], clear ? "clearCredentials" : "deleteCredential")
        }
        // Unrelated credentials keep theirs.
        let k = try await reopen(try container(credentials: [
            credEntry(1, extra: ["futureMember": 1]), credEntry(2, extra: ["futureMember": 2]),
        ]))
        try await k.deleteCredential(id: 1)
        let out = try await creds(of: k)
        XCTAssertEqual(entry(2, in: out)?["futureMember"] as? Int, 2)
    }

    func testLockClearsMetadata() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        k.lock()
        let none = await k.credentialMetadata(id: 1)
        XCTAssertNil(none)
    }

    /// Regression: `StoredCredential.metadata` is DISPLAY metadata (an
    /// object). The container's `metadata` array must never reach the JSON
    /// the credential store decodes, or the credential silently vanishes.
    func testCredentialWithBothKindsOfMetadataStaysDecodable() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        let json = try await k.getCredential(id: 1)
        let stored = try JSONDecoder().decode(StoredCredential.self, from: Data(XCTUnwrap(json).utf8))
        XCTAssertEqual(stored.id, 1)
        XCTAssertNil(stored.metadata, "container metadata must not leak into display metadata")
        let meta = await k.credentialMetadata(id: 1)
        XCTAssertEqual(meta?.count, 1)
    }

    func testMalformedMetadataIsPreservedVerbatimAndNotInterpreted() async throws {
        for malformed in [["oops": 1] as [String: Any], "str", 7] as [Any] {
            let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": malformed])]))
            let json = try await k.getCredential(id: 1)
            XCTAssertNotNil(try? JSONDecoder().decode(StoredCredential.self, from: Data(XCTUnwrap(json).utf8)))
            let none = await k.credentialMetadata(id: 1)
            XCTAssertNil(none)
            let written = try await creds(of: k)
            XCTAssertTrue(ContainerTestSupport.jsonEqual(malformed, entry(1, in: written)?["metadata"]),
                          "malformed \(malformed) must be written back verbatim")
        }
    }

    /// `metadata: null` reads as no metadata and a writer MUST NOT emit it (spec section 6.0).
    func testNullMetadataIsNotWrittenBack() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": NSNull()])]))
        let written = try await creds(of: k)
        XCTAssertNil(entry(1, in: written)?["metadata"])
    }

    /// Metadata is a version 4 member: a version 3 container that gets some is written as version 4.
    func testWritingMetadataIntoAVersionThreeContainerWritesVersionFour() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1)]))
        try await k.setCredentialMetadata(id: 1, [seedEntry()])
        let state = try ContainerTestSupport.plaintext(of: try await k.exportEncryptedContainer(), prfOutput: prf, hkdfSalt: salt)
        let s = try XCTUnwrap(state["S"] as? [String: Any])
        XCTAssertEqual(s["schemaVersion"] as? Int, 4)
        XCTAssertNotNil(entry(1, in: (s["credentials"] as? [[String: Any]]) ?? [])?["metadata"])
    }

    func testAContainerThisBuildMustNotRewriteRefusesMetadataChanges() async throws {
        var s: [String: Any] = [
            "schemaVersion": 5, "keypairs": [] as [Any], "credentials": [credEntry(1)],
            "presentations": [] as [Any], "settings": ["openidRefreshTokenMaxAgeInSeconds": "0"],
            "credentialIssuanceSessions": [] as [Any],
        ]
        s["futureMember"] = 1
        let container = try ContainerTestSupport.buildContainer(
            prfOutput: prf, hkdfSalt: salt, hkdfInfo: info, plaintextState: ["lastEventHash": "", "events": [] as [Any], "S": s]
        )
        let k = try await reopen(container)
        do {
            try await k.setCredentialMetadata(id: 1, [seedEntry()])
            XCTFail("a container of a newer schema is not rewritten")
        } catch KeystoreError.unsupportedSchemaVersion { /* expected */ }
    }

    /// Review: what is stored is an independent copy. Mutating the caller's objects afterwards changes
    /// nothing, and neither does mutating what an accessor returned.
    func testMetadataIsSnapshottedNotShared() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1)]))
        let value = NSMutableDictionary(dictionary: ["org.siros.nym_auth": seedHex])
        let entry: [String: Any] = ["type": "org.siros.secret_seed", "value": value]
        try await k.setCredentialMetadata(id: 1, [entry])
        value["org.siros.nym_auth"] = "tampered-after-set"
        value["extra"] = "added-after-set"
        let readOpt = await k.credentialMetadata(id: 1)
        let read = try XCTUnwrap(readOpt)
        XCTAssertEqual((read[0]["value"] as? [String: Any])?["org.siros.nym_auth"] as? String, seedHex)
        XCTAssertNil((read[0]["value"] as? [String: Any])?["extra"])
        let written = try await creds(of: k)
        XCTAssertEqual(((entry1(written)?["value"]) as? [String: Any])?["org.siros.nym_auth"] as? String, seedHex)
        // The accessor returns a copy too.
        if let again = await k.credentialMetadata(id: 1), let mutable = again[0]["value"] as? NSMutableDictionary {
            mutable["org.siros.nym_auth"] = "tampered-after-get"
        }
        let afterOpt = await k.credentialMetadata(id: 1)
        let after = try XCTUnwrap(afterOpt)
        XCTAssertEqual((after[0]["value"] as? [String: Any])?["org.siros.nym_auth"] as? String, seedHex)
    }

    private func entry1(_ written: [[String: Any]]) -> [String: Any]? {
        ((entry(1, in: written)?["metadata"]) as? [[String: Any]])?.first
    }

    /// Review: EVERY successful replacement of the container clears the metadata, including a legacy
    /// container (no `S`) and a first-time empty one, not only a current one.
    func testEveryKindOfContainerReplacementClearsMetadata() async throws {
        let withMetadata = try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])])
        let legacy = try ContainerTestSupport.buildContainer(
            prfOutput: prf, hkdfSalt: salt, hkdfInfo: info, plaintextState: ["keys": [] as [Any]]
        )
        for (name, next) in [("legacy", legacy), ("first-time", Data()), ("without credentials", try container(credentials: []))] {
            let k = try await reopen(withMetadata)
            let before = await k.credentialMetadata(id: 1)
            XCTAssertNotNil(before, name)
            try await k.unlock(prfOutput: prf, encryptedContainer: next, hkdfSalt: salt, hkdfInfo: info)
            let after = await k.credentialMetadata(id: 1)
            XCTAssertNil(after, "\(name): a replaced container carries nothing over")
            try await k.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\"}")
            let written = try await creds(of: k)
            XCTAssertNil(entry(1, in: written)?["metadata"], "\(name): and nothing is written back")
        }
    }

    func testSettingNilOrEmptyOmitsMemberAndInvalidEntriesAreRejected() async throws {
        let k = try await reopen(try container(credentials: [credEntry(1, extra: ["metadata": [seedEntry()]])]))
        try await k.setCredentialMetadata(id: 1, [])
        let afterEmpty = try await creds(of: k)
        XCTAssertNil(entry(1, in: afterEmpty)?["metadata"])
        try await k.setCredentialMetadata(id: 1, [seedEntry()])
        try await k.setCredentialMetadata(id: 1, nil)
        let afterNil = try await creds(of: k)
        XCTAssertNil(entry(1, in: afterNil)?["metadata"])

        do { try await k.setCredentialMetadata(id: 1, [["type": "", "value": "v"]]); XCTFail("empty type") } catch {}
        do { try await k.setCredentialMetadata(id: 1, [["type": "t"]]); XCTFail("missing value") } catch {}
        do { try await k.setCredentialMetadata(id: 99, [seedEntry()]); XCTFail("no such credential") } catch {}
    }

    func testAdapterForwardsMetadataAccessors() async throws {
        let adapter = WscdKeystoreAdapter(signer: NoopSigner())
        try await adapter.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: salt, hkdfInfo: info)
        try await adapter.saveCredential(id: 1, json: "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"r\",\"batch_id\":1,\"instance_id\":0}")
        try await adapter.setCredentialMetadata(id: 1, [seedEntry()])
        let got = await adapter.credentialMetadata(id: 1)
        XCTAssertTrue(ContainerTestSupport.jsonEqual([seedEntry()], got))
    }
}

private final class NoopSigner: Signer, @unchecked Sendable {
    func generateKey(algorithm: String) async throws -> String { "k" }
    func sign(keyId: String, data: Data) async throws -> Data { Data(count: 64) }
    func listKeys() async throws -> [SignerKeyInfo] { [] }
    func deleteKey(keyId: String) async throws {}
    func attestationChain(keyId: String) async throws -> AttestationChain? { nil }
    func exportPublicKey(keyId: String) async throws -> Data { Data() }
    func migrateKey(keyId: String, targetPlugin: String) async throws -> MigrationResult { .migrated(newKeyId: keyId) }
    func securityProperties(keyId: String) async throws -> SignerSecurityProperties {
        SignerSecurityProperties(keyStorage: ["software"], userAuthentication: [])
    }
}

#else
final class CredentialMetadataTests: XCTestCase {
    func testCryptoKitUnavailable() { XCTAssertTrue(true) }
}
#endif
