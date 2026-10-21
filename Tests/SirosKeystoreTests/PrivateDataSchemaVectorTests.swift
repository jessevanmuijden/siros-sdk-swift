// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)
import CryptoKit

/// privatedata-spec 3.0 (`S.schemaVersion` 4) at the keystore: the spec's vendored
/// vectors, and the rules the vectors do not exercise (refusal, migration,
/// writer rules, preservation).
final class PrivateDataSchemaVectorTests: XCTestCase {

    /// SHA-256 of the vendored files. Re-vendoring changes them; see
    /// `Resources/privatedata-spec/vectors.PROVENANCE.txt`.
    private static let vectorsSha256 = "9505e976b4fd44b9ce645cec952506ccfcd823627f99c50c9023125c90519021"
    private static let sumsSha256 = "22c55ef0a0f4eb132d4bdb7a1d7fabf36ac18137725ea7e08f2ae2fe518978db"

    private let prf = Data(repeating: 0x42, count: 32)
    private let salt = Data(repeating: 0x07, count: 32)
    private let info = Data("eDiplomas PRF".utf8)

    // MARK: - Fixtures

    private func resourceDirectory() throws -> URL {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "vectors", withExtension: "jsonl", subdirectory: "privatedata-spec")
        )
        return url.deletingLastPathComponent()
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func vectors() throws -> [[String: Any]] {
        let text = try String(contentsOf: resourceDirectory().appendingPathComponent("vectors.jsonl"), encoding: .utf8)
        return try text.split(separator: "\n").compactMap { line in
            try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any]
        }
    }

    private func vector(_ id: String) throws -> [String: Any] {
        try XCTUnwrap(vectors().first { ($0["id"] as? String) == id }, "vector \(id)")
    }

    private func plaintextState(of vector: [String: Any]) throws -> [String: Any]? {
        (vector["inputs"] as? [String: Any])?["plaintextState"] as? [String: Any]
    }

    private func open(_ state: [String: Any]) async throws -> (JweKeystore, Data) {
        let container = try ContainerTestSupport.buildContainer(
            prfOutput: prf, hkdfSalt: salt, hkdfInfo: info, plaintextState: state
        )
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: prf, encryptedContainer: container, hkdfSalt: salt, hkdfInfo: info)
        return (keystore, container)
    }

    private func rewritten(_ keystore: JweKeystore) async throws -> [String: Any] {
        let bytes = try await keystore.exportEncryptedContainer()
        return try ContainerTestSupport.plaintext(of: bytes, prfOutput: prf, hkdfSalt: salt)
    }

    private func s(_ state: [String: Any]) -> [String: Any] { state["S"] as? [String: Any] ?? [:] }

    private func state(
        version: Any = 4,
        events: [[String: Any]] = [],
        credentials: [[String: Any]] = [],
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        var sMember: [String: Any] = [
            "schemaVersion": version,
            "keypairs": [] as [Any],
            "credentials": credentials,
            "presentations": [] as [Any],
            "settings": ["openidRefreshTokenMaxAgeInSeconds": "0"],
            "credentialIssuanceSessions": [] as [Any],
        ]
        for (key, value) in extra { sMember[key] = value }
        return ["lastEventHash": "h-0", "events": events, "S": sMember]
    }

    private func credential(id: Int, extra: [String: Any] = [:]) -> [String: Any] {
        var entry: [String: Any] = [
            "credentialId": id, "format": "dc+sd-jwt", "data": "<credential \(id)>", "kid": "kid-1",
            "instanceId": 0, "batchId": 1, "credentialIssuerIdentifier": "https://issuer.example.com",
            "credentialConfigurationId": "org.siros.nym_auth",
        ]
        for (key, value) in extra { entry[key] = value }
        return entry
    }

    // MARK: - Vendored vectors

    func testTheVendoredVectorsAreTheSpecsByDigest() throws {
        let dir = try resourceDirectory()
        XCTAssertEqual(sha256Hex(try Data(contentsOf: dir.appendingPathComponent("vectors.jsonl"))), Self.vectorsSha256)
        let sums = try Data(contentsOf: dir.appendingPathComponent("vectors.SHA256SUMS"))
        XCTAssertEqual(sha256Hex(sums), Self.sumsSha256)
        var checked = 0
        for line in String(decoding: sums, as: UTF8.self).split(separator: "\n") {
            let parts = line.components(separatedBy: "  ")
            XCTAssertEqual(parts.count, 2, "malformed line \(line)")
            let file = try Data(contentsOf: dir.appendingPathComponent(parts[1]))
            XCTAssertEqual(sha256Hex(file), parts[0], parts[1])
            checked += 1
        }
        XCTAssertGreaterThanOrEqual(checked, 11)
    }

    /// Vectors that need nothing from the keystore container: the delivered-secret
    /// vectors are the receipt's (siros-sdk-swift DeliveredSecretReceipt), and the
    /// merge vectors need an event merger this SDK does not have (it never merges
    /// histories; see the PR description). Listed so a NEW vector id is a decision.
    private static let refusalVectors: Set<String> = [
        "schema-version-unknown-state-001", "schema-version-unknown-event-version-001",
        "schema-version-unknown-event-type-001", "schema-version-event-missing-version-001",
    ]

    private static let notContainerRoundTrips: Set<String> = [
        "schema-version-v3-writer-001",   // driven separately below
        "extensions-unknown-event-001", "extensions-concurrent-keys-001", "extensions-tombstone-001",
        "extensions-stale-peer-001", "extensions-size-accounting-001", "extensions-lww-fold-order-001",
        "extensions-lww-tiebreak-001", "extensions-unknown-namespace-retained-001",
        "extensions-version-coexistence-001",
        "delivered-secret-commitment-001", "delivered-secret-wire-001", "delivered-secret-malformed-001",
        "delivered-secret-refusal-001", "delivered-secret-strip-001", "delivered-secret-advertise-001",
    ]

    func testEveryVectorWithAStateRoundTripsThroughTheKeystoreAsTheSpecSays() async throws {
        var roundTripped: [String] = []
        for vector in try vectors() {
            let id = try XCTUnwrap(vector["id"] as? String)
            guard !Self.notContainerRoundTrips.contains(id), !Self.refusalVectors.contains(id) else { continue }
            let input = try XCTUnwrap(plaintextState(of: vector), "vector \(id) has no plaintextState; classify it")
            let (keystore, _) = try await open(input)
            XCTAssertNil(keystore.unsupportedSchemaVersion, id)
            let output = try await rewritten(keystore)

            var expected = ((vector["expected"] as? [String: Any])?["roundTripState"] as? [String: Any]) ?? input
            var expectedS = s(expected)
            expectedS["schemaVersion"] = 4   // a rewrite writes version 4; nothing else changes
            expected["S"] = expectedS

            XCTAssertEqual(output["lastEventHash"] as? String, expected["lastEventHash"] as? String, id)
            XCTAssertTrue(ContainerTestSupport.jsonEqual(output["events"], expected["events"]), "\(id): events")
            for member in Set(s(output).keys).union(expectedS.keys) {
                XCTAssertTrue(
                    ContainerTestSupport.jsonEqual(s(output)[member], expectedS[member]),
                    "\(id): S.\(member) differs\n got \(String(describing: s(output)[member]))\n want \(String(describing: expectedS[member]))"
                )
            }
            roundTripped.append(id)
        }
        XCTAssertTrue(roundTripped.contains("credential-metadata-001"))
        XCTAssertTrue(roundTripped.contains("credential-unknown-member-001"))
        XCTAssertTrue(roundTripped.contains("container-unknown-top-level-member-001"))
        XCTAssertTrue(roundTripped.contains("single-credential-v3-001"))
        XCTAssertTrue(roundTripped.contains("multi-passkey-v3-001"))
        XCTAssertTrue(roundTripped.contains("schema-version-event-types-001"))
        XCTAssertTrue(roundTripped.contains("keypair-unknown-entry-001"))
    }

    func testTheRefusalVectorsAreRefusedAsUnsupportedAndNothingIsRewritten() async throws {
        let expectedSubjects: [String: UnsupportedSchemaVersion.Subject] = [
            "schema-version-unknown-state-001": .state,
            "schema-version-unknown-event-version-001": .event(index: 0),
            "schema-version-unknown-event-type-001": .eventType(index: 0, type: "a_type_this_reader_does_not_know"),
            "schema-version-event-missing-version-001": .event(index: 0),
        ]
        XCTAssertEqual(Set(expectedSubjects.keys), Self.refusalVectors)
        for (id, subject) in expectedSubjects {
            let input = try XCTUnwrap(plaintextState(of: try vector(id)))
            let (keystore, container) = try await open(input)
            // Reading is unaffected; rewriting is refused, typed, with the right part named.
            await assertRefused(keystore, subject: subject)
            // The container the caller holds is untouched, so nothing was overwritten.
            let still = try ContainerTestSupport.plaintext(of: container, prfOutput: prf, hkdfSalt: salt)
            XCTAssertTrue(ContainerTestSupport.jsonEqual(still["S"], input["S"]), id)
            XCTAssertTrue(ContainerTestSupport.jsonEqual(still["events"], input["events"]), id)
        }
    }

    /// `schema-version-v3-writer-001`: storing into a version 3 container writes version 4. The
    /// `credentialMetadata` write needs the per-credential metadata accessor (siros-sdk-swift #202,
    /// not on main); the extension write is exercised here.
    func testTheWriterVectorWritesVersionFourWhenStoringAnExtension() async throws {
        let v = try vector("schema-version-v3-writer-001")
        let input = try XCTUnwrap(plaintextState(of: v))
        XCTAssertEqual(s(input)["schemaVersion"] as? Int, 3)
        let write = try XCTUnwrap((v["inputs"] as? [String: Any])?["write"] as? [String: Any])
        let ext = try XCTUnwrap(write["setExtension"] as? [String: String])
        let expected = try XCTUnwrap(v["expected"] as? [String: Any])
        let (keystore, _) = try await open(input)
        try await keystore.setExtensionEntry(
            namespace: try XCTUnwrap(ext["namespace"]), key: try XCTUnwrap(ext["key"]), value: try XCTUnwrap(ext["value"])
        )
        let output = try await rewritten(keystore)
        XCTAssertEqual(s(output)["schemaVersion"] as? Int, expected["writtenSchemaVersion"] as? Int)
        XCTAssertNoThrow(try WalletStateSchema.requireWriterRules(output))
    }

    // MARK: - Refusal

    private func assertRefused(
        _ keystore: JweKeystore, subject: UnsupportedSchemaVersion.Subject,
        file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await keystore.exportEncryptedContainer()
            XCTFail("export succeeded", file: file, line: line)
        } catch KeystoreError.unsupportedSchemaVersion(let unsupported) {
            XCTAssertEqual(unsupported.subject, subject, file: file, line: line)
        } catch {
            XCTFail("expected unsupportedSchemaVersion, got \(error)", file: file, line: line)
        }
        do {
            try await keystore.saveCredential(id: 9, json: "{\"id\":9}")
            XCTFail("saveCredential succeeded", file: file, line: line)
        } catch KeystoreError.unsupportedSchemaVersion {
            // expected
        } catch {
            XCTFail("expected unsupportedSchemaVersion, got \(error)", file: file, line: line)
        }
    }

    func testRefusedStateStillReadsAtSchemaVersionFive() async throws {
        let (keystore, _) = try await open(state(version: 5, credentials: [credential(id: 1)]))
        let readable = try await keystore.getCredential(id: 1)
        XCTAssertNotNil(readable, "reading still works")
        XCTAssertEqual(keystore.unsupportedSchemaVersion?.found, "5")
    }

    func testVersionTwoIsReadableButNotRewritten() async throws {
        let (keystore, _) = try await open(state(version: 2, credentials: [credential(id: 1)]))
        let readable = try await keystore.getCredential(id: 1)
        XCTAssertNotNil(readable)
        await assertRefused(keystore, subject: .state)
    }

    func testTheRefusalClearsWhenTheStoreIsLockedAndReopenedOnASupportedContainer() async throws {
        let (keystore, _) = try await open(state(version: 5))
        XCTAssertNotNil(keystore.unsupportedSchemaVersion)
        keystore.lock()
        XCTAssertNil(keystore.unsupportedSchemaVersion)
        let ok = try ContainerTestSupport.buildContainer(
            prfOutput: prf, hkdfSalt: salt, hkdfInfo: info, plaintextState: state(version: 4)
        )
        try await keystore.unlock(prfOutput: prf, encryptedContainer: ok, hkdfSalt: salt, hkdfInfo: info)
        XCTAssertNil(keystore.unsupportedSchemaVersion)
        _ = try await keystore.exportEncryptedContainer()
    }

    // MARK: - Migration and writer rules

    func testAFreshContainerIsWrittenAtVersionFour() async throws {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: prf, encryptedContainer: Data(), hkdfSalt: salt, hkdfInfo: info)
        let output = try await rewritten(keystore)
        XCTAssertEqual(s(output)["schemaVersion"] as? Int, 4)
    }

    func testEmptyOrNullMetadataIsNotWrittenBack() async throws {
        let creds = [
            credential(id: 1, extra: ["metadata": [] as [Any]]),
            credential(id: 2, extra: ["metadata": NSNull()]),
        ]
        let (keystore, _) = try await open(state(credentials: creds))
        let output = try await rewritten(keystore)
        let out = (s(output)["credentials"] as? [[String: Any]]) ?? []
        XCTAssertEqual(out.count, 2)
        for entry in out { XCTAssertNil(entry["metadata"], "metadata must be absent, not [] or null") }
    }

    // MARK: - Preservation

    func testUnknownMembersAndMetadataAreWrittenBackWithIdenticalValuesInOrder() async throws {
        let meta: [[String: Any]] = [
            ["type": "org.siros.secret_seed", "value": ["org.siros.nym_auth": "00112233445566778899aabbccddeeff"], "x-entry-member": [1, [2, NSNull()]] as [Any]],
            ["type": "example.dup", "value": "first"],
            ["type": "example.dup", "value": "second"],
            ["type": "example.unicode", "value": "Körkort – Åland テスト 😀"],
        ]
        let creds = [
            credential(id: 30, extra: ["metadata": meta, "x-unknown": ["k": [1, 2, 3], "n": NSNull(), "b": false] as [String: Any]]),
            credential(id: 10, extra: ["x-other": "o"]),
            credential(id: 20),
        ]
        let input = state(credentials: creds, extra: [
            "futureMember": ["nested": ["a": true]],
            "extensions": ["com.example.unknown": ["entity": "opaque"]],
        ])
        let (keystore, _) = try await open(input)
        let output = try await rewritten(keystore)

        // Same array, same order (30, 10, 20 - not sorted, not hash order).
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["credentials"], creds))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["futureMember"], s(input)["futureMember"]))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["extensions"], s(input)["extensions"]))
    }

    func testDeletingACredentialDeletesItsMetadataAndAddingOneAppendsIt() async throws {
        let creds = [
            credential(id: 1, extra: ["metadata": [["type": "t", "value": 1]], "x-unknown": 1]),
            credential(id: 2),
        ]
        let (keystore, _) = try await open(state(credentials: creds))
        try await keystore.deleteCredential(id: 1)
        try await keystore.saveCredential(id: 3, json: "{\"id\":3,\"format\":\"dc+sd-jwt\",\"raw\":\"r\"}")
        let output = try await rewritten(keystore)
        let out = (s(output)["credentials"] as? [[String: Any]]) ?? []
        XCTAssertEqual(out.compactMap { ($0["credentialId"] as? NSNumber)?.int64Value }, [2, 3])
        XCTAssertTrue(out.allSatisfy { $0["metadata"] == nil && $0["x-unknown"] == nil })
    }

    /// Export starts each entry from the loaded one, so a deleted credential's entry must be
    /// forgotten, or a different credential saved under the same id inherits its metadata.
    func testASavedCredentialDoesNotInheritADeletedOnesMetadataOrUnknownMembers() async throws {
        let seeded = credential(id: 1, extra: ["metadata": [["type": "org.siros.secret_seed", "value": ["ns": "00"]]], "x-unknown": 1])
        let json = "{\"id\":1,\"format\":\"dc+sd-jwt\",\"raw\":\"new\"}"
        for clear in [false, true] {
            let (keystore, _) = try await open(state(credentials: [seeded, credential(id: 2)]))
            if clear { try await keystore.clearCredentials() } else { try await keystore.deleteCredential(id: 1) }
            try await keystore.saveCredential(id: 1, json: json)
            let output = try await rewritten(keystore)
            let out = (s(output)["credentials"] as? [[String: Any]]) ?? []
            let reused = try XCTUnwrap(out.first { ($0["credentialId"] as? NSNumber)?.int64Value == 1 })
            XCTAssertNil(reused["metadata"], "clear=\(clear)")
            XCTAssertNil(reused["x-unknown"], "clear=\(clear)")
            XCTAssertEqual(reused["data"] as? String, "new")
        }
    }

    func testKeypairEntriesKeepTheirPositionsWhenLoadedAndUnloadableEntriesAreMixed() async throws {
        let first: [String: Any] = ["kid": "z-hw", "keypair": ["kid": "z-hw", "alg": "ES384"] as [String: Any]]
        let key = P256.Signing.PrivateKey()
        let x963 = key.publicKey.x963Representation
        let b64 = EncryptedContainer.base64UrlEncode
        let loaded: [String: Any] = ["kid": "a-sw", "x-entry": 1, "keypair": [
            "kid": "a-sw", "did": "did:example:a", "alg": "ES256",
            "publicKey": ["kty": "EC", "crv": "P-256", "x": b64(Data(x963[1..<33])), "y": b64(Data(x963[33..<65]))],
            "privateKey": ["kty": "EC", "crv": "P-256", "x": b64(Data(x963[1..<33])), "y": b64(Data(x963[33..<65])), "d": b64(key.rawRepresentation)],
        ] as [String: Any]]
        let (keystore, _) = try await open(state(extra: ["keypairs": [first, loaded]]))
        let newKid = try await keystore.generateKey()
        let output = try await rewritten(keystore)
        let kids = ((s(output)["keypairs"] as? [[String: Any]]) ?? []).compactMap { $0["kid"] as? String }
        XCTAssertEqual(kids, ["z-hw", "a-sw", newKid])
        let entries = (s(output)["keypairs"] as? [[String: Any]]) ?? []
        XCTAssertEqual(entries[1]["x-entry"] as? Int, 1)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(entries[0], first))
    }

    func testPresentationsAndJwkMembersSurviveAVersionOnlyMigration() async throws {
        let key = P256.Signing.PrivateKey()
        let x963 = key.publicKey.x963Representation
        let b64 = EncryptedContainer.base64UrlEncode
        let x = b64(Data(x963[1..<33])), y = b64(Data(x963[33..<65]))
        let keypair: [String: Any] = ["kid": "kp", "keypair": [
            "kid": "kp", "did": "did:example:kp", "alg": "ES256",
            "publicKey": ["kty": "EC", "crv": "P-256", "x": x, "y": y, "key_ops": ["verify"], "x-peer": 1],
            "privateKey": ["kty": "EC", "crv": "P-256", "x": x, "y": y, "d": b64(key.rawRepresentation), "use": "sig", "ext": true],
        ] as [String: Any]]
        let presentations: [[String: Any]] = [
            ["presentationId": 9, "transactionId": 77, "data": "vp-token", "usedCredentialIds": [1],
             "presentationTimestampSeconds": 5, "audience": "a", "x-unknown": 1],
            ["presentationId": 3, "transactionId": 3, "data": "", "usedCredentialIds": [] as [Any],
             "presentationTimestampSeconds": 6, "audience": "b"],
        ]
        let input = state(version: 3, extra: ["keypairs": [keypair], "presentations": presentations])
        let (keystore, _) = try await open(input)
        let output = try await rewritten(keystore)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["presentations"], presentations))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["keypairs"], [keypair]))
    }

    /// The chain is wallet-frontend's: pinned against the real chain in the spec's
    /// `schema-version-event-types-001`, which covers all ten types including `new_keypair`
    /// (hashed with `wrappedPrivateKey` null) and `set_extension`.
    func testTheEventHashReproducesTheSpecsParentHashChain() throws {
        let input = try XCTUnwrap(plaintextState(of: try vector("schema-version-event-types-001")))
        let events = try XCTUnwrap(input["events"] as? [[String: Any]])
        XCTAssertEqual(events.count, 13)
        XCTAssertEqual(events[0]["parentHash"] as? String, input["lastEventHash"] as? String)
        for index in 1..<events.count {
            XCTAssertEqual(WalletStateEvents.hash(events[index - 1]), events[index]["parentHash"] as? String, "event \(index)")
        }
    }

    func testChangingAnExtensionAppendsAChainedSetExtensionEventAtVersionFour() async throws {
        let input = try XCTUnwrap(plaintextState(of: try vector("schema-version-event-types-001")))
        let before = try XCTUnwrap(input["events"] as? [[String: Any]])
        let (keystore, _) = try await open(input)
        try await keystore.setExtensionEntry(namespace: "org.siros.wscd", key: "kid-a", value: "v1")
        try await keystore.removeExtensionEntry(namespace: "org.siros.wscd", key: "kid-a")
        let output = try await rewritten(keystore)
        let events = try XCTUnwrap(output["events"] as? [[String: Any]])
        XCTAssertEqual(events.count, before.count + 2)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(Array(events.prefix(before.count)), before), "history untouched")
        let set = events[before.count], tombstone = events[before.count + 1]
        XCTAssertEqual(set["type"] as? String, "set_extension")
        XCTAssertEqual(set["schemaVersion"] as? Int, 4)
        XCTAssertEqual(set["namespace"] as? String, "org.siros.wscd")
        XCTAssertEqual(set["key"] as? String, "kid-a")
        XCTAssertEqual(set["value"] as? String, "v1")
        XCTAssertEqual(set["parentHash"] as? String, WalletStateEvents.hash(before[before.count - 1]))
        XCTAssertTrue(tombstone["value"] is NSNull, "removal is a tombstone")
        XCTAssertEqual(tombstone["parentHash"] as? String, WalletStateEvents.hash(set))
        XCTAssertNil(WalletStateSchema.rewriteRefusal(of: output))
        // Exporting again appends nothing: the history is now the container's.
        let again = try await rewritten(keystore)
        XCTAssertEqual((again["events"] as? [Any])?.count, events.count)
    }

    func testAFreshContainerChainsItsFirstExtensionEventFromLastEventHash() async throws {
        let (keystore, _) = try await open(state())   // lastEventHash "h-0", no events
        try await keystore.setExtensionEntry(namespace: "ns", key: "k", value: "v")
        let output = try await rewritten(keystore)
        let events = try XCTUnwrap(output["events"] as? [[String: Any]])
        XCTAssertEqual(events.count, 1)
        XCTAssertEqual(events[0]["parentHash"] as? String, "h-0")
    }

    func testClearingPresentationsRemovesTheLoadedHistoryAndASavedRecordUpdatesItsEntry() async throws {
        let presentations: [Any] = [
            ["presentationId": 9, "transactionId": 77, "data": "vp-token", "usedCredentialIds": [1],
             "presentationTimestampSeconds": 5, "audience": "old", "x-unknown": 1] as [String: Any],
            "unreadable entry",
            ["presentationId": 3, "transactionId": 3, "data": "", "usedCredentialIds": [] as [Any],
             "presentationTimestampSeconds": 6, "audience": "b"] as [String: Any],
        ]
        // A record saved under a loaded id updates that entry; the rest stay as they were.
        let (updating, _) = try await open(state(extra: ["presentations": presentations]))
        try await updating.savePresentationRecord(
            id: 9, json: "{\"id\":9,\"flow_id\":\"\",\"credential_ids\":[2],\"timestamp\":7000,\"verifier_name\":\"new\"}"
        )
        let out = (s(try await rewritten(updating))["presentations"] as? [Any]) ?? []
        XCTAssertEqual(out.count, 3)
        let first = try XCTUnwrap(out[0] as? [String: Any])
        XCTAssertEqual(first["audience"] as? String, "new")
        XCTAssertEqual(first["presentationTimestampSeconds"] as? Int, 7)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(first["usedCredentialIds"], [2]))
        XCTAssertEqual(first["data"] as? String, "vp-token")
        XCTAssertEqual(first["transactionId"] as? Int, 77)
        XCTAssertEqual(first["x-unknown"] as? Int, 1)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(out[1], presentations[1]))
        XCTAssertTrue(ContainerTestSupport.jsonEqual(out[2], presentations[2]))

        // Clearing removes everything, including the unreadable entry; a reused id starts fresh.
        let (clearing, _) = try await open(state(extra: ["presentations": presentations]))
        try await clearing.clearPresentationRecords()
        let cleared = try await rewritten(clearing)
        XCTAssertTrue(((s(cleared)["presentations"] as? [Any]) ?? [1]).isEmpty)
        try await clearing.savePresentationRecord(id: 9, json: "{\"id\":9,\"credential_ids\":[],\"timestamp\":1000}")
        let reused = (s(try await rewritten(clearing))["presentations"] as? [[String: Any]]) ?? []
        XCTAssertEqual(reused.count, 1)
        XCTAssertEqual(reused.first?["data"] as? String, "")
        XCTAssertNil(reused.first?["x-unknown"])
    }

    func testUnknownKeypairMembersAndAnUnloadableKeypairSurvive() async throws {
        let stub: [String: Any] = ["kid": "hw-1", "keypair": ["kid": "hw-1", "alg": "ES384", "x-future": ["a": 1]] as [String: Any], "x-entry": true]
        let (keystore, _) = try await open(state(extra: ["keypairs": [stub]]))
        let output = try await rewritten(keystore)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(s(output)["keypairs"], [stub]))
    }
}

#else
final class PrivateDataSchemaVectorTests: XCTestCase {
    func testCryptoKitUnavailable() {
        // No-op placeholder: CryptoKit is unavailable on this platform.
    }
}
#endif
