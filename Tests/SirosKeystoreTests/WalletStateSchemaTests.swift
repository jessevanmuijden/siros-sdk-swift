// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

/// The schema-version rules of privatedata-spec section 6 on plain JSON. No
/// CryptoKit, so these run on Linux CI as well as on Apple platforms; the
/// keystore-level tests (`PrivateDataSchemaVectorTests`) need CryptoKit.
final class WalletStateSchemaTests: XCTestCase {

    private func container(
        schemaVersion: Any? = 4,
        events: [[String: Any]]? = nil,
        extra: [String: Any] = [:]
    ) -> [String: Any] {
        var s: [String: Any] = ["credentials": [] as [Any]]
        if let schemaVersion { s["schemaVersion"] = schemaVersion }
        for (k, v) in extra { s[k] = v }
        var c: [String: Any] = ["lastEventHash": "h", "S": s]
        if let events { c["events"] = events }
        return c
    }

    private func parse(_ json: String) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
    }

    // MARK: - Versions this build rewrites

    func testVersionsThreeAndFourMayBeRewritten() {
        XCTAssertNil(WalletStateSchema.rewriteRefusal(of: container(schemaVersion: 3)))
        XCTAssertNil(WalletStateSchema.rewriteRefusal(of: container(schemaVersion: 4)))
    }

    func testStateSchemaVersionFiveIsRefusedAsUnsupportedNotAsAFailedMerge() throws {
        let refusal = try XCTUnwrap(WalletStateSchema.rewriteRefusal(of: container(schemaVersion: 5)))
        XCTAssertEqual(refusal.subject, .state)
        XCTAssertEqual(refusal.found, "5")
        XCTAssertThrowsError(try WalletStateSchema.requireRewritable(container(schemaVersion: 5))) { error in
            guard case KeystoreError.unsupportedSchemaVersion(let unsupported) = error else {
                return XCTFail("expected KeystoreError.unsupportedSchemaVersion, got \(error)")
            }
            XCTAssertEqual(unsupported.subject, .state)
        }
    }

    func testOlderVersionsAreReadableButNotRewritable() {
        XCTAssertTrue(WalletStateSchema.readableVersions.contains(1))
        for old in [1, 2] {
            XCTAssertNotNil(WalletStateSchema.rewriteRefusal(of: container(schemaVersion: old)), "version \(old)")
        }
        XCTAssertNotNil(WalletStateSchema.rewriteRefusal(of: container(schemaVersion: 0)))
    }

    func testAnAbsentStateVersionReadsAsVersionOneAndIsRefused() {
        XCTAssertNotNil(WalletStateSchema.rewriteRefusal(of: container(schemaVersion: nil)))
    }

    func testAVersionThatIsNotAnIntegerJSONNumberIsRefused() throws {
        for bad in ["\"4\"", "true", "4.5", "null", "[4]", "{\"v\":4}", "1e300"] {
            let c = try parse("{\"S\":{\"schemaVersion\":\(bad)},\"events\":[]}")
            XCTAssertNotNil(WalletStateSchema.rewriteRefusal(of: c), "schemaVersion \(bad)")
        }
        // JSON has one number type: 4.0 is the integer 4, as it is in wallet-frontend.
        XCTAssertNil(WalletStateSchema.rewriteRefusal(of: try parse("{\"S\":{\"schemaVersion\":4.0},\"events\":[]}")))
    }

    // MARK: - Events

    func testAnEventWithSchemaVersionFiveIsRefused() throws {
        let c = container(events: [
            ["type": "alter_settings", "schemaVersion": 4, "eventId": 1],
            ["type": "alter_settings", "schemaVersion": 5, "eventId": 2],
        ])
        let refusal = try XCTUnwrap(WalletStateSchema.rewriteRefusal(of: c))
        XCTAssertEqual(refusal.subject, .event(index: 1))
        XCTAssertEqual(refusal.found, "5")
    }

    func testAnEventTypeNoImplementedVersionDefinesIsRefused() throws {
        let c = container(events: [["type": "a_type_this_reader_does_not_know", "schemaVersion": 4, "eventId": 1]])
        let refusal = try XCTUnwrap(WalletStateSchema.rewriteRefusal(of: c))
        XCTAssertEqual(refusal.subject, .eventType(index: 0, type: "a_type_this_reader_does_not_know"))
    }

    func testEveryTypeWalletFrontendDefinesIsKnown() {
        for type in [
            "new_credential", "delete_credential", "new_keypair", "delete_keypair", "new_presentation",
            "delete_presentation", "alter_settings", "save_credential_issuance_session",
            "delete_credential_issuance_session", "set_extension",
        ] {
            let c = container(events: [["type": type, "schemaVersion": 4, "eventId": 1]])
            XCTAssertNil(WalletStateSchema.rewriteRefusal(of: c), type)
        }
    }

    func testAnEventWithoutAnIntegerSchemaVersionIsRefused() throws {
        for event: [String: Any] in [
            ["type": "alter_settings", "eventId": 1],
            ["type": "alter_settings", "schemaVersion": "4"],
            ["type": "alter_settings", "schemaVersion": NSNull()],
        ] {
            let refusal = try XCTUnwrap(WalletStateSchema.rewriteRefusal(of: container(events: [event])))
            XCTAssertEqual(refusal.subject, .event(index: 0))
        }
    }

    func testAnEventThatIsNotAnObjectOrEventsThatAreNotAnArrayIsRefused() throws {
        XCTAssertNotNil(WalletStateSchema.rewriteRefusal(of: try parse("{\"S\":{\"schemaVersion\":4},\"events\":[1]}")))
        XCTAssertNotNil(WalletStateSchema.rewriteRefusal(of: try parse("{\"S\":{\"schemaVersion\":4},\"events\":{}}")))
    }

    func testAPresentSThatIsNotAnObjectIsRefused() throws {
        for bad in ["null", "[]", "\"x\"", "4"] {
            XCTAssertNotNil(WalletStateSchema.rewriteRefusal(of: try parse("{\"S\":\(bad),\"events\":[]}")), "S \(bad)")
        }
    }

    func testSetExtensionStampedThreeIsAcceptedBecauseContainersBeforeSpec30HaveIt() {
        let c = container(events: [["type": "set_extension", "schemaVersion": 3, "eventId": 1]])
        XCTAssertNil(WalletStateSchema.rewriteRefusal(of: c))
    }

    func testTheLegacyContainerWithoutSIsStillAccepted() throws {
        XCTAssertNil(WalletStateSchema.rewriteRefusal(of: try parse("{\"keys\":[]}")))
    }

    func testTheRefusalNamesWhatIsWrongForTheCaller() {
        let state = UnsupportedSchemaVersion(subject: .state, found: "5")
        XCTAssertTrue(KeystoreError.unsupportedSchemaVersion(state).localizedDescription.contains("5"))
        XCTAssertTrue(KeystoreError.unsupportedSchemaVersion(state).localizedDescription.contains("Update the app"))
    }

    // MARK: - Writer rules

    func testVersionFourMembersAreFoundWhereTheyAre() throws {
        let c = try parse("""
        {"events":[{"type":"set_extension","schemaVersion":4}],
         "S":{"schemaVersion":3,"extensions":{"a":{"b":"c"}},
              "credentials":[{"credentialId":1,"metadata":[{"type":"t","value":1}]}]}}
        """)
        XCTAssertEqual(
            Set(WalletStateSchema.versionFourMembers(in: c)),
            ["S.extensions", "S.credentials[].metadata", "set_extension"]
        )
    }

    func testAWriterMayNotEmitMetadataOrExtensionsIntoAVersionThreeContainer() throws {
        let withExtensions = container(schemaVersion: 3, extra: ["extensions": ["ns": ["k": "v"]]])
        XCTAssertThrowsError(try WalletStateSchema.requireWriterRules(withExtensions))
        let withMetadata = container(schemaVersion: 3, extra: [
            "credentials": [["credentialId": 1, "metadata": [["type": "t", "value": 1]]]],
        ])
        XCTAssertThrowsError(try WalletStateSchema.requireWriterRules(withMetadata))
        let withEvent = container(schemaVersion: 3, events: [["type": "set_extension", "schemaVersion": 3]])
        XCTAssertThrowsError(try WalletStateSchema.requireWriterRules(withEvent))
    }

    func testTheSameMembersAreFineInAVersionFourContainerAndAbsenceIsFineInVersionThree() throws {
        XCTAssertNoThrow(try WalletStateSchema.requireWriterRules(
            container(schemaVersion: 4, extra: ["extensions": ["ns": ["k": "v"]]])
        ))
        XCTAssertNoThrow(try WalletStateSchema.requireWriterRules(container(schemaVersion: 3)))
    }

    func testMetadataIsOmittedWhenThereIsNothingToStoreAndOtherwiseKeptAsIs() {
        XCTAssertNil(WalletStateSchema.writableMetadata(nil))
        XCTAssertNil(WalletStateSchema.writableMetadata(NSNull()))
        XCTAssertNil(WalletStateSchema.writableMetadata([] as [Any]))
        let entries: [Any] = [["type": "t", "value": ["a": 1]] as [String: Any]]
        XCTAssertEqual((WalletStateSchema.writableMetadata(entries) as? [Any])?.count, 1)
        // A value this build cannot read is preserved, not judged.
        XCTAssertEqual(WalletStateSchema.writableMetadata("not an array") as? String, "not an array")
    }
}
