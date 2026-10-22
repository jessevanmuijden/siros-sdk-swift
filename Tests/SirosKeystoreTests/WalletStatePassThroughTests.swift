// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

#if canImport(CryptoKit)

/// `S` in the container is shared with wallet-frontend and siros-sdk-kotlin,
/// and either may write top-level members this build has never heard of.
/// `JweKeystore` must carry every one of them through an unlock/export cycle
/// untouched: a member it drops is not degraded but destroyed, on every device
/// sharing the account, the next time this client syncs.
final class WalletStatePassThroughTests: XCTestCase {

    private let fakePrfOutput = Data(0..<32)
    private let hkdfSalt = Data((0..<32).map { UInt8($0 + 0x10) })
    private let hkdfInfo = Data("SIROS Wallet PRF".utf8)

    /// A container as another client might have left it: the normative
    /// members, `S.extensions` (privatedata-spec §6.1, written today by
    /// Kotlin and wallet-frontend), and a member nobody has defined yet.
    private var peerWrittenState: [String: Any] {
        let someFuture: [String: Any] = [
            "nested": ["a": 1, "b": [true, NSNull(), "x"] as [Any]] as [String: Any],
            "list": [1, 2, 3],
            "flag": false,
        ]
        let s: [String: Any] = [
            "schemaVersion": 3,
            "keypairs": [] as [Any],
            "credentials": [] as [Any],
            "presentations": [] as [Any],
            "settings": ["openidRefreshTokenMaxAgeInSeconds": "3600"],
            "credentialIssuanceSessions": [["sessionId": 7, "state": "pending"] as [String: Any]],
            "extensions": [
                "org.siros.bbs": ["cred-1": "blind-bbs-holder-state"],
                "com.example.unknown": ["entity-9": "opaque"],
            ],
            "someFuture": someFuture,
        ]
        return [
            "lastEventHash": "peer-hash",
            "events": [["type": "alter_settings", "schemaVersion": 3, "eventId": 1, "parentHash": "", "timestampSeconds": 1, "settings": ["openidRefreshTokenMaxAgeInSeconds": "3600"]] as [String: Any]],
            "S": s,
        ]
    }

    private func reopen(_ container: Data) async throws -> JweKeystore {
        let keystore = JweKeystore()
        try await keystore.unlock(prfOutput: fakePrfOutput, encryptedContainer: container, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
        return keystore
    }

    func testUnknownAndExtensionMembersOfSSurviveUnlockAndExportVerbatim() async throws {
        let original = peerWrittenState
        let container = try ContainerTestSupport.buildContainer(
            prfOutput: fakePrfOutput, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo, plaintextState: original
        )

        // Two round trips, so a client that reads and rewrites twice is
        // covered rather than only the first hop.
        let once = try await reopen(container).exportEncryptedContainer()
        let twice = try await reopen(once).exportEncryptedContainer()

        let redecrypted = try ContainerTestSupport.plaintext(of: twice, prfOutput: fakePrfOutput, hkdfSalt: hkdfSalt)
        var expectedS = original["S"] as! [String: Any]
        let actualS = redecrypted["S"] as! [String: Any]
        // `peerWrittenState` is a version 3 container; a rewrite migrates it to
        // version 4 by changing the version number and nothing else.
        XCTAssertEqual(expectedS["schemaVersion"] as? Int, 3)
        XCTAssertEqual(actualS["schemaVersion"] as? Int, 4)
        expectedS["schemaVersion"] = 4

        XCTAssertTrue(
            ContainerTestSupport.jsonEqual(expectedS["someFuture"], actualS["someFuture"]),
            "an S member this build does not implement must round-trip byte-for-byte; got \(String(describing: actualS["someFuture"]))"
        )
        XCTAssertTrue(
            ContainerTestSupport.jsonEqual(expectedS["extensions"], actualS["extensions"]),
            "S.extensions must round-trip byte-for-byte; got \(String(describing: actualS["extensions"]))"
        )
        // And nothing else was disturbed on the way: with no keys or
        // credentials of its own, the whole of S must come back as it went in.
        XCTAssertTrue(ContainerTestSupport.jsonEqual(expectedS, actualS), "S differs after round trip: \(actualS)")
        XCTAssertEqual(original["lastEventHash"] as? String, redecrypted["lastEventHash"] as? String)
        XCTAssertTrue(ContainerTestSupport.jsonEqual(original["events"], redecrypted["events"]))
    }

    /// The pass-through must not resurrect members this class owns. A
    /// `wscdCredentials` entry present at unlock and absent in memory at
    /// export (nothing re-recorded it) is omitted, exactly as before.
    func testOwnedMembersAreStillRebuiltFromMemoryNotCarriedFromTheLoadedState() async throws {
        var state = peerWrittenState
        var s = state["S"] as! [String: Any]
        s["wscdCredentials"] = ["fido2": "stale-plugin-state"]
        state["S"] = s
        let container = try ContainerTestSupport.buildContainer(
            prfOutput: fakePrfOutput, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo, plaintextState: state
        )

        let keystore = try await reopen(container)
        // Loaded into memory, so it IS written back...
        let kept = try ContainerTestSupport.plaintext(
            of: try await keystore.exportEncryptedContainer(), prfOutput: fakePrfOutput, hkdfSalt: hkdfSalt
        )
        XCTAssertEqual(((kept["S"] as? [String: Any])?["wscdCredentials"] as? [String: String])?["fido2"], "stale-plugin-state")

        // ...but from the in-memory map, which is what the accessor reports,
        // not from the loaded copy - so the loaded copy cannot mask an
        // in-session change.
        await keystore.setWscdCredentials(pluginId: "fido2", state: "fresh-plugin-state")
        let updated = try ContainerTestSupport.plaintext(
            of: try await keystore.exportEncryptedContainer(), prfOutput: fakePrfOutput, hkdfSalt: hkdfSalt
        )
        XCTAssertEqual(((updated["S"] as? [String: Any])?["wscdCredentials"] as? [String: String])?["fido2"], "fresh-plugin-state")
    }
}

#else
final class WalletStatePassThroughTests: XCTestCase {
    func testCryptoKitUnavailable() {
        // No-op placeholder: CryptoKit is unavailable on this platform.
    }
}
#endif
