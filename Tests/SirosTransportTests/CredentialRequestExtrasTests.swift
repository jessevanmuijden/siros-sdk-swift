// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

/// `credential_request_extras` on both transports.
///
/// The wallet, not the backend, holds the state some credential formats
/// need at issuance - blind BBS requires a commitment computed locally, and
/// the issuer will not sign without it. The backend builds the credential
/// request, so that value has to travel over whichever transport is in
/// play.
///
/// Production runs the legacy websocket protocol today; WMP is not deployed
/// yet and has to work alongside it rather than replace it. So the property
/// that matters is not that either transport carries the field, but that
/// they carry it **identically** - one member name, one shape, one backend
/// code path, and a flow that behaves the same whichever transport it runs
/// over.
///
/// Mirrors Kotlin's `CredentialRequestExtrasTest`.
final class CredentialRequestExtrasTests: XCTestCase {

    private let extras: [String: AnyCodable] = [
        "bbs_commitment": .string("q29tbWl0bWVudA"),
        "bbs_committed_claims": .array([.string("/device_pin_hash")]),
    ]

    private final class FakePeerContext: WmpPeerContext, @unchecked Sendable {
        let codec = WmpCodec()

        private let lock = NSLock()
        private var _notifications: [(method: String, params: [String: AnyCodable]?)] = []

        var notifications: [(method: String, params: [String: AnyCodable]?)] {
            lock.lock()
            defer { lock.unlock() }
            return _notifications
        }

        func notify(method: String, params: [String: AnyCodable]?) async throws {
            lock.lock()
            _notifications.append((method, params))
            lock.unlock()
        }

        func call(method: String, params: [String: AnyCodable]?) async throws -> JsonRpcResponse {
            JsonRpcResponse(id: nil)
        }
    }

    /// The shape the backend sends to open the sign sub-flow.
    private func signPayload() -> AnyCodable {
        .object_([
            "action": .string("generate_proof"),
            "nonce": .string("abc123"),
            "audience": .string("https://issuer.example.com/token"),
        ])
    }

    /// Encodes a legacy message and hands back the parsed object.
    private func encodeLegacy(_ msg: SignResponseMessage) throws -> [String: AnyCodable] {
        let data = try JSONEncoder().encode(msg)
        return try XCTUnwrap(try JSONDecoder().decode(AnyCodable.self, from: data).objectValue)
    }

    /// Runs one sign sub-flow over WMP and hands back the child's
    /// `wmp.flow.complete` result.
    private func runWmpSignFlow(returning result: SignSubFlowResult) async throws -> [String: AnyCodable] {
        let profile = OpenID4xProfile(config: OpenID4xConfig(onSignRequest: { _, _ in result }))
        let ctx = FakePeerContext()
        profile.initialize(ctx: ctx)

        var members = signPayload().objectValue ?? [:]
        members["parent_flow_id"] = .string("f1")
        await profile.runChildFlow(params: FlowStartParams(
            wmp: WmpMeta(), flowId: "c1", flowType: "sign", params: .object_(members)
        ))

        let notification = try XCTUnwrap(
            ctx.notifications.first { $0.method == WmpMethods.flowComplete },
            "no wmp.flow.complete notification was sent"
        )
        return try XCTUnwrap(notification.params?["result"]?.objectValue)
    }

    // MARK: - Tests

    /// The legacy protocol carries it under the specified member name.
    func testTheLegacyProtocolCarriesTheExtras() throws {
        let encoded = try encodeLegacy(SignResponseMessage(flowId: "f1", credentialRequestExtras: extras))

        let carried = try XCTUnwrap(
            encoded["credential_request_extras"],
            "legacy sign_response must carry credential_request_extras"
        )
        XCTAssertEqual(carried, .object_(extras))
    }

    /// WMP carries it under the same member name.
    func testWmpCarriesTheExtras() async throws {
        let params = try await runWmpSignFlow(returning: SignSubFlowResult(
            proofs: [ProofObject(proofType: "jwt", jwt: "jwt-token")],
            credentialRequestExtras: extras
        ))

        let carried = try XCTUnwrap(
            params["credential_request_extras"],
            "WMP sign_response must carry credential_request_extras"
        )
        XCTAssertEqual(carried, .object_(extras))
    }

    /// The two transports must put the *same* thing on the wire.
    ///
    /// This is the test the change exists for. If the member name or shape
    /// drifted between them, a backend would need two code paths and a flow
    /// would behave differently depending on which transport carried it -
    /// and the divergence would only show up once WMP was deployed
    /// alongside the legacy protocol, which is exactly when it is most
    /// expensive.
    func testBothTransportsAgreeOnTheWireShape() async throws {
        let legacyMessage = try encodeLegacy(SignResponseMessage(flowId: "f1", credentialRequestExtras: extras))
        let legacy = legacyMessage["credential_request_extras"]

        let wmpParams = try await runWmpSignFlow(returning: SignSubFlowResult(credentialRequestExtras: extras))
        let wmp = wmpParams["credential_request_extras"]

        XCTAssertNotNil(legacy)
        XCTAssertEqual(legacy, wmp, "the two transports must serialise this identically")
    }

    /// Absent on every flow that does not need it - which is all of them
    /// except blind BBS issuance.
    ///
    /// A member that appeared as `null` on ordinary flows would change the
    /// bytes on the wire for every existing issuance, which is not a change
    /// worth making to carry an optional field.
    func testOrdinaryFlowsCarryNoSuchMember() async throws {
        let legacy = try encodeLegacy(SignResponseMessage(flowId: "f1", proofs: nil))
        XCTAssertNil(
            legacy["credential_request_extras"],
            "legacy sign_response must omit the member entirely when unused"
        )

        let wmp = try await runWmpSignFlow(returning: SignSubFlowResult(
            proofs: [ProofObject(proofType: "jwt", jwt: "t")]
        ))
        XCTAssertNil(
            wmp["credential_request_extras"],
            "WMP sign_response must omit the member entirely when unused"
        )
    }

    /// The proofs the two transports carry alongside the extras must agree
    /// too. WMP hand-rolls the `proofs` encoding, and until now it forwarded
    /// only `proof_type` and `jwt` - an `attestation` proof (the key
    /// attestation the wallet produces for `request_attestation`-style
    /// issuance) lost its payload on that transport alone.
    func testBothTransportsCarryAttestationProofs() async throws {
        let proof = ProofObject(proofType: "attestation", attestation: "key-attestation-jwt")

        let legacy = try encodeLegacy(SignResponseMessage(flowId: "f1", proofs: [proof]))
        let legacyProof = try XCTUnwrap(legacy["proofs"]?.arrayValue?.first?.objectValue)

        let wmp = try await runWmpSignFlow(returning: SignSubFlowResult(proofs: [proof]))
        let wmpProof = try XCTUnwrap(wmp["proofs"]?.arrayValue?.first?.objectValue)

        XCTAssertEqual(legacyProof["attestation"], .string("key-attestation-jwt"))
        XCTAssertEqual(wmpProof, legacyProof, "the two transports must serialise a proof identically")
    }

    /// A backend reading the legacy shape must tolerate the member being
    /// absent, which is what every deployed wallet sends today.
    func testAnOlderWalletsMessageStillDecodes() throws {
        let fromDeployedWallet = #"{"type":"sign_response","flow_id":"f1","proofs":[{"proof_type":"jwt","jwt":"t"}]}"#
        let decoded = try JSONDecoder().decode(SignResponseMessage.self, from: Data(fromDeployedWallet.utf8))
        XCTAssertNil(decoded.credentialRequestExtras)
        XCTAssertEqual(decoded.flowId, "f1")
    }

    /// The bag survives a round trip through the legacy encoding intact,
    /// nested array and all - the shape the BBS fields actually take.
    func testTheExtrasRoundTripThroughTheLegacyEncoding() throws {
        let data = try JSONEncoder().encode(SignResponseMessage(flowId: "f1", credentialRequestExtras: extras))
        let decoded = try JSONDecoder().decode(SignResponseMessage.self, from: data)
        XCTAssertEqual(decoded.credentialRequestExtras, extras)
    }
}
