// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class CredentialResponseMetadataTests: XCTestCase {

    private let seed = "00112233445566778899aabbccddeeff"

    private func complete(_ extra: String) -> Data {
        Data("""
        {"type":"flow_complete","flow_id":"f1",
         "credentials":[{"format":"dc+sd-jwt","credential":"eyJ.x.y~","notification_id":"n-1"}]\(extra)}
        """.utf8)
    }

    func testObjectIsKeptVerbatimWithUnknownMembers() throws {
        let json = complete(#","credential_metadata":{"display":[{"name":"Nym"}],"org.siros.secret_seed":{"org.siros.nym_auth":"\#(seed)"},"x-future":{"n":[1,2.5,null,true]}},"credential_metadata_encrypted_response":true"#)
        let msg = try JSONDecoder().decode(FlowCompleteMessage.self, from: json)
        let meta = try XCTUnwrap(msg.credentialMetadata)
        XCTAssertFalse(meta.isMalformed)
        XCTAssertEqual(Set(meta.members.keys), ["display", "org.siros.secret_seed", "x-future"])
        XCTAssertEqual(meta.members["org.siros.secret_seed"]?.objectValue?["org.siros.nym_auth"]?.stringValue, seed)
        XCTAssertEqual(meta.members["x-future"], ["n": [1, 2.5, nil, true]])
        XCTAssertEqual(msg.credentialMetadataEncryptedResponse?.value, true)
        XCTAssertEqual(msg.credentials?.first?.notificationId, "n-1")
    }

    func testAbsentMetadataIsNil() throws {
        let msg = try JSONDecoder().decode(FlowCompleteMessage.self, from: complete(""))
        XCTAssertNil(msg.credentialMetadata)
        XCTAssertNil(msg.credentialMetadataEncryptedResponse)
    }

    /// A malformed value must not drop the frame (the engine decodes with `try?`, so a throw
    /// would leave the issuance hanging); the credentials and their notification_id stay readable.
    func testMalformedValuesBecomeAPlaceholderAndTheFrameStillDecodes() throws {
        for malformed in ["[]", "[{\"type\":\"x\",\"value\":1}]", "\"str\"", "7", "true"] {
            let msg = try JSONDecoder().decode(FlowCompleteMessage.self, from: complete(",\"credential_metadata\":\(malformed)"))
            XCTAssertEqual(msg.credentialMetadata?.isMalformed, true, malformed)
            XCTAssertEqual(msg.credentialMetadata?.members.isEmpty, true, malformed)
            XCTAssertEqual(msg.credentials?.first?.notificationId, "n-1", malformed)
        }
    }

    func testEncryptedFlagIsLenientAndNeverTrueByAccident() throws {
        for bad in ["\"true\"", "1", "[]", "null", "{}"] {
            let msg = try JSONDecoder().decode(
                FlowCompleteMessage.self, from: complete(",\"credential_metadata\":{},\"credential_metadata_encrypted_response\":\(bad)"))
            XCTAssertNotEqual(msg.credentialMetadataEncryptedResponse?.value, true, bad)
        }
    }

    func testNothingPrintsOrEncodesTheSeed() throws {
        let json = complete(#","credential_metadata":{"org.siros.secret_seed":{"ns":"\#(seed)"}}"#)
        let msg = try JSONDecoder().decode(FlowCompleteMessage.self, from: json)
        let meta = try XCTUnwrap(msg.credentialMetadata)
        var dumped = ""
        dump(msg, to: &dumped)
        dump(meta, to: &dumped)
        let everything = [String(describing: meta), String(reflecting: meta), "\(meta)", dumped,
                          String(decoding: try JSONEncoder().encode(msg), as: UTF8.self),
                          String(decoding: try JSONEncoder().encode(meta), as: UTF8.self)]
        for text in everything { XCTAssertFalse(text.contains(seed), text) }
        XCTAssertEqual(String(decoding: try JSONEncoder().encode(meta), as: UTF8.self), "null")
    }

    // MARK: - WMP

    private func wmpResult(_ json: String) throws -> WmpFlowCompleteResult {
        let any = try JSONDecoder().decode(AnyCodable.self, from: Data(json.utf8))
        return try WmpFlowCompleteResult(result: any)
    }

    func testLiveWmpCompletionIsComplete() throws {
        let r = try wmpResult(#"""
        {"credentials":[{"format":"dc+sd-jwt","credential":"c","notification_id":"n"}],
         "credential_metadata":{"org.siros.secret_seed":{"ns":"\#(seed)"}},"credential_metadata_encrypted_response":true,
         "refresh_token":"rt","dpop_jwk":"{}","dpop_key_id":"k"}
        """#)
        XCTAssertNil(r.redactedMembers)
        XCTAssertFalse(r.credentialMetadataWithheld)
        XCTAssertFalse(r.renewalMaterialWithheld)
        XCTAssertEqual(r.refreshToken, "rt")
        XCTAssertEqual(r.credentialMetadata?.members.count, 1)
        XCTAssertFalse("\(r) \(String(reflecting: r))".contains(seed))
    }

    func testReplayedWmpCompletionNamesWhatWasWithheldAndKeepsTheCredentials() throws {
        let r = try wmpResult(#"""
        {"credentials":[{"format":"dc+sd-jwt","credential":"c","notification_id":"n"}],
         "redacted_members":["credential_metadata","credential_metadata_encrypted_response","dpop_jwk","refresh_token"]}
        """#)
        XCTAssertEqual(r.credentials?.count, 1)
        XCTAssertNil(r.credentialMetadata)
        XCTAssertNil(r.refreshToken)
        XCTAssertNil(r.dpopJwk)
        XCTAssertTrue(r.credentialMetadataWithheld)
        XCTAssertTrue(r.renewalMaterialWithheld)
        XCTAssertEqual(r.redactedMembers?.names, ["credential_metadata", "credential_metadata_encrypted_response", "dpop_jwk", "refresh_token"])
    }

    func testOnlyRenewalMaterialWithheldLeavesTheSeedAvailable() throws {
        let r = try wmpResult(#"{"credentials":[],"credential_metadata":{},"redacted_members":["dpop_key_id"]}"#)
        XCTAssertFalse(r.credentialMetadataWithheld)
        XCTAssertTrue(r.renewalMaterialWithheld)
    }

    func testMalformedWmpMembersDoNotFailTheFrame() throws {
        let r = try wmpResult(#"{"credentials":[],"credential_metadata":[1],"credential_metadata_encrypted_response":"yes","refresh_token":5,"redacted_members":"x"}"#)
        XCTAssertEqual(r.credentialMetadata?.isMalformed, true)
        XCTAssertNotEqual(r.credentialMetadataEncryptedResponse?.value, true)
        XCTAssertNil(r.refreshToken)
        XCTAssertEqual(r.redactedMembers?.names, [])
    }
}
