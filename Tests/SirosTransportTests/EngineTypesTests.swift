// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosTransport

final class EngineTypesTests: XCTestCase {
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    func testHandshakeMessageEncoding() throws {
        let msg = HandshakeMessage(appToken: "test-token")
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"handshake\""))
        XCTAssertTrue(text.contains("\"app_token\":\"test-token\""))
    }

    func testFlowStartIssuanceEncoding() throws {
        let msg = FlowStartMessage(
            protocol: "oid4vci",
            offer: "offer-json",
            credentialOfferUri: "https://issuer.example.com/offer",
            redirectUri: "app://callback"
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"flow_start\""))
        XCTAssertTrue(text.contains("\"protocol\":\"oid4vci\""))
        XCTAssertTrue(text.contains("\"offer\":\"offer-json\""))
        XCTAssertTrue(text.contains("credential_offer_uri"))
        XCTAssertTrue(text.contains("issuer.example.com"))
        XCTAssertTrue(text.contains("redirect_uri"))
    }

    /// The SDK no longer pre-supplies wallet attestation on FlowStart (it
    /// answers the engine's `request_attestation` sign request instead), so
    /// the plain issuance FlowStart must not carry - not even as `null` -
    /// the `client_attestation*` keys the engine treats as "already
    /// attested, don't ask".
    func testFlowStartIssuanceOmitsClientAttestationByDefault() throws {
        let msg = FlowStartMessage(
            protocol: "oid4vci",
            credentialOfferUri: "https://issuer.example.com/offer/1",
            redirectUri: "https://wallet.example.com/cb"
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"credential_offer_uri\""))
        XCTAssertFalse(text.contains("client_attestation"))
        XCTAssertFalse(text.contains("client_attestation_pop"))
    }

    /// `sign_client_auth` reply (go-wallet-backend#317): the key identifier,
    /// DPoP proof and fresh attestation ride on the sign_response under the
    /// backend's `SignResponseMessage` wire names.
    func testSignResponseEncodesClientAuthMembers() throws {
        let msg = SignResponseMessage(
            flowId: "flow-77",
            messageId: "msg-9",
            clientAttestation: "wia-jwt",
            clientAttestationPoP: "pop-jwt",
            dpopKeyId: "instance-key-1",
            dpopProof: "dpop-jwt"
        )
        let text = String(data: try encoder.encode(msg), encoding: .utf8)!
        XCTAssertTrue(text.contains("\"dpop_key_id\":\"instance-key-1\""))
        XCTAssertTrue(text.contains("\"dpop_proof\":\"dpop-jwt\""))
        XCTAssertTrue(text.contains("\"client_attestation\":\"wia-jwt\""))
        XCTAssertTrue(text.contains("\"client_attestation_pop\":\"pop-jwt\""))

        // Absent members stay off the wire, as for every other optional.
        let bare = String(data: try encoder.encode(SignResponseMessage(flowId: "f", messageId: "m")), encoding: .utf8)!
        XCTAssertFalse(bare.contains("dpop_key_id"))
        XCTAssertFalse(bare.contains("dpop_proof"))
    }

    /// The engine's `sign_client_auth` params decode under their wire names.
    func testSignRequestDecodesClientAuthParams() throws {
        let json = """
        {"type":"sign_request","flow_id":"f","message_id":"m","action":"sign_client_auth",
         "params":{"audience":"https://as.example.com","issuer":"siros-sample://callback",
                   "htm":"POST","htu":"https://as.example.com/token","dpop_nonce":"n-1","ath":"h","key_id":"k-1"}}
        """
        let msg = try JSONDecoder().decode(SignRequestMessage.self, from: Data(json.utf8))
        XCTAssertEqual(msg.action, "sign_client_auth")
        XCTAssertEqual(msg.params.htm, "POST")
        XCTAssertEqual(msg.params.htu, "https://as.example.com/token")
        XCTAssertEqual(msg.params.dpopNonce, "n-1")
        XCTAssertEqual(msg.params.ath, "h")
        XCTAssertEqual(msg.params.keyId, "k-1")
        XCTAssertEqual(msg.params.audience, "https://as.example.com")
        XCTAssertEqual(msg.params.issuer, "siros-sample://callback")
    }

    /// A renewal names the client-held key the refresh_token is bound to,
    /// and `flow_complete` is where that name arrives.
    func testRenewalCarriesDpopKeyId() throws {
        let start = FlowStartMessage(protocol: "oid4vci", refreshToken: "rt", credentialIssuer: "https://issuer.example.com",
                                     selectedCredentialConfigurationId: "pid", dpopKeyId: "instance-key-1")
        let text = String(data: try encoder.encode(start), encoding: .utf8)!
        XCTAssertTrue(text.contains("\"dpop_key_id\":\"instance-key-1\""))
        XCTAssertFalse(text.contains("dpop_jwk"))

        let complete = """
        {"type":"flow_complete","flow_id":"f","refresh_token":"rt","dpop_key_id":"instance-key-1"}
        """
        let msg = try JSONDecoder().decode(FlowCompleteMessage.self, from: Data(complete.utf8))
        XCTAssertEqual(msg.refreshToken, "rt")
        XCTAssertEqual(msg.dpopKeyId, "instance-key-1")
        XCTAssertNil(msg.dpopJwk)
    }

    func testFlowStartPresentationEncoding() throws {
        let msg = FlowStartMessage(
            protocol: "oid4vp",
            requestUri: "https://verifier.example.com/request",
            requestUriRef: "urn:request:1"
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"protocol\":\"oid4vp\""))
        XCTAssertTrue(text.contains("request_uri"))
        XCTAssertTrue(text.contains("verifier.example.com"))
        XCTAssertTrue(text.contains("\"request_uri_ref\":\"urn:request:1\""))
    }

    func testSignResponseEncoding() throws {
        let msg = SignResponseMessage(
            flowId: "flow-77",
            proofJwt: "proof-jwt",
            vpToken: "vp-token",
            proofs: [ProofObject(proofType: "jwt", jwt: "nested-proof")]
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"sign_response\""))
        XCTAssertTrue(text.contains("\"flow_id\":\"flow-77\""))
        XCTAssertTrue(text.contains("\"proof_jwt\":\"proof-jwt\""))
        XCTAssertTrue(text.contains("\"vp_token\":\"vp-token\""))
        XCTAssertTrue(text.contains("\"proof_type\":\"jwt\""))
    }

    /// `request_attestation` answers carry the WIA + PoP under exactly the
    /// wire names go-wallet-backend's `SignResponseMessage` decodes
    /// (`client_attestation` / `client_attestation_pop`).
    func testSignResponseEncodesClientAttestation() throws {
        let msg = SignResponseMessage(
            flowId: "flow-78",
            messageId: "msg-1",
            clientAttestation: "wia-jwt",
            clientAttestationPoP: "pop-jwt"
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"sign_response\""))
        XCTAssertTrue(text.contains("\"message_id\":\"msg-1\""))
        XCTAssertTrue(text.contains("\"client_attestation\":\"wia-jwt\""))
        XCTAssertTrue(text.contains("\"client_attestation_pop\":\"pop-jwt\""))
        XCTAssertFalse(text.contains("proof_jwt"))
        XCTAssertFalse(text.contains("vp_token"))
    }

    /// An empty response (the client declining an attestation request) must
    /// omit the attestation keys entirely - the backend treats absent and
    /// empty the same, but `null` would not round-trip through its
    /// `omitempty` string fields as cleanly.
    func testSignResponseOmitsAbsentClientAttestation() throws {
        let msg = SignResponseMessage(flowId: "flow-79", messageId: "msg-2")
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"flow_id\":\"flow-79\""))
        XCTAssertFalse(text.contains("client_attestation"))
        XCTAssertFalse(text.contains("client_attestation_pop"))
    }

    func testMatchResponseEncoding() throws {
        let msg = MatchResponseMessage(
            flowId: "flow-88",
            matches: [
                CredentialMatch(
                    credentialQueryId: "query-1",
                    credentialId: "cred-1",
                    format: "dc+sd-jwt",
                    vct: "urn:eu:pid:1",
                    availableClaims: ["given_name", "family_name"]
                ),
            ]
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"match_response\""))
        XCTAssertTrue(text.contains("\"flow_id\":\"flow-88\""))
        XCTAssertTrue(text.contains("\"credential_query_id\":\"query-1\""))
        XCTAssertTrue(text.contains("\"credential_id\":\"cred-1\""))
    }

    /// An empty match set is only half the answer - the reason is what says
    /// *which* credential the user is missing. It rides on the same message
    /// and must reach the wire under the backend's `no_match_reason` name.
    func testMatchResponseEncodesNoMatchReason() throws {
        let msg = MatchResponseMessage(
            flowId: "flow-89",
            matches: [],
            noMatchReason: "no stored credential matches the requested type(s): urn:eudi:pid:1"
        )
        let text = String(data: try encoder.encode(msg), encoding: .utf8)!

        XCTAssertTrue(text.contains("\"matches\":[]"))
        XCTAssertTrue(text.contains("\"no_match_reason\":\"no stored credential matches the requested type(s): urn:eudi:pid:1\""))
    }

    func testMatchResponseOmitsAbsentNoMatchReason() throws {
        let msg = MatchResponseMessage(
            flowId: "flow-90",
            matches: [CredentialMatch(credentialId: "cred-1", format: "dc+sd-jwt")]
        )
        let text = String(data: try encoder.encode(msg), encoding: .utf8)!

        XCTAssertFalse(text.contains("no_match_reason"))
    }

    /// The `credentials_matched` payload the engine parses as
    /// `CredentialsMatchedPayload` (go-wallet-backend #336). An empty
    /// `matches` is what ends a flow the wallet cannot satisfy, so the key
    /// must be present and empty - not omitted.
    func testCredentialsMatchedPayloadForEmptyMatchSet() throws {
        let payload = WalletEngineSession.credentialsMatchedPayload(
            matches: [],
            noMatchReason: "nothing to present"
        )

        XCTAssertEqual(payload["matches"], .array([]))
        XCTAssertEqual(payload["no_match_reason"], .string("nothing to present"))
    }

    func testCredentialsMatchedPayloadEncodesEachMatch() throws {
        let payload = WalletEngineSession.credentialsMatchedPayload(
            matches: [
                CredentialMatch(
                    credentialQueryId: "query-1",
                    credentialId: "7",
                    format: "mso_mdoc",
                    vct: "urn:eu:pid:1",
                    availableClaims: ["given_name"]
                ),
            ],
            noMatchReason: nil
        )

        XCTAssertNil(payload["no_match_reason"])
        guard case .array(let matches)? = payload["matches"], case .object_(let match)? = matches.first else {
            return XCTFail("Expected one encoded match")
        }
        XCTAssertEqual(match["credential_query_id"], .string("query-1"))
        XCTAssertEqual(match["credential_id"], .string("7"))
        XCTAssertEqual(match["format"], .string("mso_mdoc"))
        XCTAssertEqual(match["vct"], .string("urn:eu:pid:1"))
        XCTAssertEqual(match["available_claims"], .array([.string("given_name")]))
    }

    /// The engine's `NO_MATCHING_CREDENTIAL` error carries the two things an
    /// app needs to explain the failure; both live in `details`, which the
    /// SDK used to decode only far enough to find `redirect_uri`.
    func testFlowErrorDecodesNoMatchingCredentialDetails() throws {
        let json = """
        {"type":"flow_error","flow_id":"flow-1","step":"credential_selection","error":{\
        "code":"NO_MATCHING_CREDENTIAL","message":"This request needs a credential you do not have: urn:eudi:pid:1",\
        "details":{"requested_types":["urn:eudi:pid:1"],"no_match_reason":"wallet holds no PID",\
        "redirect_uri":"https://verifier.example/done"}}}
        """
        let msg = try decoder.decode(FlowErrorMessage.self, from: json.data(using: .utf8)!)

        XCTAssertEqual(msg.error.code, EngineErrorCodes.noMatchingCredential)
        XCTAssertEqual(msg.error.details?["requested_types"], .array([.string("urn:eudi:pid:1")]))
        XCTAssertEqual(msg.error.details?["no_match_reason"]?.stringValue, "wallet holds no PID")
        XCTAssertEqual(msg.error.details?["redirect_uri"]?.stringValue, "https://verifier.example/done")
    }

    func testFlowActionEncoding() throws {
        let msg = FlowActionMessage(
            flowId: "flow-77",
            action: "trust_result",
            payload: ["trusted": .bool(true), "reason": "verified"]
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"flow_action\""))
        XCTAssertTrue(text.contains("\"flow_id\":\"flow-77\""))
        XCTAssertTrue(text.contains("\"action\":\"trust_result\""))
        XCTAssertTrue(text.contains("\"trusted\":true"))
        XCTAssertTrue(text.contains("\"reason\":\"verified\""))
    }

    func testHandshakeCompleteDecoding() throws {
        let json = """
        {"type":"handshake_complete","session_id":"session-123","capabilities":["oid4vci","oid4vp"]}
        """
        let msg = try decoder.decode(HandshakeCompleteMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.sessionId, "session-123")
        XCTAssertEqual(msg.capabilities, ["oid4vci", "oid4vp"])
        XCTAssertNil(msg.config)
    }

    func testHandshakeCompleteDecodingWithConfig() throws {
        let json = """
        {"type":"handshake_complete","session_id":"session-123","config":{"ping_interval_ms":7000}}
        """
        let msg = try decoder.decode(HandshakeCompleteMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.config?.pingIntervalMs, 7000)
    }

    func testFlowProgressDecoding() throws {
        let json = """
        {"type":"flow_progress","flow_id":"flow-1","step":"issuing","payload":{"percent":50}}
        """
        let msg = try decoder.decode(FlowProgressMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.step, "issuing")
    }

    func testFlowCompleteDecoding() throws {
        let json = """
        {"type":"flow_complete","flow_id":"flow-1","redirect_uri":"https://wallet.example.com/callback","credentials":[{"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1"}]}
        """
        let msg = try decoder.decode(FlowCompleteMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.redirectUri, "https://wallet.example.com/callback")
        XCTAssertEqual(msg.credentials?.first?.credential, "jwt-token")
    }

    func testFlowErrorDecoding() throws {
        let json = """
        {"type":"flow_error","flow_id":"flow-1","step":"authorize","error":{"code":"invalid_request","message":"missing parameter"}}
        """
        let msg = try decoder.decode(FlowErrorMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.error.code, "invalid_request")
        XCTAssertEqual(msg.error.message, "missing parameter")
    }

    func testSignRequestDecoding() throws {
        let json = """
        {"type":"sign_request","flow_id":"flow-1","action":"proof","params":{"audience":"aud","nonce":"nonce","proof_type":"jwt"}}
        """
        let msg = try decoder.decode(SignRequestMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.action, "proof")
        XCTAssertEqual(msg.params.audience, "aud")
        XCTAssertEqual(msg.params.proofType, "jwt")
    }

    func testMatchRequestDecoding() throws {
        let json = """
        {"type":"match_request","flow_id":"flow-1","dcql_query":{"credentials":[{"id":"q-1"}]}}
        """
        let msg = try decoder.decode(MatchRequestMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertNotNil(msg.dcqlQuery)
    }

    func testPushMessageDecoding() throws {
        let json = """
        {"type":"push","push_type":"issuance_complete","credentials":[{"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1"}]}
        """
        let msg = try decoder.decode(PushMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.pushType, "issuance_complete")
        XCTAssertEqual(msg.credentials?.first?.credential, "jwt-token")
    }

    func testErrorMessageDecoding() throws {
        let json = """
        {"type":"error","code":"bad_request","message":"invalid flow"}
        """
        let msg = try decoder.decode(ErrorMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.code, "bad_request")
        XCTAssertEqual(msg.details, "invalid flow")
    }

    func testCredentialNotificationEncoding() throws {
        let msg = CredentialNotificationMessage(
            flowId: "flow-1",
            notificationId: "notif-abc",
            event: CredentialNotificationEvent.accepted,
            eventDescription: "stored",
            timestamp: "2026-06-22T00:00:00Z"
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"type\":\"credential_notification\""))
        XCTAssertTrue(text.contains("\"flow_id\":\"flow-1\""))
        XCTAssertTrue(text.contains("\"notification_id\":\"notif-abc\""))
        XCTAssertTrue(text.contains("\"event\":\"credential_accepted\""))
        XCTAssertTrue(text.contains("\"event_description\":\"stored\""))
    }

    func testCredentialNotificationOmitsOptionalDescription() throws {
        let msg = CredentialNotificationMessage(
            flowId: "flow-1",
            notificationId: "notif-abc",
            event: CredentialNotificationEvent.failure
        )
        let data = try encoder.encode(msg)
        let text = String(data: data, encoding: .utf8)!

        XCTAssertTrue(text.contains("\"event\":\"credential_failure\""))
        XCTAssertFalse(text.contains("event_description"))
    }

    func testNotificationAckDecoding() throws {
        let json = """
        {"type":"notification_ack","flow_id":"flow-1","notification_id":"notif-abc","status":"forwarded"}
        """
        let msg = try decoder.decode(NotificationAckMessage.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(msg.type, "notification_ack")
        XCTAssertEqual(msg.flowId, "flow-1")
        XCTAssertEqual(msg.notificationId, "notif-abc")
        XCTAssertEqual(msg.status, "forwarded")
        XCTAssertNil(msg.error)
    }

    func testCredentialResultNotificationIdRoundtrip() throws {
        let json = """
        {"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1","notification_id":"notif-xyz"}
        """
        let result = try decoder.decode(CredentialResult.self, from: json.data(using: .utf8)!)
        XCTAssertEqual(result.notificationId, "notif-xyz")

        let data = try encoder.encode(result)
        let text = String(data: data, encoding: .utf8)!
        XCTAssertTrue(text.contains("\"notification_id\":\"notif-xyz\""))
    }

    func testCredentialResultOmitsNilNotificationId() throws {
        let json = """
        {"format":"dc+sd-jwt","credential":"jwt-token","vct":"urn:eu:pid:1"}
        """
        let result = try decoder.decode(CredentialResult.self, from: json.data(using: .utf8)!)
        XCTAssertNil(result.notificationId)

        let data = try encoder.encode(result)
        let text = String(data: data, encoding: .utf8)!
        XCTAssertFalse(text.contains("notification_id"))
    }

    func testSendCredentialNotificationIsNoOpWhenNotConnected() {
        // A never-connected session must report disconnected and must not crash
        // when an automatic credential notification is attempted (the send is a
        // no-op rather than a preconditionFailure).
        let session = WalletEngineSession(baseUrl: "https://wallet.example.com", tenantId: "t")
        XCTAssertFalse(session.isConnected)
        session.sendCredentialNotification(
            flowId: "flow-1",
            notificationId: "notif-1",
            event: CredentialNotificationEvent.accepted
        )
    }

    // MARK: - Engine-blind issuance wire shapes

    func testSignRequestParamsDecodeTheResponseEncryptionAndDecryptMembers() throws {
        let generate = try JSONDecoder().decode(SignRequestParams.self, from: Data(#"""
        {"audience":"https://i.example","nonce":"n","credential_response_encryption":{"alg":"ECDH-ES+A256KW","enc":"A256GCM","required":true}}
        """#.utf8))
        XCTAssertEqual(generate.credentialResponseEncryption, CredentialResponseEncryptionRequest(alg: "ECDH-ES+A256KW", enc: "A256GCM", required: true))
        let decrypt = try JSONDecoder().decode(SignRequestParams.self, from: Data(#"{"jwe":"a.b.c.d.e","deferred":false}"#.utf8))
        XCTAssertEqual(decrypt.jwe, "a.b.c.d.e")
        XCTAssertEqual(decrypt.deferred, false)
        XCTAssertNil(decrypt.credentialResponseEncryption)
    }

    func testSignResponseCarriesOnlyWhatWasSet() throws {
        func object(_ m: SignResponseMessage) throws -> [String: Any] {
            try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(m)) as? [String: Any])
        }
        let jwk = ["kty": "EC", "crv": "P-256", "x": "X", "y": "Y", "use": "enc", "alg": "ECDH-ES"]
        let proof = try object(SignResponseMessage(flowId: "f", credentialResponseEncryptionJwk: jwk))
        XCTAssertEqual(proof["credential_response_encryption_jwk"] as? [String: String], jwk)
        XCTAssertNil(proof["transaction_id"])
        XCTAssertNil(proof["error"])
        let control = try object(SignResponseMessage(flowId: "f", transactionId: "tx", interval: 3))
        XCTAssertEqual(control["transaction_id"] as? String, "tx")
        XCTAssertEqual(control["interval"] as? Int, 3)
        XCTAssertNil(control["credential_response_encryption_jwk"])
        let failure = try object(SignResponseMessage(flowId: "f", error: "no", errorCode: "DECRYPT_FAILED"))
        XCTAssertEqual(failure["error_code"] as? String, "DECRYPT_FAILED")
        let plain = try object(SignResponseMessage(flowId: "f"))
        for member in ["credential_response_encryption_jwk", "transaction_id", "interval", "error", "error_code"] {
            XCTAssertNil(plain[member], member)
        }
    }

    func testFlowCompleteOfAnEncryptedResponseHasNoCredentialValues() throws {
        let message = try JSONDecoder().decode(FlowCompleteMessage.self, from: Data(#"""
        {"type":"flow_complete","flow_id":"f","credential_response_encrypted":true,
         "credentials":[{"format":"dc+sd-jwt","vct":"urn:eudi:pid:1"},{"format":"dc+sd-jwt"}]}
        """#.utf8))
        XCTAssertEqual(message.credentialResponseEncrypted, true)
        XCTAssertEqual(message.credentials?.count, 2)
        XCTAssertNil(message.credentials?.first?.credential)
        // A plain response still decodes as before.
        let plain = try JSONDecoder().decode(FlowCompleteMessage.self, from: Data(#"""
        {"type":"flow_complete","flow_id":"f","credentials":[{"format":"dc+sd-jwt","credential":"x.y.z"}]}
        """#.utf8))
        XCTAssertNil(plain.credentialResponseEncrypted)
        XCTAssertEqual(plain.credentials?.first?.credential, "x.y.z")
    }

    func testFlowCompleteKeepsOnlyDisplayAndClaimsOfCredentialMetadata() throws {
        let message = try JSONDecoder().decode(FlowCompleteMessage.self, from: Data(#"""
        {"type":"flow_complete","flow_id":"f","credentials":[{"format":"dc+sd-jwt","credential":"x.y.z"}],
         "credential_metadata":{
           "display":[{"name":"Nym","locale":"en"}],
           "claims":[{"path":["a"]}],
           "org.siros.secret_seed":{"org.siros.nym_auth":"00112233445566778899aabbccddeeff"},
           "x-other":{"k":1}}}
        """#.utf8))
        let metadata = try XCTUnwrap(message.credentialMetadata)
        XCTAssertEqual(metadata.display?.arrayValue?.first?.objectValue?["name"]?.stringValue, "Nym")
        XCTAssertNotNil(metadata.claims)
        // Nothing but display and claims is held, so nothing else can be logged or re-encoded from it.
        let reencoded = String(decoding: try JSONEncoder().encode(metadata), as: UTF8.self)
        XCTAssertFalse(reencoded.contains("secret_seed"))
        XCTAssertFalse(reencoded.contains("00112233445566778899aabbccddeeff"))
        XCTAssertFalse(reencoded.contains("x-other"))
        let whole = String(decoding: try JSONEncoder().encode(message), as: UTF8.self)
        XCTAssertFalse(whole.contains("00112233445566778899aabbccddeeff"))
    }

    func testCredentialMetadataOfTheWrongShapeNeverFailsTheFlow() throws {
        for raw in ["null", "[1]", "\"s\"", "7", #"{"display":"not an array","claims":3}"#, "{}"] {
            let message = try JSONDecoder().decode(
                FlowCompleteMessage.self,
                from: Data(#"{"type":"flow_complete","flow_id":"f","credential_metadata":\#(raw)}"#.utf8)
            )
            if !raw.hasPrefix("{") {
                XCTAssertNil(message.credentialMetadata?.display, raw)
                XCTAssertNil(message.credentialMetadata?.claims, raw)
            }
        }
        let absent = try JSONDecoder().decode(FlowCompleteMessage.self, from: Data(#"{"type":"flow_complete","flow_id":"f"}"#.utf8))
        XCTAssertNil(absent.credentialMetadata)
    }

    // MARK: - Engine-blind presentation wire shapes

    func testSignPresentationParamsCarryTheResponseEncryptionStateAndVerifiedRequest() throws {
        let params = try JSONDecoder().decode(SignRequestParams.self, from: Data(#"""
        {"audience":"a","nonce":"n","state":"st",
         "response_encryption":{"jwk":{"kty":"EC","crv":"P-256","x":"X","y":"Y","kid":"k1"},"alg":"ECDH-ES","enc":"A128GCM"},
         "verified_request":{"client_id":"x509_san_dns:v.example","client_id_scheme":"x509_san_dns","response_mode":"direct_post.jwt",
                             "response_uri":"https://v.example/cb","signed":true,"signature_verification":"verified"}}
        """#.utf8))
        XCTAssertEqual(params.state, "st")
        XCTAssertEqual(params.responseEncryption?.alg, "ECDH-ES")
        XCTAssertEqual(params.responseEncryption?.enc, "A128GCM")
        XCTAssertEqual(params.responseEncryption?.jwkStrings["kid"], "k1")
        XCTAssertEqual(params.verifiedRequest?.clientId, "x509_san_dns:v.example")
        XCTAssertEqual(params.verifiedRequest?.signed, true)
        let plain = try JSONDecoder().decode(SignRequestParams.self, from: Data(#"{"audience":"a","nonce":"n"}"#.utf8))
        XCTAssertNil(plain.responseEncryption)
        XCTAssertNil(plain.state)
        XCTAssertNil(plain.verifiedRequest)
    }

    func testAResponseJweIsSentWithNoVpToken() throws {
        let object = try XCTUnwrap(JSONSerialization.jsonObject(
            with: JSONEncoder().encode(SignResponseMessage(flowId: "f", responseJwe: "a..b.c.d"))
        ) as? [String: Any])
        XCTAssertEqual(object["response_jwe"] as? String, "a..b.c.d")
        XCTAssertNil(object["vp_token"])
        XCTAssertNil(object["error"])
    }

    /// Losing a connection tells the owner once, before a replacement is attempted, so what it keeps for the flows
    /// that ran on the old socket can go. A session that was told to disconnect says nothing, even when a late
    /// failure from its old socket arrives after a replacement session has begun.
        /// A loss tells the owner EVERY time, not only the first (the attempt counter is not reset by a successful
    /// reconnect), and opening the replacement socket does too, so a path that bumps the connection without a state
    /// change still drops the old flows' state. The first socket is not a replacement.
        /// Each loss tells the owner, not only the first: the attempt counter is not reset by a successful reconnect.
        /// A recovered connection starts a fresh retry budget: after the budget was used up once and the socket
    /// recovered (`handshake_complete`), the next loss reconnects again instead of failing at once.
        /// A failure reported by a socket that has since been replaced (forceReconnect) says nothing about the current
    /// one: it neither tells the owner nor schedules a reconnect.
        /// A frame a replaced socket delivers late (its receive succeeded just before `forceReconnect`) is dropped before
    /// dispatch, and a request received on the current socket is stamped with that socket's generation.
        /// A request received on a LOST socket is obsolete from the loss itself: the generation advances at once (during the
    /// backoff) and again on every further loss, including when the retry budget is exhausted and no replacement
    /// ever opens, so a request stamped before the loss never matches the current generation.
        }
