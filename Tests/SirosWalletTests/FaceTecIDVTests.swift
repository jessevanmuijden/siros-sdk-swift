// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Records the requests a fake facetec-api saw and answers from a script.
private final class FakeFacetecApi: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var requests: [URLRequest] = []
    private var answers: [(status: Int, body: String)]

    init(_ answers: [(status: Int, body: String)]) {
        self.answers = answers
    }

    var transport: FaceTecProcessRequestClient.Transport {
        { [self] request in
            lock.lock()
            requests.append(request)
            let answer = answers.isEmpty ? (status: 200, body: #"{"responseBlob":"r"}"#) : answers.removeFirst()
            lock.unlock()
            let response = HTTPURLResponse(url: request.url!, statusCode: answer.status, httpVersion: nil, headerFields: nil)!
            return (Data(answer.body.utf8), response)
        }
    }

    func body(_ index: Int) throws -> [String: Any] {
        let data = try XCTUnwrap(requests[index].httpBody)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }
}

private let config = FaceTecIDVConfig(
    processRequestUrl: URL(string: "https://idv.example.com/v1/process-request")!,
    authToken: "Bearer secret-token",
    deviceKeyIdentifier: "dev-key"
)

final class FaceTecProcessRequestClientTests: XCTestCase {

    func testPostsBlobAndRefIdWithAuthHeader() async throws {
        let api = FakeFacetecApi([(200, #"{"responseBlob":"resp"}"#)])
        let client = FaceTecProcessRequestClient(config: config, transport: api.transport)

        let response = try await client.post(requestBlob: "blob-1", externalDatabaseRefID: "ref-1")

        XCTAssertEqual(response.responseBlob, "resp")
        XCTAssertEqual(api.requests.count, 1)
        let request = api.requests[0]
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url, config.processRequestUrl)
        XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer secret-token")
        XCTAssertEqual(request.value(forHTTPHeaderField: "Content-Type"), "application/json")
        let body = try api.body(0)
        XCTAssertEqual(body["requestBlob"] as? String, "blob-1")
        XCTAssertEqual(body["externalDatabaseRefID"] as? String, "ref-1")
    }

    func testReadsOfferAndRefusalFields() async throws {
        let api = FakeFacetecApi([
            (200, #"{"responseBlob":"a","credentialOfferURI":"openid-credential-offer://?x=1","transactionId":"tx"}"#),
            (200, #"{"responseBlob":"b","credentialIssueErrorCode":"chip_untrusted","credentialIssueError":"chip not trusted"}"#),
        ])
        let client = FaceTecProcessRequestClient(config: config, transport: api.transport)

        let issued = try await client.post(requestBlob: "x", externalDatabaseRefID: "r")
        XCTAssertEqual(issued.credentialOfferURI, "openid-credential-offer://?x=1")
        XCTAssertEqual(issued.transactionId, "tx")
        XCTAssertNil(issued.credentialIssueErrorCode)

        let refused = try await client.post(requestBlob: "x", externalDatabaseRefID: "r")
        XCTAssertNil(refused.credentialOfferURI)
        XCTAssertEqual(refused.credentialIssueErrorCode, "chip_untrusted")
        XCTAssertEqual(refused.credentialIssueError, "chip not trusted")
    }

    func testEmptyNullAndBlankFieldsAreAbsent() async throws {
        let api = FakeFacetecApi([
            (200, #"{"responseBlob":"a","credentialOfferURI":"","transactionId":null,"credentialIssueErrorCode":"  "}"#),
        ])
        let client = FaceTecProcessRequestClient(config: config, transport: api.transport)

        let response = try await client.post(requestBlob: "x", externalDatabaseRefID: "r")

        XCTAssertNil(response.credentialOfferURI)
        XCTAssertNil(response.transactionId)
        XCTAssertNil(response.credentialIssueErrorCode)
    }

    func testHttpErrorDoesNotEchoTheBody() async {
        let api = FakeFacetecApi([(502, "echoed requestBlob SECRET-BLOB")])
        let client = FaceTecProcessRequestClient(config: config, transport: api.transport)

        do {
            _ = try await client.post(requestBlob: "SECRET-BLOB", externalDatabaseRefID: "r")
            XCTFail("expected a failure")
        } catch let failure as ProcessRequestFailure {
            XCTAssertEqual(failure, .httpStatus(502))
            XCTAssertFalse(failure.description.contains("SECRET-BLOB"))
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testBodyThatIsNotJsonOrLacksResponseBlobFails() async {
        for (body, expected) in [("not json", ProcessRequestFailure.notJson),
                                 (#"{"credentialOfferURI":"x"}"#, .noResponseBlob),
                                 (#"{"responseBlob":""}"#, .noResponseBlob)] {
            let api = FakeFacetecApi([(200, body)])
            let client = FaceTecProcessRequestClient(config: config, transport: api.transport)
            do {
                _ = try await client.post(requestBlob: "x", externalDatabaseRefID: "r")
                XCTFail("expected a failure for \(body)")
            } catch {
                XCTAssertEqual(error as? ProcessRequestFailure, expected)
            }
        }
    }

    func testConfigDescriptionLeavesOutTheToken() {
        XCTAssertFalse(config.description.contains("secret-token"))
        XCTAssertTrue(config.description.contains("<redacted>"))
        XCTAssertTrue("\(config)".contains("dev-key"))
    }
}

/// The contract facetec-api v0.16.0 holds clients to: one `externalDatabaseRefID`
/// per FaceTec session, on every request of it, and a new one for each session.
final class FaceTecSessionRelayTests: XCTestCase {

    private func relay(_ api: FakeFacetecApi) -> FaceTecSessionRelay {
        let client = FaceTecProcessRequestClient(config: config, transport: api.transport)
        return FaceTecSessionRelay { blob, refID in
            try await client.post(requestBlob: blob, externalDatabaseRefID: refID)
        }
    }

    func testEveryRequestOfASessionCarriesTheSameRefId() async throws {
        let api = FakeFacetecApi([])
        let session = relay(api)

        // Liveness step, a retry of it, then the final match: four requests.
        for blob in ["liveness", "liveness-retry", "idscan", "match"] {
            let answer = await session.onSessionRequest(blob)
            XCTAssertEqual(answer, "r")
        }

        XCTAssertEqual(api.requests.count, 4)
        let ids = try (0..<4).map { try XCTUnwrap(api.body($0)["externalDatabaseRefID"] as? String) }
        XCTAssertEqual(Set(ids), [session.externalDatabaseRefID])
        XCTAssertFalse(session.externalDatabaseRefID.isEmpty)
    }

    func testEachSessionGetsItsOwnRefId() async throws {
        let api = FakeFacetecApi([])
        let first = relay(api)
        let second = relay(api)

        _ = await first.onSessionRequest("a")
        _ = await second.onSessionRequest("b")

        XCTAssertNotEqual(first.externalDatabaseRefID, second.externalDatabaseRefID)
        XCTAssertEqual(try api.body(0)["externalDatabaseRefID"] as? String, first.externalDatabaseRefID)
        XCTAssertEqual(try api.body(1)["externalDatabaseRefID"] as? String, second.externalDatabaseRefID)
        XCTAssertTrue(first.externalDatabaseRefID.hasPrefix("siros-sdk-ios-"))
    }

    func testOfferFromAnEarlierRequestIsKept() async {
        let api = FakeFacetecApi([
            (200, #"{"responseBlob":"a","credentialOfferURI":"openid-credential-offer://?o=1","transactionId":"tx"}"#),
            (200, #"{"responseBlob":"b"}"#),
        ])
        let session = relay(api)

        _ = await session.onSessionRequest("one")
        _ = await session.onSessionRequest("two")

        XCTAssertEqual(session.credentialOfferURI, "openid-credential-offer://?o=1")
        XCTAssertEqual(session.transactionId, "tx")
    }

    func testTransportFailureIsReadableThroughTheIdvError() async {
        let session = relay(FakeFacetecApi([(503, "echoed SECRET-BLOB")]))
        _ = await session.onSessionRequest("SECRET-BLOB")

        XCTAssertThrowsError(try sessionOutcome(status: .requestAborted, relay: session)) { error in
            XCTAssertEqual(
                (error as? IDVError)?.errorDescription,
                "Network error during IDV: process-request failed with HTTP 503"
            )
        }
    }

    func testTransportFailureAbortsTheSessionAndKeepsTheCause() async {
        let api = FakeFacetecApi([(503, "")])
        let session = relay(api)

        let answer = await session.onSessionRequest("one")

        XCTAssertNil(answer, "nil means abortOnCatastrophicError")
        XCTAssertEqual(session.transportError as? ProcessRequestFailure, .httpStatus(503))
    }
}

final class FaceTecSessionOutcomeTests: XCTestCase {

    private func relay(answering body: String?) async -> FaceTecSessionRelay {
        let session = FaceTecSessionRelay { _, _ in
            guard let body else { throw URLError(.notConnectedToInternet) }
            let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(body.utf8)) as? [String: String])
            return ProcessRequestResponse(
                responseBlob: "r",
                credentialOfferURI: json["offer"],
                transactionId: json["tx"],
                credentialIssueErrorCode: json["code"],
                credentialIssueError: json["msg"]
            )
        }
        _ = await session.onSessionRequest("x")
        return session
    }

    func testIssuedCredentialWinsOverSessionStatus() async throws {
        let session = await relay(answering: #"{"offer":"openid-credential-offer://?o=1","tx":"t1"}"#)

        let result = try sessionOutcome(status: .requestAborted, relay: session)

        XCTAssertEqual(result, IDVResult(credentialOfferURI: "openid-credential-offer://?o=1", transactionId: "t1"))
    }

    func testRefusalWinsOverSessionStatus() async {
        let session = await relay(answering: #"{"code":"document_expired","msg":"document has expired"}"#)

        XCTAssertThrowsError(try sessionOutcome(status: .sessionCompleted, relay: session)) { error in
            guard case let IDVError.documentExpired(message) = error else { return XCTFail("got \(error)") }
            XCTAssertEqual(message, "document has expired")
        }
    }

    func testSessionStatusesWithoutAnyAnswer() async {
        let session = await relay(answering: #"{}"#)
        func error(_ status: FaceTecSessionEnd?) -> IDVError? {
            do { _ = try sessionOutcome(status: status, relay: session); return nil } catch { return error as? IDVError }
        }

        XCTAssertEqual(error(.userCancelledFaceScan)?.errorCode, "idv_cancelled")
        XCTAssertEqual(error(.userCancelledIdScan)?.errorCode, "idv_cancelled")
        XCTAssertEqual(error(.cameraPermissionsDenied)?.errorCode, "idv_unavailable")
        XCTAssertEqual(error(.cameraError)?.errorCode, "idv_unavailable")
        XCTAssertEqual(error(.lockedOut)?.errorCode, "idv_provider_locked_out")
        XCTAssertEqual(error(.requestAborted)?.errorCode, "idv_provider_request_aborted")
        XCTAssertEqual(error(.sessionCompleted)?.errorCode, "idv_verification_failed")
        XCTAssertEqual(error(.unknownInternalError)?.errorCode, "idv_provider_unknown_internal_error")
        XCTAssertEqual(error(nil)?.errorCode, "idv_provider_no_session_result")
    }

    func testAbortAfterTransportFailureIsANetworkError() async {
        let session = await relay(answering: nil)

        XCTAssertThrowsError(try sessionOutcome(status: .requestAborted, relay: session)) { error in
            guard case IDVError.networkError = error else { return XCTFail("got \(error)") }
        }
    }

    /// Every code facetec-api returns to clients (v0.16.0, plus
    /// `chip_photo_mismatch` from sirosfoundation/facetec-api#78), and the typed
    /// error each becomes. siros-sdk-kotlin's `refusalToException` is the same.
    func testEveryFacetecApiCodeMapsToATypedError() {
        let expected: [(code: String, errorCode: String)] = [
            ("liveness_failed", "idv_liveness_failed"),
            ("match_failed", "idv_verification_failed"),
            ("document_unreadable", "idv_verification_failed"),
            ("policy_rejected", "idv_verification_failed"),
            ("nfc_skipped", "idv_nfc_skipped"),
            ("nfc_not_requested", "idv_nfc_not_requested"),
            ("nfc_device_not_capable", "idv_nfc_device_not_capable"),
            ("nfc_chip_read_failed", "idv_nfc_chip_read_failed"),
            ("nfc_not_authenticated", "idv_nfc_not_authenticated"),
            ("chip_untrusted", "idv_chip_untrusted"),
            ("chip_photo_mismatch", "idv_chip_photo_mismatch"),
            ("document_expired", "idv_document_expired"),
            ("session_expired", "idv_session_expired"),
            ("issuance_failed", "idv_provider_issuance_failed"),
            ("internal_error", "idv_provider_internal_error"),
            ("some_future_code", "idv_provider_some_future_code"),
        ]
        for (code, errorCode) in expected {
            let error = IDVError(refusalCode: code, message: "msg")
            XCTAssertEqual(error.errorCode, errorCode, code)
            XCTAssertEqual(error.errorDescription?.contains("msg"), true, code)
        }
    }

    func testRefusalWithoutMessageNamesTheCode() {
        XCTAssertEqual(IDVError(refusalCode: "chip_untrusted", message: nil).errorDescription,
                       "No credential was issued (chip_untrusted)")
    }
}

final class FaceTecSessionExitTests: XCTestCase {

    func testExitBeforeWaitIsNotLost() async {
        let exit = FaceTecSessionExit()
        exit.fire(.sessionCompleted)

        let end = await exit.wait()

        XCTAssertEqual(end, .sessionCompleted)
    }

    func testWaitBeforeExitIsWoken() async {
        let exit = FaceTecSessionExit()
        let waiting = Task { await exit.wait() }
        try? await Task.sleep(nanoseconds: 50_000_000)

        exit.fire(.userCancelledFaceScan)

        let end = await waiting.value
        XCTAssertEqual(end, .userCancelledFaceScan)
    }

    func testOnlyTheFirstExitCounts() async {
        let exit = FaceTecSessionExit()
        exit.fire(.userCancelledIdScan)
        exit.fire(.sessionCompleted)

        let end = await exit.wait()

        XCTAssertEqual(end, .userCancelledIdScan)
    }
}

final class ResumeOnceTests: XCTestCase {

    func testOnlyTheFirstClaimGetsThrough() {
        let once = ResumeOnce()

        XCTAssertTrue(once.claim())
        XCTAssertFalse(once.claim())
        XCTAssertFalse(once.claim())
    }
}

final class FaceTecIDVProviderAvailabilityTests: XCTestCase {

    #if !canImport(FaceTecSDK)
    func testUnavailableWithoutTheFaceTecSdk() async {
        let provider = FaceTecIDVProvider(config: config)

        let available = await provider.isAvailable()
        XCTAssertFalse(available)
        XCTAssertEqual(provider.name, "FaceTec")
        do {
            _ = try await provider.startVerification(presentingViewController: "not a view controller")
            XCTFail("expected unavailable")
        } catch let error as IDVError {
            XCTAssertEqual(error.errorCode, "idv_unavailable")
        } catch {
            XCTFail("unexpected \(error)")
        }
    }
    #endif
}

@available(*, deprecated)
final class FaceTecCaptureDelegateTests: XCTestCase {

    /// The FaceTec 9 delegate is retired: it must say so rather than pretend.
    func testDeprecatedDelegateIsNeverAvailable() async {
        let delegate = FaceTecCaptureDelegate()

        let available = await delegate.isAvailable()
        XCTAssertFalse(available)
        do {
            _ = try await delegate.captureLiveness(presentingViewController: "vc", sessionToken: "t")
            XCTFail("expected unavailable")
        } catch let error as IDVError {
            XCTAssertEqual(error.errorCode, "idv_unavailable")
        } catch {
            XCTFail("unexpected \(error)")
        }
    }
}
