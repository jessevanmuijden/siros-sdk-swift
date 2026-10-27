// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

// The bridge to the UniFFI callback and error types exists on iOS only (the XCFramework has no other slice).
#if os(iOS)
import siros_wscd_managerFFI

/// `AuthCallbackBridge.requestNewPin`, the `FfiWscdError.Pin` classification and `withPinRecovery`, driven by a
/// fake app. No authenticator and no hardware: this is the SDK's bridge code only.
final class UniFFIPinBridgeTests: XCTestCase {

    private final class FakeProvider: WscdAuthProvider, @unchecked Sendable {
        private let lock = NSLock()
        private var answers: [String?]
        private(set) var requests: [PinRequest] = []
        init(_ answers: [String?]) { self.answers = answers }
        func requestPin(pluginId: String) throws -> Data { try requestPin(pluginId: pluginId, request: PinRequest(kind: .enterPin)) }
        func requestPin(pluginId: String, request: PinRequest) throws -> Data {
            lock.lock(); defer { lock.unlock() }
            requests.append(request)
            guard !answers.isEmpty, let answer = answers.removeFirst() else { throw PinPromptCancelled() }
            return Data(answer.utf8)
        }
        func requestWebauthnAssertion(pluginId: String, challenge: Data, rpId: String, allowedCredentials: [Data]) throws -> Data {
            throw PinPromptCancelled()
        }
    }

    func testRequestNewPinChoosesConfirmsAndReturnsTheSamePin() throws {
        let provider = FakeProvider(["12", "123456", "123456"])
        let bridge = AuthCallbackBridge(provider: provider)
        let pin = try bridge.requestNewPin(pluginId: "fido2", minLength: 6)
        XCTAssertEqual(pin, Data("123456".utf8))
        XCTAssertEqual(provider.requests.map(\.kind), [.setNewPin(minLength: 6), .setNewPin(minLength: 6), .confirmNewPin])
        XCTAssertEqual(provider.requests[1].retry, .tooShort(minLength: 6))
    }

    func testRequestPinAsksToEnterTheExistingPinAndCarriesAnOperationRetryOnce() throws {
        let provider = FakeProvider(["1234", "1234"])
        let bridge = AuthCallbackBridge(provider: provider)
        bridge.setNextPromptRetry(.wrongPin)
        _ = try bridge.requestPin(pluginId: "fido2")
        _ = try bridge.requestPin(pluginId: "fido2")
        XCTAssertEqual(provider.requests.map(\.kind), [.enterPin, .enterPin])
        XCTAssertEqual(provider.requests[0].retry, .wrongPin)
        XCTAssertNil(provider.requests[1].retry, "the retry reason is consumed by the first prompt")
    }

    func testCancellingTheNewPinPromptIsAnAuthCancelled() {
        // The bridge holds its provider weakly: retain it, and assert it WAS asked, so the cancel is the user's and
        // not the "No AuthProvider configured" guard's.
        let provider = FakeProvider([nil])
        let bridge = AuthCallbackBridge(provider: provider)
        XCTAssertThrowsError(try bridge.requestNewPin(pluginId: "fido2", minLength: 4)) { error in
            guard case let FfiWscdError.AuthCancelled(msg) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(msg, "the user cancelled the PIN prompt")
        }
        XCTAssertEqual(provider.requests.map(\.kind), [.setNewPin(minLength: 4)], "the provider received the new-PIN request")
    }

    func testRunningOutOfNewPinAttemptsIsRecordedAndReplacesTheGenericCancel() throws {
        let provider = FakeProvider(["1", "1", "1"])          // the signer holds its provider weakly: keep it alive
        let signer = try UniFFISigner(config: FfiWscdConfig(defaultPlugin: "softkey"), authProvider: provider)
        XCTAssertThrowsError(try signer.withPinRecovery { bridge in
            try bridge.requestNewPin(pluginId: "fido2", minLength: 4)
        }) { XCTAssertEqual($0 as? WscdPinError, .tooManyAttempts) }
    }

    /// The library surfaces a failing callback as `FfiWscdError.Callback`, not as the `AuthCancelled` the bridge
    /// threw: the error the bridge recorded must still win.
    func testTheRecordedPinErrorSurvivesTheLibrarysCallbackWrapper() throws {
        let provider = FakeProvider(["1", "1", "1"])
        let signer = try UniFFISigner(config: FfiWscdConfig(defaultPlugin: "softkey"), authProvider: provider)
        XCTAssertThrowsError(try signer.withPinRecovery { bridge -> Int in
            do { _ = try bridge.requestNewPin(pluginId: "fido2", minLength: 4) } catch {}
            throw FfiWscdError.Callback(msg: "callback failed")      // what the Rust bridge reports after the callback gave up
        }) { XCTAssertEqual($0 as? WscdPinError, .tooManyAttempts) }
    }

    func testEveryFfiPinFailureIsClassified() {
        func classify(_ reason: FfiPinFailure) -> PinFailureReason? {
            UniFFISigner.classifyPinFailure(FfiWscdError.Pin(reason: reason, msg: ""))
        }
        XCTAssertEqual(classify(.tooShort(minLength: 6)), .tooShort(minLength: 6))
        XCTAssertEqual(classify(.tooLong), .tooLong)
        XCTAssertEqual(classify(.invalidEncoding), .invalidEncoding)
        XCTAssertEqual(classify(.policyViolation), .policyViolation)
        XCTAssertEqual(classify(.invalid), .invalid)
        XCTAssertEqual(classify(.blocked), .blocked)
        XCTAssertEqual(classify(.authBlocked), .authBlocked)
        XCTAssertEqual(classify(.notSet), .notSet)
        XCTAssertNil(UniFFISigner.classifyPinFailure(FfiWscdError.AuthCancelled(msg: "x")), "not a PIN failure")
    }

    func testAWrongPinRerunsTheOperationAndTheNextPromptSaysSo() throws {
        let provider = FakeProvider(["0000", "1234"])
        let signer = try UniFFISigner(config: FfiWscdConfig(defaultPlugin: "softkey"), authProvider: provider)
        var runs = 0
        let result: String = try signer.withPinRecovery { bridge in
            runs += 1
            _ = try bridge.requestPin(pluginId: "fido2")
            if runs == 1 { throw FfiWscdError.Pin(reason: .invalid, msg: "") }
            return "signed"
        }
        XCTAssertEqual(result, "signed")
        XCTAssertEqual(provider.requests.map(\.retry), [nil, .wrongPin])
    }

    func testAFormatRefusalOfTheTypedPinAsksToEnterAgainWithANotAcceptedNotice() throws {
        let provider = FakeProvider(["12", "1234"])
        let signer = try UniFFISigner(config: FfiWscdConfig(defaultPlugin: "softkey"), authProvider: provider)
        var runs = 0
        _ = try signer.withPinRecovery { bridge -> Int in
            runs += 1
            _ = try bridge.requestPin(pluginId: "fido2")
            if runs == 1 { throw FfiWscdError.Pin(reason: .tooShort(minLength: 4), msg: "") }
            return 1
        }
        XCTAssertEqual(provider.requests.map(\.kind), [.enterPin, .enterPin])
        XCTAssertEqual(provider.requests.map(\.retry), [nil, .notAccepted])
    }

    func testAnErrorOfTheHostsOwnTypeFromAPromptBecomesACancelledAuthentication() {
        let provider = FakeProvider([nil])      // throws PinPromptCancelled, not an FfiWscdError
        let bridge = AuthCallbackBridge(provider: provider)
        XCTAssertThrowsError(try bridge.requestPin(pluginId: "fido2")) { error in
            guard case FfiWscdError.AuthCancelled = error else { return XCTFail("\(error)") }
        }
        XCTAssertEqual(provider.requests.count, 1)
    }

    func testAnScaRetryPromptCarriesTheWrongPinNoticeAndTheTypedPinIsServedOnce() throws {
        let provider = FakeProvider(["5678"])
        let callback = OneShotPinAuthCallback(pin: nil, retry: .wrongPin, fallback: provider)
        XCTAssertEqual(try callback.requestPin(pluginId: "fido2"), Data("5678".utf8))
        XCTAssertEqual(provider.requests.map(\.retry), [.wrongPin])
        XCTAssertFalse(callback.promptFailed)
        let cancelled = OneShotPinAuthCallback(pin: nil, fallback: FakeProvider([nil]))
        XCTAssertThrowsError(try cancelled.requestPin(pluginId: "fido2"))
        XCTAssertTrue(cancelled.promptFailed)
    }

    func testABlockedKeyEndsTheOperationWithAClearError() throws {
        let provider = FakeProvider([])
        let signer = try UniFFISigner(config: FfiWscdConfig(defaultPlugin: "softkey"), authProvider: provider)
        XCTAssertThrowsError(try signer.withPinRecovery { _ -> Int in
            throw FfiWscdError.Pin(reason: .blocked, msg: "")
        }) { XCTAssertEqual($0 as? WscdPinError, .keyBlocked) }
    }

    func testAnScaSignNeverSetsAPin() {
        let callback = OneShotPinAuthCallback(pin: Data("1234".utf8), fallback: nil)
        XCTAssertThrowsError(try callback.requestNewPin(pluginId: "fido2", minLength: 4)) { error in
            guard case FfiWscdError.AuthCancelled = error else { return XCTFail("\(error)") }
        }
    }
}
#endif
