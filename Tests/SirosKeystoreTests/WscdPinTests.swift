// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosKeystore

/// The set-PIN flow's logic (choose, confirm, compare, enforce the minimum length, bounded re-prompts, the
/// per-reason handling of PIN failures) with a scripted prompt standing in for the app. No UniFFI types and no
/// hardware: this is the SDK-side logic only.
final class WscdPinTests: XCTestCase {

    /// A scripted "app": answers each prompt from a queue and records what it was asked.
    private final class ScriptedApp {
        private var answers: [String?]            // nil = the user cancels
        private(set) var requests: [PinRequest] = []
        init(_ answers: [String?]) { self.answers = answers }
        func ask(_ request: PinRequest) throws -> Data {
            requests.append(request)
            guard !answers.isEmpty, let answer = answers.removeFirst() else { throw PinPromptCancelled() }
            return Data(answer.utf8)
        }
    }

    private func choose(_ app: ScriptedApp, minLength: Int = 4, firstRetry: PinRetryReason? = nil) throws -> Data {
        try NewPinChooser(ask: app.ask).choose(minLength: minLength, firstRetry: firstRetry)
    }

    // MARK: NewPinChooser

    func testAsksTwiceAndReturnsThePinWhenBothEntriesMatch() throws {
        let app = ScriptedApp(["1234", "1234"])
        let pin = try choose(app)
        XCTAssertEqual(pin, Data("1234".utf8))
        XCTAssertEqual(app.requests.map(\.kind), [.setNewPin(minLength: 4), .confirmNewPin])
        XCTAssertNil(app.requests[0].retry)
    }

    func testAShortPinIsRefusedBeforeItIsConfirmedAndTheNextPromptSaysWhy() throws {
        let app = ScriptedApp(["12", "1234", "1234"])
        _ = try choose(app, minLength: 4)
        XCTAssertEqual(app.requests.map(\.kind), [.setNewPin(minLength: 4), .setNewPin(minLength: 4), .confirmNewPin],
                       "no confirmation prompt for a PIN that is too short")
        XCTAssertEqual(app.requests[1].retry, .tooShort(minLength: 4))
    }

    func testMismatchedEntriesAskForANewPinAgain() throws {
        let app = ScriptedApp(["1234", "1235", "5678", "5678"])
        let pin = try choose(app)
        XCTAssertEqual(pin, Data("5678".utf8))
        guard app.requests.count == 4 else { return XCTFail("expected 4 prompts, got \(app.requests.count)") }
        XCTAssertEqual(app.requests[2].retry, .mismatch)
        XCTAssertEqual(app.requests[2].kind, .setNewPin(minLength: 4))
    }

    func testTheNewPinPromptsAreBoundedAtThree() {
        let app = ScriptedApp(["12", "12", "12", "1234", "1234"])
        XCTAssertThrowsError(try choose(app)) { XCTAssertEqual($0 as? WscdPinError, .tooManyAttempts) }
        XCTAssertEqual(app.requests.count, WscdPinLimits.newPinEntries, "stops after the bound, never reaching the later valid entry")
    }

    func testCancellingAnyPromptPropagates() {
        XCTAssertThrowsError(try choose(ScriptedApp([nil]))) { XCTAssertTrue($0 is PinPromptCancelled) }
        XCTAssertThrowsError(try choose(ScriptedApp(["1234", nil]))) { XCTAssertTrue($0 is PinPromptCancelled) }
    }

    func testLengthIsCountedInCharactersAsTheAuthenticatorCountsThem() throws {
        // "e" + combining acute is one character after NFC; a PIN of four of them is 4 characters, not 8.
        let decomposed = String(repeating: "e\u{301}", count: 3)           // 3 characters
        let app = ScriptedApp([decomposed, decomposed, decomposed + "x", decomposed + "x"])
        _ = try choose(app, minLength: 4)
        XCTAssertEqual(app.requests[1].retry, .tooShort(minLength: 4), "3 characters (6 scalars before NFC) is too short")
        // An emoji is one character although it is four UTF-8 bytes.
        let emoji = ScriptedApp(["😀😀😀", "😀😀😀"])
        XCTAssertThrowsError(try choose(emoji, minLength: 4)) { _ in }
        XCTAssertEqual(emoji.requests.first?.kind, .setNewPin(minLength: 4))
    }

    func testAnOperationLevelRetryReasonReachesTheFirstPrompt() throws {
        let app = ScriptedApp(["1234", "1234"])
        _ = try choose(app, firstRetry: .policyViolation)
        XCTAssertEqual(app.requests[0].retry, .policyViolation)
    }

    // MARK: Failure handling

    func testEveryFailureReasonHasItsHandling() {
        XCTAssertEqual(PinFailureAction.action(for: .tooShort(minLength: 6)), .repromptNewPin(.tooShort(minLength: 6)))
        XCTAssertEqual(PinFailureAction.action(for: .tooLong), .repromptNewPin(.tooLong))
        XCTAssertEqual(PinFailureAction.action(for: .invalidEncoding), .repromptNewPin(.invalidEncoding))
        XCTAssertEqual(PinFailureAction.action(for: .policyViolation), .repromptNewPin(.policyViolation))
        XCTAssertEqual(PinFailureAction.action(for: .invalid), .repromptEnterPin)
        XCTAssertEqual(PinFailureAction.action(for: .blocked), .fail(.keyBlocked))
        XCTAssertEqual(PinFailureAction.action(for: .authBlocked), .fail(.authenticatorBlocked))
        XCTAssertEqual(PinFailureAction.action(for: .notSet), .fail(.pinNotSet))
    }

    private struct PinFailure: Error { let reason: PinFailureReason }
    private struct Other: Error {}
    private func classify(_ error: Error) -> PinFailureReason? { (error as? PinFailure)?.reason }

    func testARejectedNewPinRerunsTheOperationAskingForANewOneWithTheReason() throws {
        var seenRetries: [PinRetryReason?] = []
        let value: String = try PinRecovery.run(classify: classify) { retry in
            seenRetries.append(retry)
            if seenRetries.count == 1 { throw PinFailure(reason: .policyViolation) }
            return "enrolled"
        }
        XCTAssertEqual(value, "enrolled")
        XCTAssertEqual(seenRetries, [nil, .policyViolation])
    }

    func testAWrongPinRerunsTheOperationAskingToEnterIt() throws {
        var seenRetries: [PinRetryReason?] = []
        _ = try PinRecovery.run(classify: classify) { retry -> Int in
            seenRetries.append(retry)
            if seenRetries.count == 1 { throw PinFailure(reason: .invalid) }
            return 1
        }
        XCTAssertEqual(seenRetries, [nil, .wrongPin])
    }

    func testAFormatFailureAfterAnEnterPromptAsksToEnterAgainNotToChooseANewPin() throws {
        for reason in [PinFailureReason.tooShort(minLength: 4), .tooLong, .invalidEncoding, .policyViolation] {
            var seenRetries: [PinRetryReason?] = []
            _ = try PinRecovery.run(classify: classify, askedEnter: { true }) { retry -> Int in
                seenRetries.append(retry)
                if seenRetries.count == 1 { throw PinFailure(reason: reason) }
                return 1
            }
            XCTAssertEqual(seenRetries, [nil, .notAccepted], "\(reason)")
        }
    }

    func testAFormatFailureAfterAChoosePromptStillAsksForANewPin() throws {
        var seenRetries: [PinRetryReason?] = []
        _ = try PinRecovery.run(classify: classify, askedEnter: { false }) { retry -> Int in
            seenRetries.append(retry)
            if seenRetries.count == 1 { throw PinFailure(reason: .tooLong) }
            return 1
        }
        XCTAssertEqual(seenRetries, [nil, .tooLong])
    }

    func testABlockedKeyAndABlockedAuthenticatorFailAtOnceWithAClearError() {
        var runs = 0
        XCTAssertThrowsError(try PinRecovery.run(classify: classify) { _ -> Int in
            runs += 1; throw PinFailure(reason: .blocked)
        }) { XCTAssertEqual($0 as? WscdPinError, .keyBlocked) }
        XCTAssertEqual(runs, 1, "no re-prompt for a blocked key")
        XCTAssertThrowsError(try PinRecovery.run(classify: classify) { _ -> Int in throw PinFailure(reason: .authBlocked) }) {
            XCTAssertEqual($0 as? WscdPinError, .authenticatorBlocked)
        }
        XCTAssertThrowsError(try PinRecovery.run(classify: classify) { _ -> Int in throw PinFailure(reason: .notSet) }) {
            XCTAssertEqual($0 as? WscdPinError, .pinNotSet)
        }
    }

    func testTheOperationIsRerunAtMostThreeTimes() {
        var runs = 0
        XCTAssertThrowsError(try PinRecovery.run(classify: classify) { _ -> Int in
            runs += 1; throw PinFailure(reason: .invalid)
        }) { XCTAssertEqual($0 as? WscdPinError, .tooManyAttempts) }
        XCTAssertEqual(runs, WscdPinLimits.operationAttempts)
    }

    func testAnErrorThatIsNotAPinFailureIsRethrownUnchangedAndNotRetried() {
        var runs = 0
        XCTAssertThrowsError(try PinRecovery.run(classify: classify) { _ -> Int in runs += 1; throw Other() }) {
            XCTAssertTrue($0 is Other)
        }
        XCTAssertEqual(runs, 1)
    }

    func testEveryErrorHasAMessageAndALocalizationKey() {
        for error in [WscdPinError.keyBlocked, .authenticatorBlocked, .pinNotSet, .tooManyAttempts, .wrongPin] {
            XCTAssertFalse((error.errorDescription ?? "").isEmpty)
            XCTAssertTrue(error.localizationKey.hasPrefix("error_pin_"))
        }
    }

    /// Every key the SDK's PIN errors name exists in the string catalog, in English and Swedish.
    func testEveryPinErrorKeyIsInTheStringCatalog() throws {
        let catalog = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/SirosCredentials/Resources/Localizable.xcstrings")
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: catalog)) as? [String: Any]
        let strings = try XCTUnwrap(json?["strings"] as? [String: [String: Any]])
        for error in [WscdPinError.keyBlocked, .authenticatorBlocked, .pinNotSet, .tooManyAttempts, .wrongPin] {
            let localizations = strings[error.localizationKey]?["localizations"] as? [String: Any]
            XCTAssertNotNil(localizations?["en"], error.localizationKey)
            XCTAssertNotNil(localizations?["sv"], error.localizationKey)
        }
    }
}
