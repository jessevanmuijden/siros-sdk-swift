// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// PIN prompting for the WSCD plugins, platform-independent and free of the UniFFI types so it is unit-testable
// anywhere. `UniFFISigner.swift` (iOS only) is the thin bridge that maps the FFI callback and `FfiWscdError.Pin`
// onto this.

/// Why the SDK is asking the app for a PIN. The app shows "Enter your PIN" for `enterPin`, and "Choose a PIN"
/// followed by a confirmation prompt for `setNewPin` / `confirmNewPin`.
public enum PinRequestKind: Equatable, Sendable {
    /// Enter the PIN already set on the authenticator (or the OPAQUE PIN).
    case enterPin
    /// Choose a NEW PIN for an authenticator that has none. At least `minLength` characters.
    case setNewPin(minLength: Int)
    /// Type the PIN chosen just before again; the SDK compares the two.
    case confirmNewPin
}

/// Why the previous attempt is being asked again, so the app can say so ("PIN too short", "PINs did not match").
public enum PinRetryReason: Equatable, Sendable {
    case tooShort(minLength: Int)
    case tooLong
    case invalidEncoding
    case policyViolation
    /// The two entries of a new PIN differed.
    case mismatch
    /// The authenticator rejected the PIN that was entered.
    case wrongPin
}

/// One PIN prompt: what to ask and, when it repeats an earlier prompt, why.
public struct PinRequest: Equatable, Sendable {
    public let kind: PinRequestKind
    public let retry: PinRetryReason?

    public init(kind: PinRequestKind, retry: PinRetryReason? = nil) {
        self.kind = kind
        self.retry = retry
    }
}

/// The SDK's mirror of the library's PIN failure reasons (`FfiPinFailure`).
public enum PinFailureReason: Equatable, Sendable {
    case tooShort(minLength: Int)
    case tooLong
    case invalidEncoding
    case policyViolation
    case invalid
    case blocked
    case authBlocked
    case notSet
}

/// A PIN failure the SDK could not recover from by asking again. `localizationKey` is looked up in the SDK's
/// `Localizable.xcstrings` (`error_pin_*`); `errorDescription` is the English text.
public enum WscdPinError: Error, LocalizedError, Equatable, Sendable {
    /// The PIN is blocked on the authenticator; it needs a reset.
    case keyBlocked
    /// Too many wrong PINs since power-up: unplug and replug the authenticator.
    case authenticatorBlocked
    /// The authenticator reported no PIN is set although one was just set: an internal error.
    case pinNotSet
    /// The bounded number of prompts was used up.
    case tooManyAttempts
    /// The authenticator did not accept the PIN (and the operation is not re-run, e.g. a transaction signature).
    case wrongPin

    public var localizationKey: String {
        switch self {
        case .keyBlocked: return "error_pin_key_blocked"
        case .authenticatorBlocked: return "error_pin_authenticator_blocked"
        case .pinNotSet: return "error_pin_not_set"
        case .tooManyAttempts: return "error_pin_too_many_attempts"
        case .wrongPin: return "error_pin_wrong"
        }
    }

    public var errorDescription: String? {
        switch self {
        case .keyBlocked: return "The key is blocked and needs a reset."
        case .authenticatorBlocked: return "The authenticator is blocked: unplug it and plug it in again."
        case .pinNotSet: return "Internal error: the authenticator has no PIN set."
        case .tooManyAttempts: return "Too many PIN attempts."
        case .wrongPin: return "The PIN was not accepted."
        }
    }
}

/// What to do about a PIN failure that ended an operation.
public enum PinFailureAction: Equatable, Sendable {
    /// Run the operation again; the next prompt is for a NEW PIN, with this reason.
    case repromptNewPin(PinRetryReason)
    /// Run the operation again; the next prompt is to ENTER the existing PIN.
    case repromptEnterPin
    /// Give up with this error.
    case fail(WscdPinError)

    /// The error for a failure that is not retried (an operation that asks once): a wrong or unacceptable PIN is
    /// `wrongPin`, the others are as in `action(for:)`.
    public static func terminalError(for reason: PinFailureReason) -> WscdPinError {
        if case let .fail(error) = action(for: reason) { return error }
        return .wrongPin
    }

    public static func action(for reason: PinFailureReason) -> PinFailureAction {
        switch reason {
        case let .tooShort(minLength): return .repromptNewPin(.tooShort(minLength: minLength))
        case .tooLong: return .repromptNewPin(.tooLong)
        case .invalidEncoding: return .repromptNewPin(.invalidEncoding)
        case .policyViolation: return .repromptNewPin(.policyViolation)
        case .invalid: return .repromptEnterPin
        case .blocked: return .fail(.keyBlocked)
        case .authBlocked: return .fail(.authenticatorBlocked)
        case .notSet: return .fail(.pinNotSet)
        }
    }
}

/// The user backed out of a PIN prompt.
public struct PinPromptCancelled: Error, Equatable, Sendable {
    public init() {}
}

/// Bounds on re-prompting. Three entries of a NEW PIN per ceremony (too short, mismatched), and three re-runs of
/// an operation after the authenticator refused a PIN - the authenticator's own retry counter is the hard limit
/// behind the second.
public enum WscdPinLimits {
    public static let newPinEntries = 3
    public static let operationAttempts = 3
}

/// Asks the app for a NEW PIN, twice, and checks it. All of the logic lives here, not in the app: the app only
/// shows the prompt for each `PinRequest`.
public struct NewPinChooser {
    /// Shows one prompt and returns what the user typed; throws if the user cancels.
    public typealias Ask = (PinRequest) throws -> Data

    private let ask: Ask

    public init(ask: @escaping Ask) { self.ask = ask }

    /// Returns the chosen PIN once it is at least `minLength` characters and typed identically twice.
    /// - Parameter firstRetry: why the very first prompt repeats an earlier one (an operation-level re-prompt).
    /// - Throws: whatever `ask` throws on cancel, or `WscdPinError.tooManyAttempts` after
    ///   `WscdPinLimits.newPinEntries` unsuccessful entries.
    public func choose(minLength: Int, firstRetry: PinRetryReason? = nil) throws -> Data {
        var retry = firstRetry
        for _ in 0..<WscdPinLimits.newPinEntries {
            let first = SecureBytes(try ask(PinRequest(kind: .setNewPin(minLength: minLength), retry: retry)))
            defer { first.wipe() }
            // Characters as the authenticator counts them: Unicode scalars after NFC normalisation.
            let characters = Self.characterCount(first)
            if characters < minLength {
                retry = .tooShort(minLength: minLength)
                continue
            }
            let second = SecureBytes(try ask(PinRequest(kind: .confirmNewPin)))
            defer { second.wipe() }
            guard Self.equal(first, second) else {
                retry = .mismatch
                continue
            }
            return first.dataCopy()
        }
        throw WscdPinError.tooManyAttempts
    }

    static func characterCount(_ pin: SecureBytes) -> Int {
        let text = String(decoding: pin.dataCopy(), as: UTF8.self)
        return text.precomposedStringWithCanonicalMapping.unicodeScalars.count
    }

    /// Compares without an early exit on the first differing byte.
    static func equal(_ a: SecureBytes, _ b: SecureBytes) -> Bool {
        let x = [UInt8](a.dataCopy()), y = [UInt8](b.dataCopy())
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<x.count { diff |= x[i] ^ y[i] }
        return diff == 0
    }
}

/// Re-runs a PIN-using operation after the authenticator refused the PIN, within `WscdPinLimits.operationAttempts`.
public enum PinRecovery {
    /// - Parameters:
    ///   - classify: maps a thrown error to a PIN failure, or nil when it is not one (rethrown unchanged).
    ///   - operation: receives the retry reason the NEXT prompt should carry (nil on the first run).
    public static func run<T>(
        classify: (Error) -> PinFailureReason?,
        operation: (_ nextPromptRetry: PinRetryReason?) throws -> T
    ) throws -> T {
        var retry: PinRetryReason?
        for attempt in 1...WscdPinLimits.operationAttempts {
            do {
                return try operation(retry)
            } catch {
                guard let reason = classify(error) else { throw error }
                switch PinFailureAction.action(for: reason) {
                case let .fail(pinError):
                    throw pinError
                case let .repromptNewPin(why):
                    retry = why
                case .repromptEnterPin:
                    retry = .wrongPin
                }
                if attempt == WscdPinLimits.operationAttempts { throw WscdPinError.tooManyAttempts }
            }
        }
        throw WscdPinError.tooManyAttempts
    }
}
