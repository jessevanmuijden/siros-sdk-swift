// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// The ready-made ``PresentationConsentHandler`` for a host app: it renders the request into the SDK's approved
/// wording (``PresentationConsentText``) and hands the app ONE question at a time, with the guarantees of
/// ``ConsentPrompt`` (a single answer; declined on timeout, dismissal, supersede and cancellation; nothing is
/// ever consented to silently).
///
/// The app only draws what it is given and answers:
///
/// ```swift
/// let coordinator = PresentationConsentCoordinator()          // locale and timeout have defaults
/// coordinator.onChange = { pending in /* show pending.request.screen, or hide the sheet when nil */ }
/// wallet.presentationConsentHandler = coordinator
/// // in the sheet:  pending.answer(true)  // Share      pending.decline()  // Cancel
/// ```
///
/// A request the wording does not cover (``PresentationConsentTextError``) is declined without being shown:
/// the user is never asked to approve a consent screen that omits something.
public final class PresentationConsentCoordinator: PresentationConsentHandler, @unchecked Sendable {
    /// What the app shows: the model (for hosts that draw their own UI) and the SDK's wording for it.
    public struct Question: Sendable {
        public let request: PresentationConsentRequest
        public let screen: PresentationConsentScreen
    }

    public typealias Pending = ConsentPrompt<Question, Bool>.Pending

    /// How long an unanswered question waits before it is declined, by default.
    public static let defaultTimeout: TimeInterval = 120

    private let prompt: ConsentPrompt<Question, Bool>
    private let text: PresentationConsentText

    /// - Parameters:
    ///   - locale: the user's locale (wording language and date style); English for a language without a translation.
    ///   - timeout: seconds before an unanswered question is declined; nil waits for the user.
    ///   - predicateRenderers: per-function wording for functions the SDK does not word itself.
    public init(
        locale: Locale = .current, timeout: TimeInterval? = defaultTimeout,
        predicateRenderers: [String: PresentationConsentText.PredicateRenderer] = [:]
    ) {
        prompt = ConsentPrompt(decline: false, timeout: timeout)
        text = PresentationConsentText(locale: locale, predicateRenderers: predicateRenderers)
    }

    /// Called with the question to show, and with nil when it is gone (answered, declined, expired). Set it before
    /// the wallet can ask: with none set every request is declined.
    public var onChange: (@Sendable (Pending?) -> Void)? {
        get { prompt.onChange }
        set { prompt.onChange = newValue }
    }

    /// The question waiting for an answer, if any.
    public var current: Pending? { prompt.current }

    /// Declines the pending question (call when the app's UI goes away).
    public func dismiss() { prompt.dismiss() }

    // MARK: PresentationConsentHandler

    public func confirm(_ request: PresentationConsentRequest) async throws -> Bool {
        guard let screen = try? text.render(request) else { return false }
        return await prompt.ask(Question(request: request, screen: screen))
    }
}
