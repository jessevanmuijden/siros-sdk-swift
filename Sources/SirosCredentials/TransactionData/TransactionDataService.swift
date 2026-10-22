// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Per-request facts the service needs besides the request itself.
public struct TransactionDataContext: Sendable {
    public var verifier: String
    /// `nil` when the SDK does not know (engine and WMP deliver requests
    /// pre-verified); `false` makes the app warn and require confirmation.
    public var requestSigned: Bool?
    public var locale: String
    /// Display name per DCQL query id.
    public var credentialNames: [String: String]
    /// The signing key per DCQL query id, for the pre-consent authentication probe.
    public var keyIds: [String: String]
    /// The claims that will be disclosed per DCQL query id, shown with the transaction.
    public var disclosedClaims: [String: [String]]
    /// Whether every credential of the request must be bound to a transaction
    /// (a transport that cannot present an unbound credential, such as WMP).
    public var requireEveryCredentialBound: Bool
    /// Further credentials presented for a query the transaction is NOT bound to (a query may answer
    /// with several credentials): each is shown with its own name and claims.
    public var additionalAttributes: [TransactionConsentAttributes]

    public init(verifier: String, requestSigned: Bool? = nil, locale: String,
                credentialNames: [String: String] = [:], keyIds: [String: String] = [:],
                disclosedClaims: [String: [String]] = [:], requireEveryCredentialBound: Bool = false) {
        self.additionalAttributes = []
        self.verifier = verifier
        self.requestSigned = requestSigned
        self.locale = locale
        self.credentialNames = credentialNames
        self.keyIds = keyIds
        self.disclosedClaims = disclosedClaims
        self.requireEveryCredentialBound = requireEveryCredentialBound
    }
}

/// What the caller signs, and the way to report how signing went. The user's
/// consent is recorded only once the presentation was actually produced:
/// call ``complete(signed:)`` exactly when signing has finished or failed.
public final class TransactionDataPlan: @unchecked Sendable {
    /// The bindings by DCQL query id, for the credentials the transaction is bound to.
    public let bindings: [String: TransactionDataBinding]
    private let onComplete: @Sendable (Bool, String?) async -> Void
    private let lock = NSLock()
    private var completed = false

    init(bindings: [String: TransactionDataBinding], onComplete: @escaping @Sendable (Bool, String?) async -> Void) {
        self.bindings = bindings
        self.onComplete = onComplete
    }

    /// Records the outcome once: `consented` if signing succeeded, otherwise a
    /// refusal (consent that did not lead to a presentation is not consent
    /// that was acted on). Later calls do nothing.
    ///
    /// - Parameter refusal: the reason to record when `signed` is false;
    ///   `signingFailed` when not given.
    /// Records signing that ended in `error`: a user's cancellation of the authentication is a
    /// decline, any other TS12 refusal keeps its own reason, anything else is `signingFailed`.
    public func complete(failedWith error: Error) async {
        var refusal: TransactionDataError.Reason?
        if let e = error as? TransactionDataError { refusal = e.reason }
        else if case SirosError.transactionData(let e) = error { refusal = e.reason }
        await complete(signed: false, refusal: refusal)
    }

    public func complete(signed: Bool, refusal: TransactionDataError.Reason? = nil) async {
        lock.lock()
        let first = !completed
        completed = true
        lock.unlock()
        if first { await onComplete(signed, refusal?.rawValue) }
    }
}

/// Runs the EC TS12 sequence for one request (contract section 4): validate,
/// check that two factor categories are even possible, build the consent
/// model, ask the user, build the per-credential
/// bindings and log the outcome. Nothing is signed by this type; a thrown
/// error means NOTHING may be signed.
public final class TransactionDataService: @unchecked Sendable {
    private let source: any TransactionMetadataSource
    private let consentHandler: (any TransactionConsentHandler)?
    private let authentication: any ScaAuthenticationCapability
    private let log: any TransactionLogStore
    private let consentTimeout: TimeInterval
    private let fetchTimeout: TimeInterval
    private let onLogFailure: (@Sendable (Error) -> Void)?

    /// 90 seconds: well below the backend's sign timeout (go-wallet-backend
    /// `Session.RequestSign` waits 3 minutes) so the wallet answers before the
    /// engine gives up, after the up to 30 s validation and fetching before it.
    public static let defaultConsentTimeout: TimeInterval = 90

    public init(
        source: any TransactionMetadataSource,
        consentHandler: (any TransactionConsentHandler)?,
        authentication: any ScaAuthenticationCapability = NoScaAuthentication(),
        log: any TransactionLogStore,
        consentTimeout: TimeInterval = TransactionDataService.defaultConsentTimeout,
        fetchTimeout: TimeInterval = 10,
        onLogFailure: (@Sendable (Error) -> Void)? = nil
    ) {
        self.source = source
        self.consentHandler = consentHandler
        self.authentication = authentication
        self.log = log
        self.consentTimeout = consentTimeout
        self.fetchTimeout = fetchTimeout
        self.onLogFailure = onLogFailure
    }

    public func process(_ request: TransactionDataRequest, context: TransactionDataContext) async throws -> TransactionDataPlan {
        let raws = request.entries.map(\.raw)
        let label: @Sendable (String?) -> String = { queryId in
            guard let queryId else { return "" }
            return context.credentialNames[queryId] ?? request.credentials.first(where: { $0.queryId == queryId })?.vct ?? ""
        }
        let note = MetadataAuthenticationNote()
        do {
            let pipeline = TransactionDataPipeline(source: source, fetchTimeout: fetchTimeout)
            let validated = try await pipeline.validate(request, note: note)
            let boundQueryIds = Set(validated.entries.flatMap(\.credentialIds))
            if context.requireEveryCredentialBound, request.credentials.contains(where: { !boundQueryIds.contains($0.queryId) }) {
                throw TransactionDataError(.invalidEntry, detail: "a credential of the request is not bound to the transaction")
            }

            // Refuse BEFORE showing anything when two factor categories cannot be established.
            for credential in request.credentials where boundQueryIds.contains(credential.queryId) {
                guard await authentication.canEstablishTwoCategories(keyId: context.keyIds[credential.queryId]) else {
                    throw TransactionDataError(.insufficientAuthenticationFactors, detail: "two authentication factor categories cannot be established")
                }
            }

            // 8. Display and consent. No handler: the transaction cannot be shown.
            guard let handler = consentHandler else { throw TransactionDataError(.noConsentHandler) }
            let firstQueryId = validated.entries.first?.credentialIds.first ?? ""
            let attributes: [TransactionConsentAttributes] = request.credentials.compactMap { credential in
                guard boundQueryIds.contains(credential.queryId) || context.disclosedClaims[credential.queryId] != nil else { return nil }
                return TransactionConsentAttributes(credentialName: label(credential.queryId), claims: context.disclosedClaims[credential.queryId] ?? [])
            } + context.additionalAttributes
            // Every string the user is shown must be safe, whoever supplied it.
            // A blank verifier cannot identify who is asking: refuse before anything is shown.
            guard !context.verifier.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw TransactionDataError(.invalidEntry, detail: "the verifier identity is empty")
            }
            try TextSafety.require(context.verifier, maxLength: 200, what: "the verifier name")
            for text in attributes.flatMap({ [$0.credentialName] + $0.claims }) + [label(firstQueryId)] {
                try TextSafety.require(text, maxLength: 200, what: "an attribute or credential name")
            }
            let model = try await TransactionConsentModelBuilder(
                source: source, fetchTimeout: fetchTimeout, maxResourceBytes: 256 * 1024, note: note
            ).build(
                validated: validated, request: request, verifier: context.verifier, credentialName: label(firstQueryId),
                requestSigned: context.requestSigned, locale: context.locale, attributes: attributes
            )
            // The metadata was used to build what the user is about to be shown: warn once if it was unpinned.
            note.emitIfNeeded()
            let answer = await askUser(handler, model)
            // The wallet's own task being cancelled is not the user declining.
            try Task.checkCancellation()
            guard answer else { throw TransactionDataError(.declined) }

            // 9. Bindings. They carry NO authentication factors: those are reported by the signing
            // operation itself and written into the `amr` by the keystore (see ScaAuthenticationCapability).
            var bindings: [String: TransactionDataBinding] = [:]
            // Only credentials the transaction is bound to: an unrelated one in a
            // combined presentation must not refuse the binding.
            for credential in request.credentials where boundQueryIds.contains(credential.queryId) {
                if let binding = try validated.binding(forQueryId: credential.queryId) {
                    bindings[credential.queryId] = binding
                }
            }

            // 10. The record is written when signing is known to have succeeded.
            let verifier = context.verifier
            return TransactionDataPlan(bindings: bindings) { [log, onLogFailure] signed, reason in
                let records = TransactionLogEntry.records(
                    rawEntries: raws, verifier: verifier, credentialLabel: label,
                    outcome: signed ? .consented : (reason == TransactionDataError.Reason.declined.rawValue ? .declined : .refused),
                    reason: signed || reason == TransactionDataError.Reason.declined.rawValue ? nil : (reason ?? "signingFailed")
                )
                do { try await log.append(records) } catch { onLogFailure?(error) }
            }
        } catch let error as TransactionDataError {
            // A cancelled request (logout, flow ended) can surface as a refusal from a deadline path:
            // it is not a refusal and must not be logged as one.
            try Task.checkCancellation()
            let declined = error.reason == .declined
            let records = TransactionLogEntry.records(
                rawEntries: raws, verifier: context.verifier, credentialLabel: label,
                outcome: declined ? .declined : .refused, reason: declined ? nil : error.reason.rawValue
            )
            do { try await log.append(records) } catch { onLogFailure?(error) }
            var logged = error
            logged.alreadyLogged = true
            throw logged
        }
    }

    /// `true` only for an explicit yes. A throw (including the handler being
    /// cancelled) or a missing answer within the time limit is a decline.
    private func askUser(_ handler: any TransactionConsentHandler, _ model: TransactionConsentRequest) async -> Bool {
        await withDeadline(consentTimeout, fallback: false) { (try? await handler.confirm(model)) ?? false }
    }
}
