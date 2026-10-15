// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosKeystore
import SirosTransport

/// Gives the EC TS12 pipeline its type metadata and referenced documents.
///
/// Neither goes through `VctmFetcher`, which follows redirects, accepts http
/// and reads without a size limit: everything here is https only, size- and
/// time-bounded, and fetched without any credential of the wallet's, EXCEPT
/// the wallet's own registry (the wallet's backend), which is asked with the
/// wallet's token because that is what it requires.
struct WalletTransactionMetadataSource: TransactionMetadataSource {
    /// Fetches a type metadata document for `vct`; see `SirosWallet.transactionMetadataFetch`.
    let metadataFetch: @Sendable (_ vct: String, _ expectedIntegrity: String?, _ maxBytes: Int) async -> String?
    /// Fetches a referenced document; see `SirosWallet.transactionResourceGet`.
    let resourceGet: @Sendable (_ url: URL, _ maxBytes: Int) async -> Data?

    func typeMetadataDocument(vct: String, expectedIntegrity: String?, maxBytes: Int) async -> String? {
        await metadataFetch(vct, expectedIntegrity, maxBytes)
    }

    func fetchResource(uri: String, maxBytes: Int) async -> Data? {
        // Only absolute https references (the fetcher enforces it again, and
        // refuses private hosts and redirects).
        guard let url = URL(string: uri), url.scheme?.lowercased() == "https" else { return nil }
        return await resourceGet(url, maxBytes)
    }
}

/// A log store that stops accepting records once the account it was created
/// for is gone, so a presentation still in flight at logout cannot write into
/// the next account's container.
final class GenerationBoundLogStore: TransactionLogStore, @unchecked Sendable {
    private let inner: any TransactionLogStore
    private let generation: Int
    private let current: @Sendable () -> Int

    init(_ inner: any TransactionLogStore, generation: Int, current: @escaping @Sendable () -> Int) {
        self.inner = inner
        self.generation = generation
        self.current = current
    }

    func append(_ entries: [TransactionLogEntry]) async throws {
        guard current() == generation else { throw TransactionLogError("the account changed before the record was written") }
        try await inner.append(entries)
    }

    func entries() async -> [TransactionLogEntry] {
        guard current() == generation else { return [] }
        let read = await inner.entries()
        // The account can switch while the read is suspended and the shared keystore then exposes the next
        // account's records: hand back nothing unless it is still the account this store belongs to.
        return current() == generation ? read : []
    }
}

/// What the wallet signs for a transaction presentation and how it reports the
/// outcome: the bindings, the signing key pinned when the transaction was
/// validated and shown, and the completion that records consent only once the
/// presentation exists.
final class ScaPlan: @unchecked Sendable {
    let plan: TransactionDataPlan
    let kids: [String: String]
    var bindings: [String: TransactionDataBinding] { plan.bindings }

    init(plan: TransactionDataPlan, kids: [String: String]) {
        self.plan = plan
        self.kids = kids
    }

    /// The key to sign with for `queryId`: the one that was validated, never re-selected.
    func kid(for queryId: String?, fallback: String?) -> String? {
        queryId.flatMap { kids[$0] } ?? fallback
    }
}

extension SirosWallet {
    /// The default `transactionResourceGet`: the hardened fetcher (https, public
    /// hosts, no redirects, no credentials, size and time caps).
    static let secureResourceGet: @Sendable (URL, Int) async -> Data? = { url, maxBytes in
        await SecureDocumentFetcher().fetch(url, maxBytes: maxBytes)
    }

    /// The headers the wallet's own registry expects (tenant and the wallet's
    /// token), sent only to the wallet's own backend.
    func registryHeaders() async -> [String: String] {
        var headers = ["X-Tenant-ID": config.tenantId]
        lock.lock(); let tokens = authTokens; lock.unlock()
        if let token = try? await tokens?.ensureBackendToken() {
            headers["Authorization"] = "Bearer \(token.raw)"
        } else if let appToken = sessionStore.appToken {
            headers["Authorization"] = "Bearer \(appToken)"
        }
        return headers
    }

    /// The default `transactionMetadataFetch`: the wallet's registry (with the
    /// wallet's token, size-checked), then the vct's own well-known location
    /// through the hardened fetcher. With a pin the first document that hashes
    /// to it wins.
    func fetchTypeMetadata(vct: String, expectedIntegrity: String?, maxBytes: Int) async -> String? {
        // The pin is checked over the downloaded BYTES, before any decoding (decoding
        // can drop a leading BOM, which would then hash differently).
        func acceptable(_ data: Data?) -> String? {
            guard let data, data.count <= maxBytes else { return nil }
            if let expectedIntegrity, !Integrity.matches(data, expectedIntegrity) { return nil }
            // Validate, but keep the text exactly as downloaded: `String(data:encoding:)`
            // drops a leading BOM, and the pipeline re-checks the pin over this text.
            guard String(data: data, encoding: .utf8) != nil else { return nil }
            return String(decoding: data, as: UTF8.self)
        }
        if let base = URL(string: resolvedRegistryUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))),
           var components = URLComponents(url: base.appendingPathComponent("type-metadata"), resolvingAgainstBaseURL: false) {
            components.queryItems = [URLQueryItem(name: "vct", value: vct)]
            if let registry = components.url,
               let found = acceptable(await SecureDocumentFetcher().fetch(registry, maxBytes: maxBytes, headers: await registryHeaders(), ownBackend: true)) {
                return found
            }
        }
        guard let url = URL(string: vct), url.scheme?.lowercased() == "https", let host = url.host else { return nil }
        let path = String(url.path.drop(while: { $0.asciiValue == 47 }))   // the leading slashes
        guard !path.isEmpty else { return nil }
        var origin = URLComponents()
        origin.scheme = "https"
        origin.host = host
        origin.port = url.port
        guard let originUrl = origin.url else { return nil }
        let wellKnown = originUrl.appendingPathComponent(".well-known").appendingPathComponent("vct").appendingPathComponent(path)
        return acceptable(await transactionResourceGet(wellKnown, maxBytes))
    }

    /// The transaction log (EC TS12 section 5.3), newest first: one record
    /// per SCA presentation attempt, consented, declined or refused.
    public func transactionLog() async -> [TransactionLogEntry] {
        await transactionLogStoreInstance().entries()
    }

    /// Replaces where transaction-log records are kept. By default they
    /// persist in the wallet's synchronised container when the keystore
    /// offers one, and in memory otherwise.
    public func setTransactionLogStore(_ store: any TransactionLogStore) {
        lock.lock(); transactionLogStoreStorage = store; transactionLogStoreIsDefault = false; lock.unlock()
    }

    /// Drops the default log store at an account boundary (logout, lock), so a
    /// later account never sees or writes into this one's records. A store the
    /// host supplied is the host's to manage and is left alone.
    func resetDefaultTransactionLogStore() {
        lock.lock(); defer { lock.unlock() }
        if transactionLogStoreIsDefault { transactionLogStoreStorage = nil }
        transactionLogGeneration += 1
    }

    func transactionLogStoreInstance() -> any TransactionLogStore {
        lock.lock(); defer { lock.unlock() }
        if let existing = transactionLogStoreStorage { return existing }
        // With no account unlocked there is no container to write to, and a default store created now
        // would be reused by whichever account unlocks next: hand out a throwaway store, uncached.
        if keystore is ExtensionStore, !keystore.isUnlocked { return InMemoryTransactionLogStore() }
        transactionLogStoreIsDefault = true
        let created: any TransactionLogStore
        if let extensions = keystore as? ExtensionStore {
            let generation = transactionLogGeneration
            created = ExtensionTransactionLogStore(store: extensions, persisted: { [weak self] in
                try await self?.persistKeystoreOrThrow(generation: generation)
            }, writesAllowed: { [weak self] in
                guard let self else { return false }
                self.lock.lock(); defer { self.lock.unlock() }
                return self.transactionLogGeneration == generation
            })
        } else {
            created = InMemoryTransactionLogStore()
        }
        let generation = transactionLogGeneration
        let bound = GenerationBoundLogStore(created, generation: generation, current: { [weak self] in
            guard let self else { return -1 }
            self.lock.lock(); defer { self.lock.unlock() }
            return self.transactionLogGeneration
        })
        transactionLogStoreStorage = bound
        return bound
    }

    func makeTransactionDataService() -> TransactionDataService {
        TransactionDataService(
            source: WalletTransactionMetadataSource(metadataFetch: transactionMetadataFetch, resourceGet: transactionResourceGet),
            consentHandler: transactionConsentHandler,
            factorsProvider: authenticationFactorsProvider,
            log: transactionLogStoreInstance(),
            consentTimeout: transactionDataConsentTimeout,
            onLogFailure: { [weak self] _ in self?.reportTransactionLogFailure() }
        )
    }

    /// Records, at the start of a legacy flow, whether TS12 handling is in
    /// effect for it, and returns that value so the declaration to the
    /// engine is derived from the same capture. The engine assigns the flow
    /// id later, so the oldest unclaimed record is assigned to the first
    /// flow that asks (`transactionDataActive(forFlow:)`).
    @discardableResult
    func snapshotTransactionDataEnablement() -> Bool {
        let effective = transactionDataEffectivelyEnabled
        lock.lock(); legacyFlowSnapshotQueue.append((effective, Date())); lock.unlock()
        return effective
    }

    /// The same for a WMP session (capabilities are offered per session).
    @discardableResult
    func snapshotWmpSessionEnablement() -> Bool {
        let effective = transactionDataEffectivelyEnabled
        lock.lock(); wmpSessionSnapshot = effective; lock.unlock()
        return effective
    }

    /// Runs `body` as a task a flow error/completion, logout or peer teardown can cancel.
    ///
    /// The task is created AND registered under the wallet lock, and its first act is to wait for that lock,
    /// so it cannot begin (and cannot prompt or sign) before it is registered. Registration then checks
    /// whether a teardown, or the end of THIS flow, happened since `body` was requested, and cancels the
    /// task at once if so.
    func trackedTransaction<T: Sendable>(flowId: String, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
        let epoch = currentTaskEpoch()
        let flowSeq = currentFlowEndSeq(flowId)
        let id = UUID()
        lock.lock()
        let task = Task { [weak self] () async throws -> T in
            self?.awaitRegistration()
            try Task.checkCancellation()
            return try await body()
        }
        registerLocked(id: id, flowId: flowId, epoch: epoch, flowSeq: flowSeq) { task.cancel() }
        lock.unlock()
        defer { unregisterTransactionTask(id) }
        return try await withTaskCancellationHandler { try await task.value } onCancel: { task.cancel() }
    }

    /// Returns once any registration in progress (made under the wallet lock) has completed.
    private func awaitRegistration() { lock.lock(); lock.unlock() }

    /// Must be called with the wallet lock held. Registers the task unless a teardown or the end of its
    /// flow has happened since `epoch` / `flowSeq` were read; then it is cancelled instead.
    private func registerLocked(id: UUID, flowId: String, epoch: Int, flowSeq: Int, cancel: @escaping @Sendable () -> Void) {
        if transactionTaskEpoch != epoch || (flowEndSeq[flowId] ?? 0) != flowSeq {
            cancel()
        } else {
            transactionTasks[id] = (flowId: flowId, cancel: cancel)
        }
    }

    /// Registers a cancellable task (see `registerLocked`).
    func registerTransactionTask(flowId: String, epoch: Int, flowSeq: Int = 0, cancel: @escaping @Sendable () -> Void) -> UUID {
        let id = UUID()
        lock.lock()
        registerLocked(id: id, flowId: flowId, epoch: epoch, flowSeq: flowSeq, cancel: cancel)
        lock.unlock()
        return id
    }

    func currentFlowEndSeq(_ flowId: String) -> Int { lock.lock(); defer { lock.unlock() }; return flowEndSeq[flowId] ?? 0 }

    func currentTaskEpoch() -> Int { lock.lock(); defer { lock.unlock() }; return transactionTaskEpoch }

    private func unregisterTransactionTask(_ id: UUID) {
        lock.lock(); transactionTasks.removeValue(forKey: id); lock.unlock()
    }

    /// Runs `body` to completion even if the calling task is cancelled meanwhile.
    static func shielded(_ body: @escaping @Sendable () async -> Void) async {
        await Task { await body() }.value
    }

    /// How long an unclaimed start record stays valid.
    static let snapshotLifetime: TimeInterval = 600

    /// Whether `flowId` (legacy) or the WMP session started with TS12
    /// handling in effect AND a handler is still registered. A legacy flow
    /// that started without a record falls back to the live value.
    func transactionDataActive(forFlow flowId: String, viaWmp: Bool) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let handlerPresent = transactionConsentHandlerStorage != nil
        if viaWmp { return handlerPresent && wmpSessionSnapshot }
        // Claim (and cache) this flow's record FIRST, whether or not a handler is
        // registered now: otherwise a flow that ran without one leaves its record
        // in the queue for a later flow to consume.
        let value: Bool
        if let known = legacyFlowSnapshots[flowId] {
            value = known
        } else {
            // Records of flows that never produced a sign request go stale: drop them.
            let horizon = Date().addingTimeInterval(-Self.snapshotLifetime)
            legacyFlowSnapshotQueue.removeAll { $0.at < horizon }
            value = legacyFlowSnapshotQueue.isEmpty
                ? transactionDataEnabledValue
                : legacyFlowSnapshotQueue.removeFirst().effective
            legacyFlowSnapshots[flowId] = value
        }
        return handlerPresent && value
    }

    /// Exports the container and syncs it, REPORTING failure (unlike
    /// `persistAndSyncKeystore`, which only logs it).
    func persistKeystoreOrThrow(generation: Int) async throws {
        guard keystore.isUnlocked else { throw TransactionLogError("the container is locked") }
        try await exportAndSyncKeystore(generation: generation)
    }

    /// Throws when the operation was cancelled or the account it started under is no longer the active one.
    func requireSameAccount(_ generation: Int) throws {
        try Task.checkCancellation()
        guard currentAccountGeneration() == generation else {
            throw SirosError.wallet(message: "The account changed while the request was being handled")
        }
    }

    func currentAccountGeneration() -> Int {
        lock.lock(); defer { lock.unlock() }
        return transactionLogGeneration
    }

    /// Tells the host a transaction-log write did not reach durable storage.
    func reportTransactionLogFailure() {
        lock.lock(); let listener = eventListener; lock.unlock()
        listener?.onTransactionLogFailure()
    }

    /// Records a refusal that happened before the pipeline ran (so the service
    /// did not log it): one `refused` record, whatever the request carried.
    func logPreparatoryRefusal(_ error: TransactionDataError, rawEntries: [String], verifier: String) async {
        let records = TransactionLogEntry.records(
            rawEntries: rawEntries, verifier: verifier, credentialLabel: { _ in "" },
            outcome: error.reason == .declined ? .declined : .refused, reason: error.reason.rawValue
        )
        do { try await transactionLogStoreInstance().append(records) } catch { reportTransactionLogFailure() }
    }

    /// The credentials chosen to answer a request: one per query id (`credentials`, which the
    /// transaction is validated against), the claims each discloses, and any further credentials
    /// of a query the transaction is NOT bound to, kept apart so consent can name each of them.
    struct ScaSelection {
        var credentials: [String: StoredCredential] = [:]
        var disclosed: [String: [String]] = [:]
        var additional: [TransactionConsentAttributes] = []
        /// The further credentials themselves: they are presented too, so they are rechecked after consent like the others.
        var extraCredentials: [StoredCredential] = []
    }

    /// Runs the TS12 sequence for a presentation and returns the plan to sign.
    /// Throws `SirosError.transactionData`.
    func processTransactionData(
        entries: [TransactionDataEntryInput],
        responseMode: String?,
        selection: ScaSelection,
        verifier: String,
        requestSigned: Bool?,
        requireEveryCredentialBound: Bool = false
    ) async throws -> ScaPlan {
        let selected = selection.credentials
        do {
            var credentials: [TransactionDataCredential] = []
            var names: [String: String] = [:]
            var factorContexts: [String: AuthenticationFactorContext] = [:]
            var kids: [String: String] = [:]
            for (queryId, cred) in selected.sorted(by: { $0.key < $1.key }) {
                // A malformed `...#integrity` claim refuses here (never reads as "no pin"). Only an SD-JWT VC has such
                // claims to read: an unbound mdoc (or other) credential in a combined presentation has none, and
                // the core refuses it itself if the transaction IS bound to it.
                let isSdJwt = cred.format == "dc+sd-jwt" || cred.format == "vc+sd-jwt"
                credentials.append(TransactionDataCredential(
                    queryId: queryId, format: cred.format, vct: cred.metadata?.vct,
                    integrityClaims: isSdJwt ? try TransactionDataCredential.integrityClaims(ofSdJwt: cred.raw) : [:]
                ))
                names[queryId] = Self.consentDisplayName(cred)
                // The key is resolved ONCE, here, and the same one is signed with.
                let keys = keystore.listKeys()
                let kid = cred.kid ?? keys.first?.keyId
                if let kid { kids[queryId] = kid }
                let properties: SignerSecurityProperties? = if let kid { await keystore.securityProperties(keyId: kid) } else { nil }
                let pluginId = kid.flatMap { id in keys.first(where: { $0.keyId == id })?.pluginId }
                factorContexts[queryId] = AuthenticationFactorContext(keyStorage: properties?.keyStorage ?? [], pluginId: pluginId, keyId: kid)
            }
            var context = TransactionDataContext(
                verifier: verifier, requestSigned: requestSigned, locale: transactionDataLocale,
                credentialNames: names, factorContexts: factorContexts, disclosedClaims: selection.disclosed,
                requireEveryCredentialBound: requireEveryCredentialBound
            )
            context.additionalAttributes = selection.additional
            let plan = try await makeTransactionDataService().process(
                TransactionDataRequest(entries: entries, responseMode: responseMode, credentials: credentials), context: context
            )
            // What was validated and shown must be what is signed: refuse if a
            // credential changed or went away while the user was deciding.
            let current = await credentialStore.getAll()
            for cred in Array(selected.values) + selection.extraCredentials where current.first(where: { $0.id == cred.id }) != cred {
                // One record, with the real reason; the caller must not log it again.
                await plan.complete(signed: false, refusal: .invalidEntry)
                var changed = TransactionDataError(.invalidEntry, detail: "a credential changed while the transaction was being confirmed")
                changed.alreadyLogged = true
                throw changed
            }
            // A logout or a finished flow may have cancelled this task while the awaits above
            // ignored it: hand nothing to a transport once that is so.
            try Task.checkCancellation()
            return ScaPlan(plan: plan, kids: kids)
        } catch let error as TransactionDataError {
            // The service logs what it refused itself; only what failed before it ran is logged here.
            guard !error.alreadyLogged else { throw error }
            await logPreparatoryRefusal(error, rawEntries: entries.map(\.raw), verifier: verifier)
            // One refusal record per request: the caller must not log what was just recorded.
            var logged = error
            logged.alreadyLogged = true
            throw logged
        }
    }

    /// What a credential is called in the consent: its name, else its vct, doctype or format, so a
    /// credential that will be presented is never listed with an empty name. Neutralised and capped,
    /// since the fallbacks come from the credential and its issuer.
    static func consentDisplayName(_ cred: StoredCredential) -> String {
        for candidate in [cred.metadata?.name, cred.metadata?.vct, cred.metadata?.doctype, cred.format] {
            let cleaned = TransactionLogEntry.displaySafe(candidate ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            if !cleaned.isEmpty { return String(cleaned.prefix(200)) }
        }
        return "credential"
    }

    /// The verifier identity the user is shown and the log records: the display name trust
    /// evaluated, else the identifier it verified, else `fallback` (what the request itself
    /// claims). For a signed DC API request whose verified `client_id` differs from the browser
    /// origin and with no display name, both are named, so the label is never the wrong identity.
    static func transactionVerifierLabel(trust: TrustResult?, fallback: String, origin: String? = nil) -> String {
        if let name = trust?.entityName, !name.isEmpty { return name }
        if let id = trust?.identifier, !id.isEmpty {
            if let origin, !origin.isEmpty, origin != id { return "\(id) (via \(origin))" }
            return id
        }
        return fallback
    }

    /// One credential of a WMP transaction presentation, resolved before anything is signed.
    struct WmpSigningItem {
        let cred: StoredCredential
        let ref: CredentialRef
        let binding: TransactionDataBinding
        let queryId: String
    }

    /// What an orchestrated request is bound to: who is shown as asking, and the KB-JWT's replay challenge and audience.
    struct ScaRequestContext {
        let verifier: String
        let nonce: String
        let audience: String
    }

    /// The TS12 plan for a presentation relayed by the orchestrator (legacy
    /// engine or WMP). `nil` when the request carries no `transaction_data`. A
    /// request that does carry it is refused unless TS12 handling was in
    /// effect when the flow started.
    func orchestratedTransactionPlan(
        transactionData: TransactionDataMember,
        responseMode: String?,
        refs: [CredentialRef]?,
        allCreds: [StoredCredential],
        flowId: String,
        viaWmp: Bool,
        context: ScaRequestContext
    ) async throws -> ScaPlan? {
        let verifier = context.verifier
        // An absent or empty member means the request carries no transaction.
        guard transactionData.requestsTransactionHandling else { return nil }
        let raws = (transactionData.entries ?? []).map { $0.raw ?? "" }
        do {
            guard let entries = transactionData.entries else {
                throw TransactionDataError(.invalidEntry, detail: "transaction_data is null")
            }
            // Without a nonce and an audience the KB-JWT would carry no replay challenge and no verifier binding.
            guard !context.nonce.isEmpty, !context.audience.isEmpty else {
                throw TransactionDataError(.invalidEntry, detail: "a transaction presentation needs a non-empty nonce and audience")
            }
            guard transactionDataActive(forFlow: flowId, viaWmp: viaWmp) else {
                throw TransactionDataError(.disabled, detail: "transaction_data received but TS12 handling is not in effect")
            }
            // Without credentials_to_include nothing resolves and the pipeline refuses.
            var selection = ScaSelection()
            // Which queries are transaction-bound is decided FIRST: only those must be answered
            // by exactly one credential; an unbound query may have several.
            let boundQueries = TransactionDataPipeline.boundQueryIds(rawEntries: raws)
            for ref in refs ?? [] {
                guard let queryId = ref.credentialQueryId, !queryId.isEmpty,
                      let id = Int64(ref.credentialId), let cred = allCreds.first(where: { $0.id == id }) else {
                    throw TransactionDataError(.invalidEntry, detail: "credentials_to_include cannot be matched to DCQL queries")
                }
                if selection.credentials[queryId] != nil {
                    guard !boundQueries.contains(queryId) else {
                        throw TransactionDataError(.invalidEntry, detail: "more than one credential answers a query the transaction is bound to")
                    }
                    selection.additional.append(TransactionConsentAttributes(credentialName: Self.consentDisplayName(cred), claims: ref.disclosedClaims ?? []))
                    selection.extraCredentials.append(cred)
                    continue
                }
                selection.credentials[queryId] = cred
                selection.disclosed[queryId] = ref.disclosedClaims ?? []
            }
            return try await processTransactionData(
                entries: entries.map(TransactionDataEntryInput.init),
                responseMode: responseMode,
                selection: selection,
                verifier: verifier,
                requestSigned: nil,
                requireEveryCredentialBound: viaWmp
            )
        } catch let error as TransactionDataError {
            if !error.alreadyLogged { await logPreparatoryRefusal(error, rawEntries: raws, verifier: verifier) }
            throw SirosError.transactionData(error)
        }
    }

    /// WMP `sign_presentation` for a request carrying `transaction_data`:
    /// every credential must be one the transaction is bound to (combined
    /// presentations are not supported over WMP, which lacks the response URI
    /// a non-SCA mdoc part would need).
    func wmpTransactionPresentation(flowId: String, params: SignSubFlowParams, verifier: String? = nil) async throws -> SignSubFlowResult {
        let allCreds = await credentialStore.getAll()
        guard let plan = try await orchestratedTransactionPlan(
            transactionData: params.transactionDataMember, responseMode: params.responseMode,
            refs: params.credentialsToInclude, allCreds: allCreds,
            flowId: flowId, viaWmp: true,
            context: ScaRequestContext(verifier: verifier ?? params.audience, nonce: params.nonce, audience: params.audience)
        ) else {
            throw SirosError.transactionData(TransactionDataError(.invalidEntry, detail: "no transaction_data"))
        }
        do {
            // Resolve every reference first: nothing is signed unless all of them
            // are bound to the transaction.
            var toSign: [WmpSigningItem] = []
            for ref in params.credentialsToInclude ?? [] {
                guard let queryId = ref.credentialQueryId, let binding = plan.bindings[queryId],
                      let id = Int64(ref.credentialId), let cred = allCreds.first(where: { $0.id == id }) else {
                    throw SirosError.transactionData(TransactionDataError(
                        .invalidEntry, detail: "every credential in a WMP transaction presentation must be bound to the transaction"
                    ))
                }
                toSign.append(WmpSigningItem(cred: cred, ref: ref, binding: binding, queryId: queryId))
            }
            var parts: [String] = []
            for item in toSign {
                parts.append(try await keystore.signVpToken(
                    credential: item.cred.raw, disclosedClaims: item.ref.disclosedClaims, nonce: params.nonce,
                    audience: params.audience, transactionData: item.binding,
                    kid: plan.kid(for: item.queryId, fallback: item.cred.kid)
                ))
            }
            try Task.checkCancellation()   // after the final signing await: an ended flow gets no token and no record
            await plan.plan.complete(signed: true)
            return SignSubFlowResult(vpToken: parts.joined(separator: "\n"))
        } catch {
            if !Task.isCancelled && !(error is CancellationError) { await plan.plan.complete(signed: false) }
            throw error
        }
    }
}
