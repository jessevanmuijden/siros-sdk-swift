// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SwiftUI
import UIKit
import SirosCredentials
import SirosKeystore

/// ISO 18013-5 §8.2 device engagement, shown as a QR code (§8.2.2.3) AND
/// real "mdoc peripheral server mode" (`BlePeripheralServer`) AND "mdoc
/// central client mode" (`BleCentralClient`) BLE data-retrieval - the
/// engagement offers both BLE modes simultaneously (§8.2.2.3's `BleOptions`)
/// since it isn't known in advance which one a given reader will pick;
/// whichever one actually completes a presentation stops the other. This is
/// a genuinely completable proximity presentation, not just an engagement
/// demo, PROVIDED a stored credential's docType matches what the reader asks
/// for - and, now, provided the user approves the consent sheet this screen
/// shows once a matching credential family is found.
///
/// Ported from the Kotlin sample app's `ProximityEngagementScreen.kt`.
/// Unlike that screen, there is no NFC static handover here: iOS doesn't
/// allow third-party apps to emulate an NFC Type 4 Tag / act as an HCE host
/// the way Android's `HostApduService` does (that capability is restricted
/// to specific system frameworks, not general app code) - QR code plus both
/// BLE modes are this screen's engagement/retrieval mechanisms.
struct ProximityEngagementScreen: View {
    @EnvironmentObject var viewModel: WalletViewModel

    @State private var engagement: DeviceEngagement.Engagement?
    @State private var qrImage: UIImage?
    @State private var setupError: String?

    @State private var server: BlePeripheralServer?
    @State private var centralClient: BleCentralClient?

    /// Canonical step token (see `FlowProgress.swift`'s proximity step
    /// list), reported by whichever BLE mode is currently furthest along.
    @State private var currentStep = "waiting_for_reader"
    /// Set once either BLE mode reports completion (success or failure) -
    /// non-nil switches this screen to its terminal Close-button view.
    @State private var result: Bool?
    /// Per-role outcome, so a terminal failure is only reported once BOTH
    /// BLE roles have finished unsuccessfully - the two run concurrently, and
    /// one failing (e.g. central-client mode never finding a reader) must
    /// not preempt the other still succeeding shortly after. Mirrors a real
    /// completion-race bug fixed on the Kotlin SDK this was ported from
    /// (`ProximityEngagementScreen.kt`, fourth Copilot-review round): this
    /// screen previously set a single terminal `result` the instant either
    /// role's `onComplete` fired with `false`.
    @State private var peripheralOutcome: Bool?
    @State private var centralOutcome: Bool?
    @State private var pendingConsent: PendingConsent?
    /// The continuation box backing the CURRENTLY shown `pendingConsent`, if
    /// any - lets `.sheet(item:onDismiss:)`'s `onDismiss` resolve it if the
    /// sheet is dismissed WITHOUT the user tapping Share/Decline (e.g.
    /// swiping it away). See `requestConsent`'s doc comment.
    @State private var activeConsentBox: ConsentContinuationBox?

    var body: some View {
        NavigationStack {
            Group {
                if let setupError {
                    errorView(setupError)
                } else if let result {
                    ProximityTerminalView(success: result, onClose: { viewModel.closeActivate() })
                } else if currentStep != "waiting_for_reader" {
                    ProximityProgressView(step: currentStep)
                } else if let qrImage {
                    engagementView(qrImage)
                } else {
                    ProgressView()
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
            }
            .navigationTitle(L10n.string("proximity.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("flow.closeButton")) { viewModel.closeActivate() }
                }
            }
        }
        .onAppear(perform: setUpIfNeeded)
        .onDisappear {
            server?.stop()
            centralClient?.stop()
        }
        .sheet(item: $pendingConsent, onDismiss: {
            // Covers the sheet being dismissed WITHOUT the user tapping
            // Share/Decline (e.g. swiping it away) - the continuation would
            // otherwise hang forever with no way to resolve it. `resumeOnce`
            // is a no-op if the user already tapped Share/Decline (`respond`
            // already resumed it, which is what triggered this dismissal in
            // the first place) - see `requestConsent`'s doc comment.
            activeConsentBox?.resumeOnce(.denied)
            activeConsentBox = nil
        }) { consent in
            ProximityConsentSheet(
                consent: consent,
                filterEligible: { viewModel.filterEligibleForProximity($0) }
            )
        }
    }

    @ViewBuilder
    private func engagementView(_ qrImage: UIImage) -> some View {
        ScrollView {
            VStack(spacing: 16) {
                Text(L10n.string("proximity.scanPrompt"))
                    .font(.title3.weight(.medium))
                    .multilineTextAlignment(.center)

                Image(uiImage: qrImage)
                    .resizable()
                    .interpolation(.none)
                    .scaledToFit()
                    .frame(maxWidth: 280, maxHeight: 280)
                    .padding(.vertical, 8)

                Divider()

                Text(L10n.string("proximity.activeDescription"))
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(24)
        }
    }

    private func errorView(_ message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 40))
                .foregroundColor(.orange)
            Text("Could not start proximity engagement")
                .font(.headline)
            Text(message)
                .font(.footnote)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func setUpIfNeeded() {
        guard engagement == nil else { return }
        do {
            let engagement = try DeviceEngagement.create(
                supportsCentralClientMode: true,
                supportsPeripheralServerMode: true
            )
            self.engagement = engagement
            self.qrImage = QrCodeGenerator.generate(engagement.mdocUri)
            startBleModes(engagement: engagement)
        } catch {
            setupError = error.localizedDescription
        }
    }

    /// Wires up BOTH `BlePeripheralServer` and `BleCentralClient`
    /// simultaneously against the same engagement, mirroring the Kotlin
    /// screen's `DisposableEffect` block: a real reader can complete a
    /// presentation via whichever BLE mode it actually supports, and
    /// whichever one wins stops the other (which would otherwise just keep
    /// scanning/advertising for a connection that will never come).
    /// `peripheralServer`/`central` are declared as local `var`s (not
    /// `let`s) and captured by the OTHER mode's `onComplete` closure before
    /// being fully assigned - Swift closures capture local `var`s by
    /// reference, so this resolves correctly once both are assigned below,
    /// the same pattern Kotlin's `var peripheralServer: BlePeripheralServer? = null`
    /// relies on.
    private func startBleModes(engagement: DeviceEngagement.Engagement) {
        var peripheralServer: BlePeripheralServer?
        var central: BleCentralClient?

        let getCredentials: () async -> [StoredCredential] = { [viewModel] in
            await viewModel.getCredentialsForProximity()
        }
        let signPresentation: (Int64, [String]?, Data) async throws -> Data = { [viewModel] credentialId, disclosedClaims, sessionTranscriptBytes in
            try await viewModel.signMdocPresentationForProximity(
                credentialId: credentialId,
                disclosedClaims: disclosedClaims,
                sessionTranscriptBytes: sessionTranscriptBytes
            )
        }
        let filterEligible: ([StoredCredential]) -> [StoredCredential] = { [viewModel] instances in
            viewModel.filterEligibleForProximity(instances)
        }
        let evaluateReaderTrust: (_ x5chain: [[UInt8]]) async -> ReaderTrustResult = { [viewModel] x5chain in
            await viewModel.evaluateReaderTrustForProximity(x5chain)
        }

        // `onStep`/`onComplete` are invoked from `BlePeripheralServer`/
        // `BleCentralClient`'s own async Task contexts (kicked off from
        // CoreBluetooth delegate callbacks), which are NOT MainActor-isolated
        // - a real Copilot-review finding: after an `await` inside those
        // Tasks, execution can resume on a background thread, so mutating
        // `@State` directly here can trigger "Publishing changes from
        // background threads" and undefined SwiftUI behavior. Hop each
        // mutation onto the main actor explicitly rather than relying on the
        // caller's thread.
        peripheralServer = BlePeripheralServer(
            engagement: engagement,
            getCredentials: getCredentials,
            signPresentation: signPresentation,
            requestConsent: requestConsent,
            evaluateReaderTrust: evaluateReaderTrust,
            filterEligible: filterEligible,
            onStep: { step in Task { @MainActor in currentStep = step } },
            onLog: { message in print("[BlePeripheralServer] \(message)") },
            onComplete: { success in
                Task { @MainActor in
                    peripheralOutcome = success
                    if success {
                        // Whichever mode the reader actually picked has now
                        // finished - the other is just wasting radio time
                        // scanning/advertising for a connection that will
                        // never come, so stop it.
                        central?.stop()
                        result = true
                    } else if centralOutcome != nil {
                        // Only report terminal failure once the OTHER role
                        // has also finished/failed - it may yet succeed on
                        // its own.
                        result = false
                    }
                }
            }
        )
        central = BleCentralClient(
            engagement: engagement,
            getCredentials: getCredentials,
            signPresentation: signPresentation,
            requestConsent: requestConsent,
            evaluateReaderTrust: evaluateReaderTrust,
            filterEligible: filterEligible,
            onStep: { step in Task { @MainActor in currentStep = step } },
            onLog: { message in print("[BleCentralClient] \(message)") },
            onComplete: { success in
                Task { @MainActor in
                    centralOutcome = success
                    if success {
                        peripheralServer?.stop()
                        result = true
                    } else if peripheralOutcome != nil {
                        result = false
                    }
                }
            }
        )

        server = peripheralServer
        centralClient = central
        peripheralServer?.start()
        central?.start()
    }

    /// Bridges `BlePeripheralServer`/`BleCentralClient`'s async consent
    /// request to this screen's consent sheet: suspends the caller until the
    /// user taps Share or Decline in `ProximityConsentSheet`. Mirrors the
    /// Kotlin screen's `suspendCancellableCoroutine` bridge to a Compose
    /// `AlertDialog`.
    ///
    /// Thread-safety note: `BlePeripheralServer`/`BleCentralClient` create
    /// their `CBPeripheralManager`/`CBCentralManager` with `queue: nil`, so
    /// CoreBluetooth's OWN delegate callbacks are delivered on the main
    /// queue - but the plain `Task { ... }` spawned from those callbacks
    /// (see `BlePeripheralServer.handleDataWrite`) is NOT MainActor-isolated,
    /// so once this function is reached (after several `await`s inside that
    /// Task - parsing, `getCredentials()`, etc.) execution may already have
    /// hopped off the main thread, matching a real Copilot-review finding
    /// against this same pattern in `startProximityEngagement`'s
    /// `onStep`/`onComplete` closures. Explicitly hop the `@State` mutation
    /// onto the main actor below rather than assuming thread affinity.
    ///
    /// Cancellation note (Kotlin's fix used `suspendCancellableCoroutine`'s
    /// `invokeOnCancellation` to clear `pendingConsent` and guard `resume()`
    /// with an `isActive` check, for when the underlying BLE coroutine scope
    /// is torn down while the user hasn't answered yet): this screen never
    /// actually calls `Task.cancel()` on the BLE `Task`s awaiting this
    /// function (`stop()` only tears down the CoreBluetooth managers, not the
    /// Swift `Task` itself), so `withTaskCancellationHandler` would have
    /// nothing to hook here - Kotlin's specific trigger has no real Swift
    /// equivalent in this screen. The GENUINE equivalent gap in THIS SwiftUI
    /// screen is the user dismissing the consent sheet by swiping it away
    /// instead of tapping Share/Decline, which would otherwise leave this
    /// continuation suspended forever with no way to resolve it - handled via
    /// `.sheet(item:onDismiss:)`'s `onDismiss` (see `body`), which resumes
    /// `activeConsentBox` with `.denied` in that case. `ConsentContinuationBox`
    /// guards the resulting race the same way Kotlin's `isActive` check does:
    /// whichever of `respond`/`onDismiss` runs first wins, the other is a
    /// no-op.
    private func requestConsent(
        _ docType: String,
        _ requestedClaims: [String],
        _ matchingFamilies: [CredentialFamily],
        _ readerTrust: ReaderTrustResult?
    ) async -> ProximityConsentResult {
        await withCheckedContinuation { (continuation: CheckedContinuation<ProximityConsentResult, Never>) in
            let box = ConsentContinuationBox()
            box.set(continuation)
            Task { @MainActor in
                activeConsentBox = box
                pendingConsent = PendingConsent(
                    docType: docType,
                    requestedClaims: requestedClaims,
                    matchingFamilies: matchingFamilies,
                    readerTrust: readerTrust,
                    respond: { chosen in
                        // Triggers `.sheet(item:onDismiss:)`'s onDismiss too
                        // (setting the bound item to nil dismisses the sheet) -
                        // that's fine: `box.resumeOnce` below already wins the
                        // race, so onDismiss's own `resumeOnce(.denied)` call is
                        // a harmless no-op by the time it runs.
                        pendingConsent = nil
                        box.resumeOnce(chosen.map { ProximityConsentResult.approved($0) } ?? .denied)
                    }
                )
            }
        }
    }
}

/// Resumes a `ProximityConsentResult` continuation at most once, guarding
/// the race between the user answering via `PendingConsent.respond` and the
/// consent sheet being dismissed some other way (see `.sheet(item:onDismiss:)`
/// in `ProximityEngagementScreen.body`, and `requestConsent`'s doc comment).
/// Both call sites run on the main actor (SwiftUI button actions and
/// `onDismiss` alike), so no locking is needed here - just the
/// resume-at-most-once guard itself.
private final class ConsentContinuationBox {
    private var continuation: CheckedContinuation<ProximityConsentResult, Never>?

    func set(_ continuation: CheckedContinuation<ProximityConsentResult, Never>) {
        self.continuation = continuation
    }

    func resumeOnce(_ result: ProximityConsentResult) {
        let continuation = self.continuation
        self.continuation = nil
        continuation?.resume(returning: result)
    }
}

/// Progress bar + step label for an in-flight proximity presentation, once a
/// reader has connected - mirrors `FlowActiveView`'s look
/// (`ContentView.swift`) for the issuance/redirect-presentation flows, using
/// the "proximity" step list from `FlowProgress.swift`.
private struct ProximityProgressView: View {
    let step: String

    // Same monotonic guard as FlowActiveView: real execution order can
    // deviate slightly (e.g. both BLE modes reporting steps interleaved
    // before one wins), but the bar should never visibly un-progress.
    @State private var maxProgress: Double = 0

    private var stepProgress: Double? { flowStepProgress(flowType: "proximity", step: step) }

    var body: some View {
        VStack(spacing: 16) {
            if let stepProgress {
                ProgressView(value: maxProgress)
                    .tint(SirosTheme.brand)
                    .onAppear { maxProgress = max(maxProgress, stepProgress) }
                    .onChange(of: stepProgress) { _, newValue in
                        maxProgress = max(maxProgress, newValue)
                    }
            } else {
                ProgressView()
                    .scaleEffect(1.5)
                    .tint(SirosTheme.brand)
            }
            Text(flowStepLabel(step))
                .font(.body)
                .foregroundColor(SirosTheme.onSurfaceVariant)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(SirosTheme.background)
    }
}

/// Terminal state once a proximity presentation has completed or failed -
/// shows a clear "Close" action rather than "Cancel", since there is nothing
/// left to cancel: per this feature's explicit UX requirement, this screen
/// must not offer a Cancel button once the flow is done.
private struct ProximityTerminalView: View {
    let success: Bool
    let onClose: () -> Void

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: success ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.system(size: 64))
                .foregroundColor(success ? SirosTheme.brand : SirosTheme.error)
            Text(success ? L10n.string("flow.presentationSent") : L10n.string("proximity.presentationFailed"))
                .font(.title3.weight(.medium))
                .multilineTextAlignment(.center)
            Button(L10n.string("flow.closeButton"), action: onClose)
                .buttonStyle(.borderedProminent)
                .tint(SirosTheme.brand)
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(SirosTheme.background)
    }
}

/// Holds one in-flight consent request's details plus how to answer it - see
/// `RequestProximityConsent`. `Identifiable` so it can drive a
/// `.sheet(item:)` presentation directly.
private struct PendingConsent: Identifiable {
    let id = UUID()
    let docType: String
    let requestedClaims: [String]
    let matchingFamilies: [CredentialFamily]
    /// See `RequestProximityConsent`'s `readerTrust` parameter doc comment.
    let readerTrust: ReaderTrustResult?
    /// Call with the chosen family to approve, or nil to deny.
    let respond: (CredentialFamily?) -> Void
}

/// Consent sheet shown before a proximity presentation is signed and sent:
/// a recognizable preview of the actual credential (not just its raw
/// docType string, so the user can tell at a glance whether this is really
/// their own mDL/etc.), the actual requested claims, and - only if more
/// than one credential family matches - a picker to choose which to share.
/// Mirrors the Kotlin screen's `ProximityConsentDialog`.
private struct ProximityConsentSheet: View {
    let consent: PendingConsent
    /// See `BlePeripheralServer.filterEligible`'s doc comment. A family with
    /// zero eligible instances (every copy already used under the active
    /// consumption policy) is shown here, not silently omitted - so the user
    /// isn't confused about where their credential went - but disabled: the
    /// SDK refuses to sign with an exhausted instance regardless (defense in
    /// depth), so letting the user pick one here would just fail later.
    /// Mirrors the Kotlin screen's `ProximityConsentDialog`.
    let filterEligible: ([StoredCredential]) -> [StoredCredential]
    @State private var selected: CredentialFamily

    init(consent: PendingConsent, filterEligible: @escaping ([StoredCredential]) -> [StoredCredential]) {
        self.consent = consent
        self.filterEligible = filterEligible
        let eligible = consent.matchingFamilies.first(where: { !filterEligible($0.instances).isEmpty })
        _selected = State(initialValue: eligible ?? consent.matchingFamilies.first!)
    }

    private func isEligible(_ family: CredentialFamily) -> Bool {
        !filterEligible(family.instances).isEmpty
    }

    private var selectedIsEligible: Bool { isEligible(selected) }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    CredentialCardView(credential: selected.representative)

                    ReaderTrustBadge(readerTrust: consent.readerTrust)

                    Text(L10n.string("proximity.requestingClaims"))
                        .font(.subheadline)
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                    ForEach(consent.requestedClaims, id: \.self) { claim in
                        Text("• \(claim)")
                            .font(.body)
                    }

                    if consent.matchingFamilies.count > 1 {
                        Divider()
                        Text(L10n.string("proximity.multipleMatches"))
                            .font(.subheadline.weight(.semibold))
                        // Tappable-row selection (checkmark indicates the
                        // current choice) rather than a native SwiftUI
                        // `Picker` - matches this repo's existing
                        // tap-to-select convention for small in-app choice
                        // lists (see `WscdSettingsView.swift`'s
                        // `PluginChip`), adapted to full-width rows since
                        // each option here needs a full credential name.
                        ForEach(consent.matchingFamilies, id: \.representative.id) { family in
                            let eligible = isEligible(family)
                            Button(action: { if eligible { selected = family } }) {
                                HStack {
                                    Image(systemName: family == selected ? "checkmark.circle.fill" : "circle")
                                        .foregroundColor(family == selected ? SirosTheme.brand : SirosTheme.onSurfaceVariant)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(family.representative.metadata?.vct ?? family.representative.metadata?.doctype ?? consent.docType)
                                            .foregroundColor(eligible ? .primary : SirosTheme.onSurfaceVariant)
                                        if !eligible {
                                            Text(L10n.string("proximity.noCopiesLeft"))
                                                .font(.caption2)
                                                .foregroundColor(SirosTheme.error)
                                        }
                                    }
                                    Spacer()
                                }
                            }
                            .buttonStyle(.plain)
                            .disabled(!eligible)
                        }
                    }
                }
                .padding()
            }
            .navigationTitle(L10n.string("proximity.shareCredential"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(L10n.string("proximity.declineButton")) { consent.respond(nil) }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(L10n.string("proximity.shareButton")) { consent.respond(selected) }
                        .disabled(!selectedIsEligible)
                }
            }
        }
    }
}

/// RICAL reader-trust indicator for the consent sheet (Geneva 2026 interop
/// requirement: reader trust must be a visible, distinguishable signal, not
/// enforced/blocking). Three states: trusted (verified signature + trusted
/// chain), untrusted (verified signature but an untrusted/unresolved chain),
/// and no badge at all when `readerTrust` is nil - see `ReaderTrustResult`'s
/// doc comment for why "no `readerAuth`/invalid signature" is deliberately
/// silent rather than shown as "untrusted". Mirrors the Kotlin app's
/// `ReaderTrustBadge`.
private struct ReaderTrustBadge: View {
    let readerTrust: ReaderTrustResult?

    var body: some View {
        if let readerTrust {
            HStack(spacing: 6) {
                Image(systemName: readerTrust.trusted ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .foregroundColor(readerTrust.trusted ? SirosTheme.brand : SirosTheme.error)
                Text(label(for: readerTrust))
                    .font(.caption.weight(.medium))
                    .foregroundColor(readerTrust.trusted ? SirosTheme.brand : SirosTheme.error)
            }
        }
    }

    private func label(for readerTrust: ReaderTrustResult) -> String {
        if readerTrust.trusted {
            if let entityName = readerTrust.entityName {
                return "Trusted reader: \(entityName)"
            }
            return "Trusted reader"
        }
        if let reason = readerTrust.reason {
            return "Reader identity not trusted (\(reason))"
        }
        return "Reader identity not trusted"
    }
}
