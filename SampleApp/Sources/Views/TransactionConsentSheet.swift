// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet
import SirosCredentials

/// One in-flight transaction-consent prompt (EC TS12) plus how to answer it.
/// `Identifiable` so it drives a `.sheet(item:)`, like `PendingWscdChoice`.
struct PendingTransactionConsent: Identifiable {
    let id = UUID()
    let request: TransactionConsentRequest
    /// `true` confirms, `false` declines.
    let respond: (Bool) -> Void
}

/// Bridges the SDK's `TransactionConsentHandler.confirm` to the sheet:
/// suspends until the user answers, resuming at most once. All TS12 logic
/// lives in the SDK; this only shows what the SDK built.
final class TransactionConsentContinuationBox {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Bool, Never>?
    private var cancelled = false

    /// Installs the continuation. Returns `false` (having resumed it with
    /// `false`) when the box was cancelled before it was installed.
    func set(_ continuation: CheckedContinuation<Bool, Never>) -> Bool {
        lock.lock()
        if cancelled { lock.unlock(); continuation.resume(returning: false); return false }
        self.continuation = continuation
        lock.unlock()
        return true
    }

    /// Whether the box still awaits an answer: installed, not answered, not cancelled.
    var isPending: Bool {
        lock.lock(); defer { lock.unlock() }
        return continuation != nil && !cancelled
    }

    func resumeOnce(_ answer: Bool) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: answer)
    }

    /// Declines, whether or not the continuation has been installed yet.
    func cancel() {
        // Mark and take the continuation under ONE lock, so a simultaneous confirm
        // cannot slip in between and return consent after the deadline already won.
        lock.lock()
        cancelled = true
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(returning: false)
    }
}

/// The handler registered on `SirosWallet.transactionConsentHandler`.
final class TransactionConsentBridge: TransactionConsentHandler, @unchecked Sendable {
    private weak var viewModel: WalletViewModel?

    init(viewModel: WalletViewModel) { self.viewModel = viewModel }

    func confirm(_ request: TransactionConsentRequest) async throws -> Bool {
        guard let viewModel else { return false }
        return await viewModel.requestTransactionConsent(request)
    }
}

/// Shows a transaction for confirmation (TS12 3.3): level 1 fields
/// prominently, levels 2 and 3 below, level 4 omitted, the labels exactly as
/// the SDK model gives them, and a warning that must be acknowledged when the
/// request is not signed (TS12 3.1).
struct TransactionConsentSheet: View {
    @EnvironmentObject var viewModel: WalletViewModel
    let pending: PendingTransactionConsent
    @State private var acknowledgedUnsigned = false

    private var request: TransactionConsentRequest { pending.request }
    private var requiresAcknowledgement: Bool { request.requestSigned == false }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    if requiresAcknowledgement { unsignedWarning }

                    VStack(alignment: .leading, spacing: 4) {
                        Text(L10n.string("transactionConsent.verifier", request.verifier))
                        Text(L10n.string("transactionConsent.credential", request.credentialName))
                    }
                    .font(.subheadline)
                    .foregroundColor(SirosTheme.onSurfaceVariant)

                    ForEach(Array(request.entries.enumerated()), id: \.offset) { _, entry in
                        entryView(entry)
                    }

                    attributesView

                    actions
                }
                .padding()
            }
            .navigationTitle(L10n.string("transactionConsent.title"))
            .navigationBarTitleDisplayMode(.inline)
            // SwiftUI clears the `.sheet(item:)` binding BEFORE this runs on an interactive
            // dismissal, so the view model's current prompt cannot be consulted. Answer
            // through THIS sheet's own response instead: it is bound to its own box, a
            // second answer is a no-op, and a stale callback cannot touch a newer prompt.
            .onDisappear { pending.respond(false) }
        }
    }

    /// What will be shared along with the transaction (TS12 3.3.1).
    @ViewBuilder private var attributesView: some View {
        let shown = request.attributes.filter { !$0.claims.isEmpty }
        if !shown.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                Text(L10n.string("transactionConsent.attributesTitle"))
                    .font(.caption.weight(.semibold))
                    .foregroundColor(SirosTheme.onSurfaceVariant)
                ForEach(Array(shown.enumerated()), id: \.offset) { _, group in
                    Text("\(group.credentialName): \(group.claims.joined(separator: ", "))")
                        .font(.footnote)
                }
            }
        }
    }

    private var unsignedWarning: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(L10n.string("transactionConsent.unsignedWarningTitle"), systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundColor(SirosTheme.error)
            Text(L10n.string("transactionConsent.unsignedWarningBody"))
                .font(.subheadline)
            Toggle(L10n.string("transactionConsent.unsignedAcknowledge"), isOn: $acknowledgedUnsigned)
                .font(.subheadline)
        }
        .padding()
        .background(RoundedRectangle(cornerRadius: 10).fill(SirosTheme.surfaceVariant))
    }

    private func entryView(_ entry: TransactionConsentEntry) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            // Each entry shows its own title, so none of them goes unseen.
            if let title = entry.title {
                Text(title).font(.headline)
            }
            Text(entry.typeName)
                .font(.caption.weight(.semibold))
                .foregroundColor(SirosTheme.onSurfaceVariant)
            // Level 4 may be omitted; levels 1 to 3 are shown, 1 prominently.
            ForEach(Array(entry.fields.filter { $0.level <= 3 }.enumerated()), id: \.offset) { _, field in
                if field.level == 1 {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(field.label).font(.caption).foregroundColor(SirosTheme.onSurfaceVariant)
                        Text(field.value).font(.title.bold())
                    }
                } else {
                    HStack(alignment: .firstTextBaseline) {
                        Text(field.label).font(.subheadline).foregroundColor(SirosTheme.onSurfaceVariant)
                        Spacer()
                        Text(field.value).font(.body)
                    }
                }
            }
            if let hint = entry.securityHint {
                Text(hint)
                    .font(.footnote)
                    .foregroundColor(SirosTheme.onSurfaceVariant)
                    .padding(.top, 4)
            }
        }
    }

    private var actions: some View {
        // One button answers for every entry, so a label is used only when the
        // SDK says all entries share it; otherwise the app's own wording.
        return VStack(spacing: 10) {
            Button(action: { pending.respond(true) }) {
                Text(request.commonAffirmativeLabel ?? L10n.string(request.entries.count > 1 ? "transactionConsent.confirmAll" : "transactionConsent.confirm"))
                    .frame(maxWidth: .infinity, minHeight: 48)
            }
            .buttonStyle(.borderedProminent)
            .disabled(requiresAcknowledgement && !acknowledgedUnsigned)

            Button(action: { pending.respond(false) }) {
                Text(request.commonDenialLabel ?? L10n.string("transactionConsent.cancel"))
                    .frame(maxWidth: .infinity, minHeight: 48)
            }
            .buttonStyle(.bordered)
            .tint(.red)
        }
    }
}

/// The transaction log (TS12 5.3): a plain list of what the SDK recorded.
struct TransactionLogView: View {
    @EnvironmentObject var viewModel: WalletViewModel

    var body: some View {
        NavigationStack {
            Group {
                if viewModel.transactionLog.isEmpty {
                    Text(L10n.string("transactionLog.empty"))
                        .font(.body)
                        .foregroundColor(SirosTheme.onSurfaceVariant)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    List(viewModel.transactionLog, id: \.id) { entry in
                        TransactionLogRow(entry: entry)
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle(L10n.string("transactionLog.title"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button(L10n.string("nav.back")) { viewModel.closeTransactionLog() }
                }
            }
        }
    }
}

struct TransactionLogRow: View {
    let entry: TransactionLogEntry

    private var icon: String {
        switch entry.outcome {
        case .consented: return "checkmark.circle.fill"
        case .declined: return "hand.raised.circle.fill"
        case .refused: return "xmark.circle.fill"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Image(systemName: icon)
                // Text from a request is neutralised again at render: an entry read back from storage
                // did not necessarily go through the SDK's sanitising initialiser.
                Text(entry.typeName.map(TransactionLogEntry.displaySafe) ?? L10n.string("transactionLog.unknownType")).font(.body.weight(.medium)).lineLimit(2)
                Spacer()
                Text(L10n.string("transactionLog.outcome.\(entry.outcome.rawValue)")).font(.caption)
            }
            if let id = entry.transactionId {
                Text(L10n.string("transactionLog.transactionId", TransactionLogEntry.displaySafe(id))).font(.caption).lineLimit(2)
            }
            ForEach(entry.entities.sorted(by: { $0.key < $1.key }), id: \.key) { key, value in
                Text("\(L10n.string("transactionLog.entity.\(key)")): \(TransactionLogEntry.displaySafe(value))").font(.caption).lineLimit(2)
            }
            Text(TransactionLogEntry.displaySafe(entry.verifier)).font(.caption).lineLimit(2).foregroundColor(SirosTheme.onSurfaceVariant)
            if let reason = entry.reason {
                Text(L10n.string("transactionLog.reasons.\(reason)")).font(.caption).foregroundColor(SirosTheme.error)
            }
            Text(Date(timeIntervalSince1970: Double(entry.timestamp) / 1000).formatted(date: .abbreviated, time: .shortened))
                .font(.caption2)
                .foregroundColor(SirosTheme.onSurfaceVariant)
        }
        .padding(.vertical, 4)
    }
}
