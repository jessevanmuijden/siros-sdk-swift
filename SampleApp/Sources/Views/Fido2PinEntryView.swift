// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosKeystore

/// One in-flight FIDO2 ClientPin prompt plus how to answer it - fired from
/// `SampleAppAuthProvider.requestPin` (a synchronous, FFI-thread-blocking
/// callback - see its doc comment) whenever the "fido2" plugin needs the
/// authenticator's real PIN. `Identifiable` so it can drive a
/// `.sheet(item:)` presentation directly, mirroring `PendingWscdChoice`.
struct PendingFido2PinEntry: Identifiable {
    let id = UUID()
    /// What the SDK is asking for - enter the PIN, choose a new one, or confirm it - and why it repeats. The SDK runs
    /// the choose/confirm/compare logic; this sheet only shows each prompt.
    let request: PinRequest
    /// Call with the PIN the user entered, or `nil` to cancel.
    let respond: (String?) -> Void
}

/// Sheet shown when a FIDO2 plugin operation needs the authenticator's real
/// CTAP2 ClientPin PIN. Mirrors the Kotlin sample app's `PinEntryDialog`: a
/// single text field with a show/hide toggle so the user can visually
/// verify what they typed (found necessary during live hardware testing -
/// a silent typo/autocorrect is otherwise indistinguishable from a genuine
/// wrong-PIN authenticator rejection).
///
/// CTAP2 PINs aren't necessarily numeric (FIDO2 allows any UTF-8 PIN), so
/// this uses a general text keyboard rather than a numeric one.
struct Fido2PinEntryView: View {
    let pending: PendingFido2PinEntry

    @State private var pin: String = ""
    @State private var pinVisible = false
    @FocusState private var fieldFocused: Bool

    private var title: String {
        switch pending.request.kind {
        case .enterPin: return L10n.string("fido2.pinTitle")
        case .setNewPin: return L10n.string("fido2.choosePinTitle")
        case .confirmNewPin: return L10n.string("fido2.confirmPinTitle")
        }
    }

    private var description: String {
        switch pending.request.kind {
        case .enterPin: return L10n.string("fido2.pinDescription")
        case let .setNewPin(minLength): return L10n.string("fido2.choosePinDescription", minLength)
        case .confirmNewPin: return L10n.string("fido2.confirmPinDescription")
        }
    }

    private var retryMessage: String? {
        guard let retry = pending.request.retry else { return nil }
        switch retry {
        case let .tooShort(minLength): return L10n.string("fido2.retryTooShort", minLength)
        case .tooLong: return L10n.string("fido2.retryTooLong")
        case .invalidEncoding: return L10n.string("fido2.retryInvalidEncoding")
        case .policyViolation: return L10n.string("fido2.retryPolicy")
        case .mismatch: return L10n.string("fido2.retryMismatch")
        case .wrongPin: return L10n.string("fido2.retryWrongPin")
        }
    }

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 20) {
                HStack(spacing: 12) {
                    Image(systemName: "wave.3.right.circle.fill")
                        .font(.system(size: 28))
                        .foregroundColor(SirosTheme.brand)
                    Text(title)
                        .font(.title2.bold())
                }

                Text(description)
                    .font(.body)
                    .foregroundColor(SirosTheme.onSurfaceVariant)

                if let retry = retryMessage {
                    Text(retry)
                        .font(.callout)
                        .foregroundColor(.red)
                }

                HStack {
                    Group {
                        if pinVisible {
                            TextField(L10n.string("fido2.pinPlaceholder"), text: $pin)
                        } else {
                            SecureField(L10n.string("fido2.pinPlaceholder"), text: $pin)
                        }
                    }
                    .textFieldStyle(.roundedBorder)
                    .focused($fieldFocused)

                    Button(action: { pinVisible.toggle() }) {
                        Image(systemName: pinVisible ? "eye.slash" : "eye")
                            .foregroundColor(SirosTheme.onSurfaceVariant)
                    }
                }

                Spacer()

                HStack(spacing: 12) {
                    Button(action: { pending.respond(nil) }) {
                        Text(L10n.string("common.cancel"))
                            .frame(maxWidth: .infinity)
                            .frame(height: 48)
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)

                    Button(action: { pending.respond(pin) }) {
                        Text(L10n.string("fido2.submitButton"))
                            .frame(maxWidth: .infinity)
                            .frame(height: 48)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(SirosTheme.brand)
                    .disabled(pin.isEmpty)
                }
            }
            .padding()
            .navigationTitle(L10n.string("fido2.navTitle"))
            .navigationBarTitleDisplayMode(.inline)
            .onAppear { fieldFocused = true }
        }
    }
}
