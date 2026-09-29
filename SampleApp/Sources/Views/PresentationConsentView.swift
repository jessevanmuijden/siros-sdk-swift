// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosWallet
import SirosCredentials

/// Multi-step presentation consent screen with selective disclosure.
///
/// Steps:
/// 1. Preview: verifier info and overview of what's requested
/// 2. Per-credential: select which claims to disclose
/// 3. Summary: confirm final selection before sharing
struct PresentationConsentView: View {
    @EnvironmentObject var viewModel: WalletViewModel
    @State private var currentStep = 0
    @State private var claimSelections: [String: Bool] = [:]

    var body: some View {
        guard let request = viewModel.pendingPresentation else {
            return AnyView(EmptyView())
        }

        // Unlike the Kotlin sample app's PresentationConsentScreen (which
        // tracks exhaustion per DCQL query/matchResult), this screen's
        // PresentationRequest is a single flat candidate list - so exhaustion
        // is computed once, for the whole request, rather than per query.
        let eligibleIds = Set(viewModel.eligibleCredentialIds(from: request.candidates))
        let isExhausted = !request.candidates.isEmpty && eligibleIds.isEmpty

        // A batch-issued credential contributes multiple interchangeable
        // StoredCredential copies (same batchId/credentialConfigurationId)
        // to `candidates` - one wizard step per raw candidate would show the
        // user 5 near-identical "choices" for what is really one credential
        // type. Collapse to one representative per unique credential type;
        // eligibleIds (used at Share time) still considers every raw
        // candidate, so the SDK - not the user - picks which physical copy
        // is actually used.
        let displayCandidates = uniqueRepresentativeCandidates(request.candidates)

        let totalSteps = displayCandidates.count + 2 // preview + per-cred + summary

        // NavigationStack + inline title matches every other sub-screen's
        // chrome (CredentialDetailView, etc.) instead of a bare, unchromed
        // VStack. No back toolbar button: the Decline/Back buttons below
        // already cover "leave this screen", and a back button that did
        // something different would be confusing.
        return AnyView(
            NavigationStack {
                VStack(spacing: 16) {
                    // Step progress bar
                    StepProgressBar(currentStep: currentStep, totalSteps: totalSteps)
                        .padding(.horizontal)

                    // Content
                    Group {
                        if currentStep == 0 {
                            previewStep(request, displayCandidates: displayCandidates, isExhausted: isExhausted)
                        } else if currentStep <= displayCandidates.count {
                            let cred = displayCandidates[currentStep - 1]
                            claimSelectionStep(credential: cred, requestedClaims: request.requestedClaims)
                        } else {
                            summaryStep(request, displayCandidates: displayCandidates)
                        }
                    }
                    .frame(maxWidth: .infinity, maxHeight: .infinity)

                    // Navigation buttons
                    HStack(spacing: 12) {
                        if currentStep == 0 {
                            Button(action: { viewModel.declinePresentation() }) {
                                HStack {
                                    Image(systemName: "xmark")
                                    Text(L10n.string("presentation.declineButton"))
                                }
                                .frame(maxWidth: .infinity)
                                .frame(height: 48)
                            }
                            .buttonStyle(.bordered)
                            .tint(.red)
                        } else {
                            Button(action: { currentStep -= 1 }) {
                                Text(L10n.string("presentation.backButton"))
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 48)
                            }
                            .buttonStyle(.bordered)
                        }

                        if currentStep < totalSteps - 1 {
                            Button(action: { currentStep += 1 }) {
                                Text(L10n.string("presentation.nextButton"))
                                    .frame(maxWidth: .infinity)
                                    .frame(height: 48)
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(SirosTheme.brand)
                        } else {
                            Button(action: {
                                viewModel.acceptPresentation(Array(eligibleIds))
                            }) {
                                HStack {
                                    Image(systemName: "checkmark")
                                    Text(L10n.string("presentation.shareButton"))
                                }
                                .frame(maxWidth: .infinity)
                                .frame(height: 48)
                            }
                            .buttonStyle(.borderedProminent)
                            .tint(SirosTheme.brand)
                            .disabled(isExhausted)
                        }
                    }
                    .padding(.horizontal)
                    .padding(.bottom)
                }
                .padding(.top, 16)
                .navigationTitle(L10n.string("presentation.title"))
                .navigationBarTitleDisplayMode(.inline)
                .onAppear { initializeSelections(displayCandidates, requestedClaims: request.requestedClaims) }
            }
        )
    }

    // MARK: - Step 1: Preview

    @ViewBuilder
    private func previewStep(_ request: PresentationRequest, displayCandidates: [StoredCredential], isExhausted: Bool) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                // The screen title itself now lives in the navigation bar, so
                // this just surfaces who's asking.
                //
                // The verified identity (client_id/DID/certificate subject) a
                // trust evaluation actually vouches for - shown, labeled as
                // such, when there's no declared display name to show
                // instead. Never used to replace a real name: a verifier
                // with no PDP-validated name gets a checkable identifier, not
                // something that reads like a friendly name it never earned.
                // See #167 - the backend no longer trusts/caches an
                // unvalidated client-supplied client_metadata.client_name, so
                // a nil verifierName is now common, not just a rare edge
                // case.
                let verifiedIdentity = request.verifierName == nil
                    ? (request.trustResult?.parsedScheme?.displayName ?? request.trustResult?.identifier)
                    : nil
                if let verifier = request.verifierName {
                    HStack(spacing: 12) {
                        Image(systemName: "info.circle.fill")
                            .font(.system(size: 28))
                            .foregroundColor(SirosTheme.brand)
                        Text(verifier)
                            .font(.title3.weight(.semibold))
                    }
                } else if let verifiedIdentity {
                    HStack(spacing: 12) {
                        Image(systemName: "info.circle.fill")
                            .font(.system(size: 28))
                            .foregroundColor(SirosTheme.brand)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(L10n.string("presentation.verifiedIdentity"))
                                .font(.caption)
                                .foregroundColor(SirosTheme.onSurfaceVariant)
                            Text(verifiedIdentity)
                                .font(.title3.weight(.semibold))
                        }
                    }
                }

                if let verifier = request.verifierName {
                    Text(L10n.string("presentation.requestingCredentials", verifier))
                        .font(.body)
                } else {
                    Text(L10n.string("presentation.requestingCredentialsUnknown"))
                        .font(.body)
                }

                // Reuses the exact same CredentialCardView as the main
                // credential list (including its batch "remaining copies"
                // ribbon) rather than a separate, simpler-looking
                // representation that risked reading as a different credential.
                let claimCount = request.requestedClaims.flatMap { $0 }.count
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(displayCandidates, id: \.id) { cred in
                        VStack(alignment: .leading, spacing: 4) {
                            CredentialCardView(credential: cred, instances: instances(for: cred))
                            Text(L10n.string("presentation.dataFieldsRequested", claimCount))
                                .font(.caption)
                                .foregroundColor(SirosTheme.onSurfaceVariant)
                        }
                    }
                    if isExhausted {
                        Text(L10n.string("presentation.noEligibleCopies"))
                            .font(.caption.bold())
                            .foregroundColor(SirosTheme.error)
                    }
                }
            }
            .padding(.horizontal)
        }
    }

    // MARK: - Step 2: Per-Credential Claim Selection

    @ViewBuilder
    private func claimSelectionStep(credential: StoredCredential, requestedClaims: [[String]]) -> some View {
        let claimMetaMap = Dictionary(
            uniqueKeysWithValues: (credential.metadata?.claims ?? []).map { ($0.path.joined(separator: "."), $0) }
        )
        let claims = requestedClaims.flatMap { $0 }.uniqued()

        ScrollView {
            VStack(alignment: .leading, spacing: 8) {
                CredentialCardView(credential: credential, instances: instances(for: credential))

                Spacer().frame(height: 8)

                Text(L10n.string("presentation.selectData"))
                    .font(.subheadline)
                    .fontWeight(.semibold)

                ForEach(claims, id: \.self) { claim in
                    let meta = claimMetaMap[claim]
                    let isRequired = meta?.mandatory == true || meta?.sd == "always"
                    let key = "\(credential.id):\(claim)"
                    let isOn = claimSelections[key] ?? true

                    HStack(spacing: 8) {
                        Toggle("", isOn: Binding(
                            get: { isOn },
                            set: { newValue in
                                if !isRequired {
                                    claimSelections[key] = newValue
                                }
                            }
                        ))
                        .toggleStyle(.switch)
                        .labelsHidden()
                        .disabled(isRequired)

                        VStack(alignment: .leading, spacing: 1) {
                            Text(meta?.label ?? formatClaimName(claim))
                                .font(.body)
                                .fontWeight(.medium)
                            if isRequired {
                                Text(L10n.string("presentation.required"))
                                    .font(.caption)
                                    .foregroundColor(SirosTheme.onSurfaceVariant)
                            } else if let desc = meta?.description {
                                Text(desc)
                                    .font(.caption)
                                    .foregroundColor(SirosTheme.onSurfaceVariant)
                            }
                        }

                        Spacer()
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(isOn ? SirosTheme.surfaceVariant : SirosTheme.surface)
                    )
                }
            }
            .padding(.horizontal)
        }
    }

    // MARK: - Step 3: Summary

    @ViewBuilder
    private func summaryStep(_ request: PresentationRequest, displayCandidates: [StoredCredential]) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                Image(systemName: "checkmark.circle.fill")
                    .font(.system(size: 28))
                    .foregroundColor(SirosTheme.brand)

                Text(L10n.string("presentation.readyToShare"))
                    .font(.title2.bold())

                let verifier = request.verifierName
                    ?? request.trustResult?.parsedScheme?.displayName
                    ?? request.trustResult?.identifier
                    ?? L10n.string("presentation.unknownVerifier")
                Text(L10n.string("presentation.sharingSummary", verifier))
                    .font(.body)
                    .foregroundColor(SirosTheme.onSurfaceVariant)

                ForEach(displayCandidates, id: \.id) { cred in
                    let claimMetaMap = Dictionary(
                        uniqueKeysWithValues: (cred.metadata?.claims ?? []).map { ($0.path.joined(separator: "."), $0) }
                    )
                    let disclosedClaims = request.requestedClaims.flatMap { $0 }.uniqued()
                        .filter { claimSelections["\(cred.id):\($0)"] ?? true }

                    VStack(alignment: .leading, spacing: 4) {
                        CredentialCardView(credential: cred, instances: instances(for: cred))
                        if !disclosedClaims.isEmpty {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(disclosedClaims, id: \.self) { claim in
                                    let meta = claimMetaMap[claim]
                                    Text("✓ \(meta?.label ?? formatClaimName(claim))")
                                        .font(.caption)
                                        .foregroundColor(SirosTheme.onSurfaceVariant)
                                }
                            }
                            .padding(12)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(
                                RoundedRectangle(cornerRadius: 12)
                                    .fill(SirosTheme.surfaceVariant)
                            )
                        }
                    }
                }
            }
            .padding(.horizontal)
        }
    }

    // MARK: - Helpers

    private func initializeSelections(_ displayCandidates: [StoredCredential], requestedClaims: [[String]]) {
        for cred in displayCandidates {
            let claimMetaMap = Dictionary(
                uniqueKeysWithValues: (cred.metadata?.claims ?? []).map { ($0.path.joined(separator: "."), $0) }
            )
            for claim in requestedClaims.flatMap({ $0 }) {
                let meta = claimMetaMap[claim]
                let key = "\(cred.id):\(claim)"
                let isRequired = meta?.mandatory == true || meta?.sd == "always"
                claimSelections[key] = isRequired || meta?.sd != "never"
            }
        }
    }

    /// Collapses raw candidates down to one representative per unique
    /// credential type, so a batch-issued credential's interchangeable
    /// copies (same batchId/credentialConfigurationId) don't each get their
    /// own wizard step - see the call site's comment for why.
    private func uniqueRepresentativeCandidates(_ candidates: [StoredCredential]) -> [StoredCredential] {
        var seen = Set<String>()
        var result: [StoredCredential] = []
        for cred in candidates {
            let key = cred.credentialConfigurationId ?? "\(cred.format):\(cred.batchId)"
            if seen.insert(key).inserted {
                result.append(cred)
            }
        }
        return result
    }

    /// Every batch instance of `credential` (see `StoredCredential.batchId`),
    /// so `CredentialCardView` can show the same "remaining copies" ribbon
    /// and exhausted-greying it uses in the main credential list.
    /// `groupForDisplay` needs every raw candidate in the batch to count
    /// remaining copies correctly, not just the one representative.
    private func instances(for credential: StoredCredential) -> [CredentialInstance] {
        let batchCandidates = viewModel.pendingPresentation?.candidates
            .filter { $0.batchId == credential.batchId } ?? [credential]
        return CredentialUtils.groupForDisplay(
            credentials: batchCandidates,
            presentationHistory: viewModel.currentPresentationHistory
        ).first(where: { $0.credential.batchId == credential.batchId })?.instances ?? []
    }

    private func formatClaimName(_ claim: String) -> String {
        claim.split(separator: ".").flatMap { $0.split(separator: "_") }
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }
}

// MARK: - Step Progress Bar

struct StepProgressBar: View {
    let currentStep: Int
    let totalSteps: Int

    var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<totalSteps, id: \.self) { step in
                RoundedRectangle(cornerRadius: 2)
                    .fill(step <= currentStep ? SirosTheme.brand : SirosTheme.border)
                    .frame(height: 4)
            }
        }
    }
}

// MARK: - Array extension for unique elements

private extension Array where Element: Hashable {
    func uniqued() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}
