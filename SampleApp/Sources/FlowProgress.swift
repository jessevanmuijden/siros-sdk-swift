// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosFlow

/// Localized display support for `FlowStepCatalog`'s raw FlowStep tokens.
/// Ordering/progress-fraction logic lives in the SDK now
/// (`FlowStepCatalog.flowStepProgress`) - this file only owns the
/// app-specific localized label mapping.

private let stepLabelKeys: [String: String] = [
    // The wallet's own steps before the engine's first progress event
    // (`WalletState.FlowActive.step*`). Entitlement and preparation reuse
    // the "fetching issuer information" wording, as the Kotlin sample app does.
    "initializing": "flow.steps.initializing",
    "connecting_engine": "flow.steps.initializing",
    "establishing_session": "flow.steps.initializing",
    "checking_entitlement": "flow.steps.fetchingMetadata",
    "preparing_issuance": "flow.steps.fetchingMetadata",
    "starting_flow": "flow.steps.parsingOffer",
    "parsing_offer": "flow.steps.parsingOffer",
    "offer_parsed": "flow.steps.offerParsed",
    "fetching_metadata": "flow.steps.fetchingMetadata",
    "metadata_fetched": "flow.steps.metadataFetched",
    "evaluating_trust": "flow.steps.evaluatingTrust",
    "trust_evaluated": "flow.steps.trustEvaluated",
    "awaiting_selection": "flow.steps.awaitingSelection",
    "authorization_required": "flow.steps.authorizationRequired",
    "exchanging_token": "flow.steps.exchangingToken",
    "token_obtained": "flow.steps.tokenObtained",
    "requesting_credential": "flow.steps.requestingCredential",
    "deferred": "flow.steps.deferred",
    "parsing_request": "flow.steps.parsingRequest",
    "request_parsed": "flow.steps.requestParsed",
    "evaluating_verifier_trust": "flow.steps.evaluatingVerifierTrust",
    "match_credentials": "flow.steps.matchCredentials",
    "awaiting_consent": "flow.steps.awaitingConsent",
    "credential_selection": "flow.steps.credentialSelection",
    "submitting_response": "flow.steps.submittingResponse",
    "waiting_for_reader": "flow.steps.waitingForReader",
    "reader_connected": "flow.steps.readerConnected",
]

/// Localized label for a raw FlowStep token, falling back to a generic
/// "Processing…" for unrecognized tokens.
func flowStepLabel(_ step: String) -> String {
    L10n.string(stepLabelKeys[step] ?? "flow.steps.unknown")
}

/// See `FlowStepCatalog.flowStepProgress`.
func flowStepProgress(flowType: String, step: String) -> Double? {
    FlowStepCatalog.flowStepProgress(flowType: flowType, step: step)
}
