// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosTransport

/// Default, host-resolvable English wording for `WalletEventListener.onFlowError`
/// when an issuance is refused because its issuer was not established as
/// trusted. Matches the Kotlin SDK's `siros_issuer_not_trusted` string.
let issuerNotTrustedMessage = "This issuer could not be verified as trusted, so the credential was not added."

/// The single issuance trust policy: a credential is stored only if its issuer's
/// trust has been established. Fails closed - anything short of an affirmative
/// result refuses the whole issuance.
///
/// - The engine's server-side issuer evaluation (`trust_evaluated` progress)
///   said `trusted: false` for this flow: refuse. (The engine already errors the
///   flow in that case; this is the wallet's own defence in depth. An ABSENT
///   report is not treated as untrusted: the engine emits none in its
///   permissive no-PDP mode.)
/// - Every `mso_mdoc` credential must have a verifiable `issuerAuth` and
///   `mdocTrust` must return `trusted: true` for it. `nil` (no x5chain, bad
///   signature, unparseable, or a platform that cannot verify it) refuses.
///   `mdocTrust` is `SirosWallet.evaluateIssuerTrust`, whose own rule already
///   restricts the weaker local fallback to a genuinely unreachable backend.
/// - No cached positive ever stands in for an evaluation here.
///
/// Ported from the Kotlin SDK's `issuanceTrustRefusal`
/// (https://github.com/sirosfoundation/siros-sdk-kotlin/pull/276).
///
/// - Returns: nil when issuance may proceed, else a short non-secret reason for
///   logs and the host.
func issuanceTrustRefusal(
    credentials: [CredentialResult],
    engineTrust: IssuerTrustReport?,
    mdocTrust: (CredentialResult) async -> TrustResult?
) async -> String? {
    if let engineTrust, !engineTrust.trusted {
        return "issuer trust evaluation by the wallet backend was negative"
            + (engineTrust.reason.map { ": \($0)" } ?? "")
    }
    for credential in credentials where credential.format == "mso_mdoc" {
        guard let trust = await mdocTrust(credential) else {
            return "mdoc issuerAuth is missing or could not be verified"
        }
        if !trust.trusted {
            return "mdoc issuer is not trusted" + (trust.reason.map { ": \($0)" } ?? "")
        }
    }
    return nil
}
