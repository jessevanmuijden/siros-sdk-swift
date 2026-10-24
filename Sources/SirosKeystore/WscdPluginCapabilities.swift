// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Static, SDK-side table of each known WSCD plugin's nominal key-storage
/// assurance tier (ISO 18045 vocabulary), used by `WscdSelectionPolicy` to
/// pick a plugin capable of meeting a credential type's declared
/// `attestation_los` requirement BEFORE the wallet generates issuance keys,
/// instead of finding out only when the issuer later rejects a Key
/// Attestation for insufficient key storage.
///
/// Phase-1 scope decision: no changes to siros-wscd-manager (Rust/UniFFI) -
/// no live plugin enumeration, no live per-plugin capability query. This is
/// a small static table of the 3 known plugin IDs' nominal tier, nothing
/// more. In particular, `"r2ps"`'s tier here is a best-effort/config-
/// dependent guess: a real R2PS deployment's actual assurance depends on
/// the backing HSM, which this table has no way to observe. Treat
/// `"r2ps" -> iso_18045_high` as a nominal ceiling for Phase 1, not a
/// guarantee - a future phase that adds live capability query should
/// replace this entry (and this whole table) with something that actually
/// asks the plugin.
public enum WscdPluginCapabilities {
    /// ISO 18045 assurance tier vocabulary, ascending order (each entry
    /// meets every requirement at or below its own index).
    public static let tierOrder = ["iso_18045_basic", "iso_18045_moderate", "iso_18045_high"]

    /// Known plugin ID -> nominal ISO 18045 tier. Plugin IDs match the
    /// ones `FfiWscdConfig(defaultPlugin:)` accepts and the sample app's
    /// plugin chooser offers (`WscaDeveloperView`): `"softkey"`, `"r2ps"`,
    /// `"fido2"`.
    public static let pluginTiers: [String: String] = [
        "softkey": "iso_18045_basic",
        "fido2": "iso_18045_high",
        // Best-effort/config-dependent - see the type's doc comment above.
        "r2ps": "iso_18045_high",
    ]

    /// Plugins with an enrollment ("onboarding") step: the user must register a
    /// token/key before the plugin can sign anything (and before a PIN means
    /// anything). `softkey` has none; `r2ps` enrolment is server-side lifecycle
    /// state this SDK does not track here, so it is not gated by this set.
    public static let onboardingRequiredPluginIds: Set<String> = ["fido2"]

    /// The nominal tier for a known plugin ID, or `nil` if the ID isn't in
    /// the static table (an unknown/future plugin ID is never eligible for
    /// anything - see `meets`).
    public static func tier(forPluginId pluginId: String) -> String? {
        pluginTiers[pluginId]
    }

    /// Whether `actual` meets or exceeds `required` in the ascending
    /// `tierOrder`. Either value being outside `tierOrder` (an unrecognized
    /// tier string) is treated as "does not meet" rather than a crash -
    /// callers should surface that as "not eligible", not fail hard.
    public static func meets(actual: String, required: String) -> Bool {
        guard let actualIndex = tierOrder.firstIndex(of: actual),
              let requiredIndex = tierOrder.firstIndex(of: required) else {
            return false
        }
        return actualIndex >= requiredIndex
    }
}
