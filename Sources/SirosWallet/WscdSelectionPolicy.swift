// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosKeystore

/// How long a `.chosen` answer from a `RequestWscdChoice` prompt should be
/// remembered - surfaced to the user via the choice sheet's scope selector
/// (and mirrored in Settings' "Preferred security key" / per-issuer override
/// sections), so a deliberate choice can outlive the single in-flight
/// issuance it was made for.
///
/// Distinct from - and orthogonal to - `WscdSelectionPolicy`'s existing TOFU
/// mechanism: TOFU is the SDK's own auto-remembered outcome of an otherwise-
/// ambiguous resolution, whereas a `.thisIssuer`/`.allIssuers` choice here is
/// an explicit user preference that intentionally OUTRANKS TOFU (see
/// `resolve`'s doc comment) and is tracked in its own separate persisted
/// state (`setUserOverride`/`setGlobalUserOverride`) rather than folded into
/// the TOFU map.
public enum WscdRememberScope: Sendable, Hashable {
    /// Use the chosen plugin for this single resolution only - no
    /// persistence of any kind, TOFU or override.
    case once
    /// Persist as a TOFU entry for this exact (issuer, credentialType) pair
    /// only - the existing per-pair TOFU mechanism, unchanged.
    case thisIssuer
    /// Persist as the global user override, applying to every (issuer,
    /// credentialType) pair that doesn't already have its own more-specific
    /// per-issuer user override.
    case allIssuers
}

/// The host app's answer to a `RequestWscdChoice` prompt - mirrors
/// `ProximityConsentResult`'s "chosen or cancelled" shape (see
/// `MdocProximitySession.RequestProximityConsent` in `SirosKeystore`), the
/// established pattern in this SDK for an async host-UI bridge callback.
public enum WscdChoiceResult: Sendable {
    case chosen(pluginId: String, rememberScope: WscdRememberScope)
    case cancelled
}

/// Asks the user to pick which registered WSCD plugin to use for an
/// about-to-be-issued credential, invoked only when more than one plugin
/// the host app has registered (`WalletConfig.availableKeystores`) meets
/// the credential type's declared key-storage assurance requirement - see
/// `WscdSelectionPolicy.resolve`. Implemented by the host app as an async
/// bridge to its own picker UI.
///
/// Only a plugin ID is returned (not a `KeystoreManager` instance) - the
/// SDK already holds the concrete instance via
/// `WalletConfig.availableKeystores`, since that dictionary is how the host
/// app registers what's available in the first place.
///
/// - Parameters:
///   - issuer: the credential issuer URL.
///   - credentialType: the vct (SD-JWT) or doctype (mdoc) being issued.
///   - eligiblePluginIds: every registered plugin ID whose static nominal
///     tier (`WscdPluginCapabilities`) meets the requirement - always 2 or
///     more when this callback is invoked (exactly one match is auto-picked
///     without a prompt, and zero matches is a hard error instead - see
///     `WscdSelectionError.noEligiblePlugin`).
public typealias RequestWscdChoice = @Sendable (
    _ issuer: String,
    _ credentialType: String,
    _ eligiblePluginIds: [String]
) async -> WscdChoiceResult

/// Thrown by `WscdSelectionPolicy.resolve` when key-storage selection
/// can't produce a plugin ID the caller may safely proceed with. Both cases
/// are deliberately distinct thrown signals rather than a soft `nil`
/// return: silently proceeding with an insufficient plugin (or falling back
/// to whatever the default keystore happens to be) would defeat this
/// feature's entire purpose - the issuer would still reject the resulting
/// Key Attestation, just later and less clearly than surfacing it here.
public enum WscdSelectionError: Error, Sendable, Equatable {
    /// Zero registered plugins' static nominal tier meets the credential
    /// type's declared requirement - there is nothing usable to fall back
    /// to at all.
    case noEligiblePlugin(issuer: String, credentialType: String, requiredTier: String)
    /// Two or more registered plugins meet the requirement (so there IS
    /// something usable), but nothing resolved which one to use: no
    /// `RequestWscdChoice` callback is configured, the user cancelled the
    /// prompt, or the callback answered with a plugin ID outside the
    /// eligible list it was given. Distinct from `noEligiblePlugin` so
    /// callers (and their own error handling/telemetry) can tell "nothing
    /// qualifies at all" apart from "several things qualified but nothing
    /// was chosen" - both must fail the same well-defined way (propagate,
    /// never silently proceed with a possibly-insufficient plugin), so both
    /// are handled identically by every caller of `resolve`.
    case ambiguousChoiceNotMade(issuer: String, credentialType: String, requiredTier: String)
    /// One or more registered plugins' nominal tier meets the requirement, but
    /// the user has not onboarded any of them (e.g. no FIDO2 token has been
    /// enrolled), so nothing can be used. Thrown BEFORE any key generation and
    /// therefore before any PIN prompt - the user is told there is no applicable
    /// WSCD instead of being asked for a PIN with no token behind it.
    /// `notOnboardedPluginIds` lists the sufficient-but-not-onboarded plugins (sorted).
    case wscdNotOnboarded(issuer: String, credentialType: String, requiredTier: String, notOnboardedPluginIds: [String])
}

extension WscdSelectionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .noEligiblePlugin(let issuer, let credentialType, let requiredTier):
            return "No available authenticator meets the required key-storage tier " +
                "(\(requiredTier)) for credential type \(credentialType) from issuer \(issuer)"
        case .ambiguousChoiceNotMade(let issuer, let credentialType, let requiredTier):
            return "Multiple authenticators meet the required key-storage tier " +
                "(\(requiredTier)) for credential type \(credentialType) from issuer \(issuer), " +
                "but no choice was made"
        case .wscdNotOnboarded(let issuer, let credentialType, let requiredTier, let notOnboarded):
            return "No applicable WSCD available: no authenticator has been set up for key-storage tier " +
                "\(requiredTier) (\(notOnboarded.joined(separator: ", "))), needed for " +
                "credential type \(credentialType) from issuer \(issuer)"
        }
    }
}

/// Resolves which registered WSCD plugin (`WalletConfig.availableKeystores`)
/// should back credential-issuance key generation for a given (issuer,
/// credential type) pair, BEFORE those keys are generated - so the wallet
/// finds out a plugin is insufficient up front instead of only when the
/// issuer later rejects a Key Attestation.
///
/// Phase-1 scope decision: no live plugin enumeration, no live per-plugin
/// capability query - eligibility is decided from `WscdPluginCapabilities`'s
/// static table alone, over whichever `KeystoreManager` instances the host
/// app has already constructed and registered. This type never constructs
/// or mutates a `KeystoreManager` itself, and never touches
/// siros-wscd-manager (Rust/UniFFI).
///
/// Resolution order (mirrors the Kotlin SDK's identical policy so both SDKs
/// behave the same way for host apps integrating either one):
/// 1. No declared requirement -> no-op (`nil`, use the existing default).
/// 2. A per-(issuer, credentialType) user override (`setUserOverride`),
///    still registered and still sufficient -> use it. This is an explicit,
///    deliberate user preference (NOT the same thing as TOFU - see
///    `WscdRememberScope`'s doc comment), so it's never itself written to
///    the TOFU map: it's already stable, separately-tracked state.
/// 3. Else the global user override (`setGlobalUserOverride`), still
///    registered and still sufficient -> use it.
/// 4. A persisted TOFU choice for this (issuer, credentialType) that's
///    still sufficient -> reuse it, no prompt.
/// 5. The host app's `WalletConfig.defaultWscdMapping` for this pair, if
///    sufficient -> persist as the new TOFU entry, no prompt.
/// 6. Exactly one registered plugin meets the requirement -> auto-pick,
///    persist as TOFU, no prompt.
/// 7. More than one meets the requirement -> ask the user via
///    `RequestWscdChoice`; `.chosen`'s `rememberScope` decides what (if
///    anything) gets persisted (see `WscdRememberScope`); `.cancelled`, no
///    callback configured, or an out-of-list answer all throw
///    `WscdSelectionError.ambiguousChoiceNotMade` - there's something
///    usable, but nothing was actually chosen, so proceeding silently would
///    risk using an insufficient plugin just as much as step 8 below.
/// 8. Zero registered plugins meet the requirement -> throws
///    `WscdSelectionError.noEligiblePlugin` (nothing usable to fall back to
///    at all).
///
/// Onboarding (steps 2-8): a plugin the user has not onboarded
/// (`isPluginOnboarded` - e.g. no FIDO2 token enrolled) is treated as if it
/// were not registered, at EVERY step including overrides/TOFU/default
/// mapping. If that leaves nothing while some sufficient plugin was merely
/// not onboarded, `WscdSelectionError.wscdNotOnboarded` is thrown - before any
/// key generation, hence before any PIN prompt. Fails closed: "cannot tell"
/// is "not onboarded".
// `@unchecked Sendable`: every mutable access (the persisted-mapping
// read-modify-write sequences) is guarded by `lock` internally - see its
// doc comment - matching this codebase's existing convention for types in
// this position (`InMemorySessionStore`, `KeychainSessionStore`). Callers
// are expected to invoke `resolve()` concurrently for different (issuer,
// credentialType) pairs (e.g. two credential types being issued near-
// simultaneously), so this must genuinely be safe to share across tasks.
public final class WscdSelectionPolicy: @unchecked Sendable {
    /// Sentinel issuer value for a per-(issuer, credentialType) user override
    /// that applies to ANY issuer of that credential type - checked in
    /// `resolve` as a fallback when no issuer-specific entry matches. Real-
    /// world need: TS11 registry discovery knows a credential *type* but has
    /// no issuer of its own to key an entry by - this constant is what makes
    /// those discovered mappings actually resolve, rather than silently
    /// never matching any real issuance. Mirrors the Kotlin SDK's
    /// `WscdSelectionPolicy.WILDCARD_ISSUER`.
    public static let wildcardIssuer = "*"

    private let sessionStore: SessionStoreProtocol
    private let defaultMapping: [String: String]
    private let requestChoice: RequestWscdChoice?

    /// Guards the read-modify-write sequence on every persisted map this
    /// policy owns (TOFU, per-issuer user overrides) against concurrent
    /// `resolve()` calls racing each other (e.g. two credential types being
    /// issued near-simultaneously) and dropping one update - last-writer-
    /// wins on an un-synchronized read-modify-write would otherwise silently
    /// lose whichever update lost the race. Matches this codebase's existing
    /// `NSLock`-around-a-critical-section convention (see `SirosWallet`'s
    /// own `lock`).
    private let lock = NSLock()

    public init(
        sessionStore: SessionStoreProtocol,
        defaultMapping: [String: String]? = nil,
        requestChoice: RequestWscdChoice? = nil
    ) {
        self.sessionStore = sessionStore
        self.defaultMapping = defaultMapping ?? [:]
        self.requestChoice = requestChoice
    }

    /// - Parameters:
    ///   - issuer: the credential issuer URL - half of the TOFU/default-mapping/
    ///     per-issuer-override key.
    ///   - credentialType: the vct/doctype being issued - the other half.
    ///   - requiredTier: the credential type's declared `attestation_los`
    ///     (`Vctm.requiredKeyStorage` / `MddlSchema.requiredKeyStorage`), or
    ///     `nil` if the type declared no requirement.
    ///   - availablePluginIds: `WalletConfig.availableKeystores.keys` - the
    ///     plugin IDs the host app has actually registered a ready
    ///     `KeystoreManager` instance for.
    /// - Returns: a plugin ID the caller should use instead of the default
    ///   keystore for this call, or `nil` meaning "no change needed."
    /// - Throws: `WscdSelectionError.noEligiblePlugin` or
    ///   `.ambiguousChoiceNotMade` - see their doc comments.
    public func resolve(
        issuer: String,
        credentialType: String,
        requiredTier: String?,
        availablePluginIds: [String],
        isPluginOnboarded: @Sendable (String) async -> Bool = { _ in true }
    ) async throws -> String? {
        // 1. No declared requirement - no-op.
        guard let requiredTier else { return nil }

        let key = Self.tofuKey(issuer: issuer, credentialType: credentialType)

        // Onboarding is only asked about plugins that could otherwise be
        // chosen (tier-sufficient), so a software plugin never costs a probe
        // and an insufficient-and-not-onboarded one is not misreported as the
        // cause. Not-onboarded plugins are dropped from everything below.
        var present: [String] = []
        var notOnboardedSufficient: [String] = []
        for id in Set(availablePluginIds) {
            guard isSufficient(id, for: requiredTier) else { present.append(id); continue }
            if await isPluginOnboarded(id) { present.append(id) } else { notOnboardedSufficient.append(id) }
        }
        let registered = Set(present)

        // 2. Per-(issuer, credentialType) user override - an explicit,
        // deliberate preference, checked first because it's the most
        // specific thing the user can have said. Validated exactly like
        // TOFU/default-mapping below: a stale (unregistered or since-
        // insufficient) override must fall through rather than being used
        // or erroring outright. Falls back to a `wildcardIssuer` entry (any
        // issuer, this credentialType) when no issuer-specific one matches -
        // see that constant's doc comment for why (TS11 discovery has no
        // real issuer to key an entry by).
        let overrides = readUserOverrides()
        if let override = overrides[key] ?? overrides[Self.tofuKey(issuer: Self.wildcardIssuer, credentialType: credentialType)],
           registered.contains(override), isSufficient(override, for: requiredTier) {
            return override
        }

        // 3. Global user override - same validation, applies whenever no
        // more-specific per-issuer override (above) was set/valid.
        if let global = readGlobalOverride(), registered.contains(global), isSufficient(global, for: requiredTier) {
            return global
        }

        // 4. TOFU hit, still registered and still sufficient. A cached
        // pluginId whose plugin was since unregistered (e.g. the host app
        // removed it from `availableKeystores`) must NOT be reused - falling
        // through here means it's re-evaluated against what's actually
        // registered by steps 5-8 instead, which can still throw
        // `noEligiblePlugin` if nothing else qualifies.
        if let cached = readTofu()[key], registered.contains(cached), isSufficient(cached, for: requiredTier) {
            return cached
        }

        // 5. Host-app-supplied default mapping - same registered-check as
        // TOFU above, since a stale/misconfigured mapping entry is the same
        // class of bug (silently falling back to the default keystore
        // instead of surfacing `noEligiblePlugin`).
        if let mapped = defaultMapping[key], registered.contains(mapped), isSufficient(mapped, for: requiredTier) {
            persistTofu(key: key, pluginId: mapped)
            return mapped
        }

        // 6/7/8. Compute eligibility over what's actually registered. Sorted
        // (rather than `availablePluginIds`'s incoming order, which callers
        // frequently derive from `Dictionary.keys` and is therefore not
        // guaranteed stable) so the host's choice-prompt UI sees the same
        // ordering across calls instead of one that varies with dictionary
        // iteration order.
        let eligible = present.filter { isSufficient($0, for: requiredTier) }.sorted()

        if eligible.count == 1 {
            persistTofu(key: key, pluginId: eligible[0])
            return eligible[0]
        }

        if eligible.count > 1 {
            guard let requestChoice else {
                throw WscdSelectionError.ambiguousChoiceNotMade(issuer: issuer, credentialType: credentialType, requiredTier: requiredTier)
            }
            switch await requestChoice(issuer, credentialType, eligible) {
            case .chosen(let pluginId, let rememberScope):
                // Guard against a host callback returning something outside
                // the `eligible` list it was just given (e.g. a UI bug) -
                // this is just as "nothing usable was actually chosen" as a
                // cancellation, so it throws the same way rather than being
                // trusted and persisted as-is.
                guard eligible.contains(pluginId) else {
                    throw WscdSelectionError.ambiguousChoiceNotMade(issuer: issuer, credentialType: credentialType, requiredTier: requiredTier)
                }
                switch rememberScope {
                case .once:
                    break
                case .thisIssuer:
                    persistTofu(key: key, pluginId: pluginId)
                case .allIssuers:
                    setGlobalUserOverride(pluginId: pluginId)
                }
                return pluginId
            case .cancelled:
                throw WscdSelectionError.ambiguousChoiceNotMade(issuer: issuer, credentialType: credentialType, requiredTier: requiredTier)
            }
        }

        // Zero eligible. If sufficient plugins exist but none is onboarded, say so
        // distinctly (before any PIN prompt) rather than a generic tier miss.
        if !notOnboardedSufficient.isEmpty {
            throw WscdSelectionError.wscdNotOnboarded(
                issuer: issuer, credentialType: credentialType, requiredTier: requiredTier,
                notOnboardedPluginIds: notOnboardedSufficient.sorted()
            )
        }
        throw WscdSelectionError.noEligiblePlugin(issuer: issuer, credentialType: credentialType, requiredTier: requiredTier)
    }

    private func isSufficient(_ pluginId: String, for requiredTier: String) -> Bool {
        guard let tier = WscdPluginCapabilities.tier(forPluginId: pluginId) else { return false }
        return WscdPluginCapabilities.meets(actual: tier, required: requiredTier)
    }

    static func tofuKey(issuer: String, credentialType: String) -> String {
        "\(issuer)|\(credentialType)"
    }

    // MARK: - TOFU inspection/management (host-app settings UI)

    /// Read-only snapshot of the currently persisted TOFU mapping
    /// (`"\(issuer)|\(credentialType)" -> pluginId`, see `tofuKey`) - lets a
    /// host app render/manage it, e.g. a settings screen listing which
    /// plugin was picked for which issuer/credential type, with an option to
    /// clear an entry and force fresh resolution (steps 5-8 of `resolve`'s
    /// doc comment) on the next matching issuance.
    public func currentTofuMapping() -> [String: String] {
        readTofu()
    }

    /// Clears one persisted TOFU entry, if present. `key` must be exactly
    /// one of `currentTofuMapping()`'s keys - this does not accept a raw
    /// `(issuer, credentialType)` pair, since either half could itself
    /// contain the `"|"` separator and there is no unambiguous way to
    /// reconstruct the exact key from its parts alone.
    public func clearTofuMapping(forKey key: String) {
        lock.lock(); defer { lock.unlock() }
        var map = readTofuLocked()
        map.removeValue(forKey: key)
        writeTofuLocked(map)
    }

    /// Clears every persisted TOFU entry.
    public func clearAllTofuMappings() {
        lock.lock(); defer { lock.unlock() }
        writeTofuLocked([:])
    }

    // MARK: - User override inspection/management (host-app settings UI)

    /// Sets (or overwrites) an explicit, deliberate per-(issuer,
    /// credentialType) user preference - distinct from TOFU (see
    /// `WscdRememberScope`'s doc comment) and checked ahead of it in
    /// `resolve`. Not validated against `requiredTier`/`registered` here -
    /// that's `resolve`'s job at the point it's actually used, so a since-
    /// increased requirement or an unregistered plugin correctly falls
    /// through instead of erroring out of this setter.
    public func setUserOverride(issuer: String, credentialType: String, pluginId: String) {
        let key = Self.tofuKey(issuer: issuer, credentialType: credentialType)
        lock.lock(); defer { lock.unlock() }
        var map = readUserOverridesLocked()
        map[key] = pluginId
        writeUserOverridesLocked(map)
    }

    /// Clears one persisted per-issuer user override, if present.
    public func clearUserOverride(issuer: String, credentialType: String) {
        let key = Self.tofuKey(issuer: issuer, credentialType: credentialType)
        lock.lock(); defer { lock.unlock() }
        var map = readUserOverridesLocked()
        map.removeValue(forKey: key)
        writeUserOverridesLocked(map)
    }

    /// Read-only snapshot of every persisted per-issuer user override
    /// (`"\(issuer)|\(credentialType)" -> pluginId`).
    public func currentUserOverrides() -> [String: String] {
        readUserOverrides()
    }

    /// Sets (or overwrites) the single global user override, applying to
    /// every (issuer, credentialType) pair that doesn't already have its
    /// own more-specific per-issuer override (see `resolve`'s doc comment).
    public func setGlobalUserOverride(pluginId: String) {
        lock.lock(); defer { lock.unlock() }
        sessionStore.wscdGlobalOverridePluginId = pluginId
    }

    /// Clears the global user override, if set.
    public func clearGlobalUserOverride() {
        lock.lock(); defer { lock.unlock() }
        sessionStore.wscdGlobalOverridePluginId = nil
    }

    /// The currently persisted global user override, if any.
    public func currentGlobalUserOverride() -> String? {
        lock.lock(); defer { lock.unlock() }
        return sessionStore.wscdGlobalOverridePluginId
    }

    // MARK: - TOFU persistence

    private func readTofu() -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        return readTofuLocked()
    }

    private func persistTofu(key: String, pluginId: String) {
        lock.lock(); defer { lock.unlock() }
        var map = readTofuLocked()
        map[key] = pluginId
        writeTofuLocked(map)
    }

    /// Callers must already hold `lock`.
    private func readTofuLocked() -> [String: String] {
        Self.decodeMapping(sessionStore.wscdTofuMappingJson)
    }

    /// Callers must already hold `lock`.
    private func writeTofuLocked(_ map: [String: String]) {
        sessionStore.wscdTofuMappingJson = Self.encodeMapping(map)
    }

    // MARK: - User override persistence

    private func readUserOverrides() -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        return readUserOverridesLocked()
    }

    /// Callers must already hold `lock`.
    private func readUserOverridesLocked() -> [String: String] {
        Self.decodeMapping(sessionStore.wscdUserOverrideMappingJson)
    }

    /// Callers must already hold `lock`.
    private func writeUserOverridesLocked(_ map: [String: String]) {
        sessionStore.wscdUserOverrideMappingJson = Self.encodeMapping(map)
    }

    private func readGlobalOverride() -> String? {
        lock.lock(); defer { lock.unlock() }
        return sessionStore.wscdGlobalOverridePluginId
    }

    // MARK: - Shared JSON blob encode/decode

    private static func decodeMapping(_ json: String?) -> [String: String] {
        guard let json,
              let data = json.data(using: .utf8),
              let decoded = try? JSONDecoder().decode([String: String].self, from: data) else {
            return [:]
        }
        return decoded
    }

    private static func encodeMapping(_ map: [String: String]) -> String? {
        guard let data = try? JSONEncoder().encode(map), let json = String(data: data, encoding: .utf8) else { return nil }
        return json
    }
}
