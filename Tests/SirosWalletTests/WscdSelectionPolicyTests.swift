// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet

/// Pure logic, no keystore/CryptoKit dependency - unlike
/// `SirosWalletKeyAttestationTests`, this doesn't need a real `SirosWallet`
/// instance, so it isn't gated behind `#if canImport(CryptoKit)`.
final class WscdSelectionPolicyTests: XCTestCase {

    private func makePolicy(
        store: SessionStoreProtocol = InMemorySessionStore(),
        defaultMapping: [String: String]? = nil,
        requestChoice: RequestWscdChoice? = nil
    ) -> WscdSelectionPolicy {
        if let mem = store as? InMemorySessionStore {
            mem.activeAccountId = "test:account"
        }
        return WscdSelectionPolicy(sessionStore: store, defaultMapping: defaultMapping, requestChoice: requestChoice)
    }

    // 1. No declared requirement.
    func testNoRequirementIsNoOp() async throws {
        let policy = makePolicy()
        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: nil,
            availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertNil(result)
    }

    // Onboarding: no onboarded token must fail before anything can prompt.
    func testNotOnboardedOnlySufficientPluginThrowsWscdNotOnboarded() async {
        let policy = makePolicy()
        do {
            _ = try await policy.resolve(
                issuer: "https://issuer.example.com",
                credentialType: "urn:eu.europa.ec.eudi:pid:1",
                requiredTier: "iso_18045_high",
                availablePluginIds: ["softkey", "fido2"],
                isPluginOnboarded: { $0 != "fido2" }
            )
            XCTFail("expected WscdSelectionError.wscdNotOnboarded")
        } catch WscdSelectionError.wscdNotOnboarded(_, _, let tier, let notOnboarded) {
            XCTAssertEqual(tier, "iso_18045_high")
            XCTAssertEqual(notOnboarded, ["fido2"])
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    /// Each cached source is exercised on its own (a per-issuer override would
    /// otherwise return before TOFU/mapping were ever consulted).
    private func assertNotOnboardedPluginNotResolved(
        _ policy: WscdSelectionPolicy, file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await policy.resolve(
                issuer: "https://issuer.example.com", credentialType: "pid",
                requiredTier: "iso_18045_high", availablePluginIds: ["fido2"],
                isPluginOnboarded: { _ in false }
            )
            XCTFail("a not-onboarded plugin must not be resolved from a cached choice", file: file, line: line)
        } catch WscdSelectionError.wscdNotOnboarded {
        } catch {
            XCTFail("unexpected error \(error)", file: file, line: line)
        }
    }

    func testNotOnboardedPluginIgnoresTofu() async throws {
        let policy = makePolicy()
        // Seed TOFU by a normal (onboarded) resolution, and prove it is seeded.
        _ = try await policy.resolve(issuer: "https://issuer.example.com", credentialType: "pid",
                                     requiredTier: "iso_18045_high", availablePluginIds: ["fido2"])
        XCTAssertEqual(policy.currentTofuMapping()["https://issuer.example.com|pid"], "fido2")
        await assertNotOnboardedPluginNotResolved(policy)
    }

    func testNotOnboardedPluginIgnoresDefaultMapping() async {
        let policy = makePolicy(defaultMapping: ["https://issuer.example.com|pid": "fido2"])
        await assertNotOnboardedPluginNotResolved(policy)
    }

    func testNotOnboardedPluginIgnoresUserOverride() async {
        let policy = makePolicy()
        policy.setUserOverride(issuer: "https://issuer.example.com", credentialType: "pid", pluginId: "fido2")
        await assertNotOnboardedPluginNotResolved(policy)
    }

    func testNotOnboardedPluginIgnoresGlobalOverride() async {
        let policy = makePolicy()
        policy.setGlobalUserOverride(pluginId: "fido2")
        await assertNotOnboardedPluginNotResolved(policy)
    }

    func testNotOnboardedInsufficientPluginDoesNotMaskNoEligible() async {
        // An insufficient plugin not being onboarded is irrelevant: still a tier miss.
        let policy = makePolicy()
        do {
            _ = try await policy.resolve(
                issuer: "i", credentialType: "t", requiredTier: "iso_18045_high",
                availablePluginIds: ["softkey"], isPluginOnboarded: { _ in false }
            )
            XCTFail("expected noEligiblePlugin")
        } catch WscdSelectionError.noEligiblePlugin {
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testOnboardedPluginsStillResolveWhenAnotherIsNotOnboarded() async throws {
        // r2ps and fido2 both high; fido2 not onboarded -> r2ps auto-picked, no prompt.
        let policy = makePolicy()
        let picked = try await policy.resolve(
            issuer: "i", credentialType: "t", requiredTier: "iso_18045_high",
            availablePluginIds: ["fido2", "r2ps"], isPluginOnboarded: { $0 != "fido2" }
        )
        XCTAssertEqual(picked, "r2ps")
    }

    // 4. TOFU hit.
    func testTofuHitReusesPersistedChoiceWithoutPrompting() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        var promptCount = 0
        let policy = WscdSelectionPolicy(
            sessionStore: store,
            requestChoice: { _, _, eligible in
                promptCount += 1
                return .chosen(pluginId: eligible.first ?? "softkey", rememberScope: .thisIssuer)
            }
        )
        // First call has 2 eligible plugins ("fido2" and "r2ps" both meet "iso_18045_high"),
        // so it must ask - seed the TOFU entry via that first resolution.
        let first = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertNotNil(first)
        XCTAssertEqual(promptCount, 1)

        // Second call for the same (issuer, credentialType) must reuse the
        // TOFU entry without prompting again.
        let second = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(second, first)
        XCTAssertEqual(promptCount, 1, "must not prompt again once TOFU is persisted")
    }

    func testTofuEntryNoLongerSufficientIsIgnored() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        // Pre-seed a TOFU mapping pointing at "softkey" (basic tier only).
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        let json = try! JSONEncoder().encode([key: "softkey"])
        store.wscdTofuMappingJson = String(data: json, encoding: .utf8)

        let policy = WscdSelectionPolicy(sessionStore: store)
        // Now the credential type demands "iso_18045_high" - softkey no
        // longer qualifies, so it must fall through instead of blindly reusing it.
        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertEqual(result, "fido2", "must fall through to the one still-sufficient plugin, not the stale TOFU entry")
    }

    func testTofuEntryNoLongerRegisteredIsIgnored() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        // Pre-seed a TOFU mapping pointing at "fido2", which meets the tier
        // but is no longer in `availablePluginIds` below (e.g. the host app
        // unregistered it since the TOFU entry was persisted).
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        let json = try! JSONEncoder().encode([key: "fido2"])
        store.wscdTofuMappingJson = String(data: json, encoding: .utf8)

        let policy = WscdSelectionPolicy(sessionStore: store)
        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["r2ps"]
        )
        XCTAssertEqual(result, "r2ps", "a TOFU entry for an unregistered plugin must not be reused - must fall through to what's actually registered")
    }

    // 5. Default-mapping hit.
    func testDefaultMappingHitIsUsedAndPersistedAsTofu() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        let policy = WscdSelectionPolicy(sessionStore: store, defaultMapping: [key: "fido2"])

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(result, "fido2")

        // Persisted as TOFU: a fresh policy over the same store (no default
        // mapping this time) must still resolve to "fido2".
        let policyWithoutMapping = WscdSelectionPolicy(sessionStore: store)
        let second = try await policyWithoutMapping.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(second, "fido2")
    }

    func testInsufficientDefaultMappingIsIgnored() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        // Mapped plugin ("softkey") doesn't meet the required tier - must be skipped.
        let policy = WscdSelectionPolicy(sessionStore: store, defaultMapping: [key: "softkey"])

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertEqual(result, "fido2", "insufficient default mapping must fall through to auto single-match")
    }

    func testDefaultMappingEntryNoLongerRegisteredIsIgnored() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let key = "https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1"
        // Mapped plugin ("fido2") meets the tier but isn't actually registered.
        let policy = WscdSelectionPolicy(sessionStore: store, defaultMapping: [key: "fido2"])

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["r2ps"]
        )
        XCTAssertEqual(result, "r2ps", "a default mapping entry for an unregistered plugin must not be used - must fall through to what's actually registered")
        XCTAssertFalse(store.wscdTofuMappingJson?.contains("fido2") ?? false, "the unregistered mapped plugin must not be persisted as TOFU")
    }

    // 6. Auto single-match.
    func testAutoPicksSingleEligiblePluginWithoutPrompting() async throws {
        var promptCount = 0
        let policy = makePolicy(requestChoice: { _, _, eligible in
            promptCount += 1
            return .chosen(pluginId: eligible.first ?? "softkey", rememberScope: .thisIssuer)
        })

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        XCTAssertEqual(result, "softkey")
        XCTAssertEqual(promptCount, 0, "exactly one eligible plugin must not trigger a user prompt")
    }

    // 7. Ask-user, multiple eligible - chosen.
    func testMultipleEligibleAsksUserAndPersistsChoice() async throws {
        var capturedEligible: [String]?
        let policy = makePolicy(requestChoice: { issuer, credentialType, eligible in
            capturedEligible = eligible
            XCTAssertEqual(issuer, "https://issuer.example.com")
            XCTAssertEqual(credentialType, "org.iso.18013.5.1.mDL")
            return .chosen(pluginId: "r2ps", rememberScope: .thisIssuer)
        })

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(result, "r2ps")
        XCTAssertEqual(Set(capturedEligible ?? []), Set(["fido2", "r2ps"]))
    }

    // `availablePluginIds` is frequently derived from `Dictionary.keys`
    // (non-deterministic order) - the eligible subset passed to the choice
    // callback must be sorted so the host's picker UI sees a stable order
    // across calls instead of one that varies with dictionary iteration.
    func testEligiblePluginIdsPassedToChoiceCallbackAreSorted() async throws {
        var capturedEligible: [String]?
        let policy = makePolicy(requestChoice: { _, _, eligible in
            capturedEligible = eligible
            return .cancelled
        })

        // `.cancelled` now throws `ambiguousChoiceNotMade` (see the
        // dedicated tests for that) - irrelevant here, this test only cares
        // about what was passed INTO the callback before it answered.
        _ = try? await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            // Deliberately not pre-sorted.
            availablePluginIds: ["r2ps", "fido2"]
        )
        XCTAssertEqual(capturedEligible, ["fido2", "r2ps"], "must be sorted regardless of input order")
    }

    // 7. Ask-user, multiple eligible - cancelled. There IS something usable
    // (2+ eligible plugins), so this must throw `ambiguousChoiceNotMade`
    // rather than silently returning `nil` (which the caller would read as
    // "use the default keystore", possibly an insufficient one).
    func testMultipleEligibleCancelledThrowsAmbiguousChoiceNotMadeAndDoesNotPersist() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store, requestChoice: { _, _, _ in .cancelled })

        do {
            _ = try await policy.resolve(
                issuer: "https://issuer.example.com",
                credentialType: "org.iso.18013.5.1.mDL",
                requiredTier: "iso_18045_high",
                availablePluginIds: ["softkey", "fido2", "r2ps"]
            )
            XCTFail("expected WscdSelectionError.ambiguousChoiceNotMade")
        } catch WscdSelectionError.ambiguousChoiceNotMade(let issuer, let credentialType, let requiredTier) {
            XCTAssertEqual(issuer, "https://issuer.example.com")
            XCTAssertEqual(credentialType, "org.iso.18013.5.1.mDL")
            XCTAssertEqual(requiredTier, "iso_18045_high")
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
        XCTAssertNil(store.wscdTofuMappingJson, "a cancelled choice must not be persisted as TOFU")
    }

    // 7. Ask-user, host callback returns a pluginId outside the eligible
    // list it was given (e.g. a host UI bug) - just as "nothing usable was
    // chosen" as a cancellation, so it must throw the same error rather
    // than being trusted and persisted as-is.
    func testMultipleEligibleChoiceOutsideEligibleListThrowsAmbiguousChoiceNotMade() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        // "softkey" doesn't meet the required tier, so it's never in `eligible`.
        let policy = WscdSelectionPolicy(
            sessionStore: store,
            requestChoice: { _, _, _ in .chosen(pluginId: "softkey", rememberScope: .thisIssuer) }
        )

        do {
            _ = try await policy.resolve(
                issuer: "https://issuer.example.com",
                credentialType: "org.iso.18013.5.1.mDL",
                requiredTier: "iso_18045_high",
                availablePluginIds: ["softkey", "fido2", "r2ps"]
            )
            XCTFail("expected WscdSelectionError.ambiguousChoiceNotMade")
        } catch WscdSelectionError.ambiguousChoiceNotMade {
            // Expected.
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
        XCTAssertNil(store.wscdTofuMappingJson, "an invalid choice must not be persisted as TOFU")
    }

    // 7. No callback configured at all - still must throw, not silently
    // return `nil` (there IS something usable, just no way to ask).
    func testMultipleEligibleWithNoCallbackConfiguredThrowsAmbiguousChoiceNotMade() async throws {
        let policy = makePolicy(requestChoice: nil)
        do {
            _ = try await policy.resolve(
                issuer: "https://issuer.example.com",
                credentialType: "org.iso.18013.5.1.mDL",
                requiredTier: "iso_18045_high",
                availablePluginIds: ["softkey", "fido2", "r2ps"]
            )
            XCTFail("expected WscdSelectionError.ambiguousChoiceNotMade")
        } catch WscdSelectionError.ambiguousChoiceNotMade {
            // Expected.
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    // `WscdRememberScope.once` must not persist anything at all - neither
    // TOFU nor either override - the chosen plugin applies to this single
    // resolution only.
    func testChosenWithOnceScopeDoesNotPersistAnything() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store, requestChoice: { _, _, _ in .chosen(pluginId: "r2ps", rememberScope: .once) })

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(result, "r2ps")
        XCTAssertNil(store.wscdTofuMappingJson, "'once' must not persist a TOFU entry")
        XCTAssertNil(store.wscdUserOverrideMappingJson, "'once' must not persist a per-issuer override")
        XCTAssertNil(store.wscdGlobalOverridePluginId, "'once' must not persist a global override")
    }

    // `WscdRememberScope.allIssuers` must set the global user override, not TOFU.
    func testChosenWithAllIssuersScopeSetsGlobalOverrideNotTofu() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store, requestChoice: { _, _, _ in .chosen(pluginId: "r2ps", rememberScope: .allIssuers) })

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "org.iso.18013.5.1.mDL",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(result, "r2ps")
        XCTAssertEqual(policy.currentGlobalUserOverride(), "r2ps")
        XCTAssertEqual(policy.currentTofuMapping(), [:], "'allIssuers' must not also write a TOFU entry")
    }

    // 8. Zero eligible - hard error.
    func testZeroEligibleThrowsNoEligiblePlugin() async {
        let policy = makePolicy()
        do {
            _ = try await policy.resolve(
                issuer: "https://issuer.example.com",
                credentialType: "urn:eu.europa.ec.eudi:pid:1",
                requiredTier: "iso_18045_high",
                availablePluginIds: ["softkey"]
            )
            XCTFail("expected WscdSelectionError.noEligiblePlugin")
        } catch WscdSelectionError.noEligiblePlugin(let issuer, let credentialType, let requiredTier) {
            XCTAssertEqual(issuer, "https://issuer.example.com")
            XCTAssertEqual(credentialType, "urn:eu.europa.ec.eudi:pid:1")
            XCTAssertEqual(requiredTier, "iso_18045_high")
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    func testZeroEligibleWithEmptyAvailablePluginsThrows() async {
        let policy = makePolicy()
        do {
            _ = try await policy.resolve(
                issuer: "https://issuer.example.com",
                credentialType: "urn:eu.europa.ec.eudi:pid:1",
                requiredTier: "iso_18045_basic",
                availablePluginIds: []
            )
            XCTFail("expected WscdSelectionError.noEligiblePlugin")
        } catch WscdSelectionError.noEligiblePlugin {
            // Expected.
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    // Independent (issuer, credentialType) pairs must not clobber each other's TOFU entries.
    func testTofuIsScopedPerIssuerAndCredentialType() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        let resultA = try await policy.resolve(
            issuer: "https://issuer-a.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        let resultB = try await policy.resolve(
            issuer: "https://issuer-b.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["fido2"]
        )
        XCTAssertEqual(resultA, "softkey")
        XCTAssertEqual(resultB, "fido2")

        // Re-resolving issuer A must still get "softkey" from its own TOFU entry.
        let resultAAgain = try await policy.resolve(
            issuer: "https://issuer-a.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertEqual(resultAAgain, "softkey")
    }

    // MARK: - TOFU inspection/management (host-app settings UI)

    func testCurrentTofuMappingReflectsPersistedEntries() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)
        XCTAssertEqual(policy.currentTofuMapping(), [:])

        _ = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        XCTAssertEqual(
            policy.currentTofuMapping(),
            ["https://issuer.example.com|urn:eu.europa.ec.eudi:pid:1": "softkey"]
        )
    }

    func testClearTofuMappingForKeyRemovesOnlyThatEntry() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        _ = try await policy.resolve(
            issuer: "https://issuer-a.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        _ = try await policy.resolve(
            issuer: "https://issuer-b.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["fido2"]
        )
        XCTAssertEqual(policy.currentTofuMapping().count, 2)

        policy.clearTofuMapping(forKey: "https://issuer-a.example.com|urn:eu.europa.ec.eudi:pid:1")

        XCTAssertEqual(
            policy.currentTofuMapping(),
            ["https://issuer-b.example.com|urn:eu.europa.ec.eudi:pid:1": "fido2"]
        )
    }

    func testClearAllTofuMappingsRemovesEverything() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        _ = try await policy.resolve(
            issuer: "https://issuer-a.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_basic",
            availablePluginIds: ["softkey"]
        )
        _ = try await policy.resolve(
            issuer: "https://issuer-b.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["fido2"]
        )
        XCTAssertEqual(policy.currentTofuMapping().count, 2)

        policy.clearAllTofuMappings()

        XCTAssertEqual(policy.currentTofuMapping(), [:])
    }

    // MARK: - User override precedence (steps 2/3 of `resolve`'s doc comment)

    func testPerIssuerUserOverrideWinsOverTofu() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)
        let issuer = "https://issuer.example.com"
        let credentialType = "urn:eu.europa.ec.eudi:pid:1"

        // Seed a TOFU entry pointing at "fido2" via auto single-match.
        let tofuResult = try await policy.resolve(
            issuer: issuer, credentialType: credentialType,
            requiredTier: "iso_18045_high", availablePluginIds: ["fido2"]
        )
        XCTAssertEqual(tofuResult, "fido2")

        // A deliberate per-issuer override for "r2ps" must win over the
        // existing TOFU entry on the next resolution.
        policy.setUserOverride(issuer: issuer, credentialType: credentialType, pluginId: "r2ps")
        let result = try await policy.resolve(
            issuer: issuer, credentialType: credentialType,
            requiredTier: "iso_18045_high", availablePluginIds: ["fido2", "r2ps"]
        )
        XCTAssertEqual(result, "r2ps", "an explicit per-issuer user override must win over TOFU")
    }

    /// TS11 registry discovery knows a credential *type* but has no real
    /// issuer to key an override by - it saves under `wildcardIssuer`
    /// instead. `resolve` must fall back to that wildcard entry when no
    /// exact-issuer override exists, or a discovered mapping would silently
    /// never apply to any real presentation (the bug this test guards
    /// against - a discovered/toggled-on row previously had no effect at
    /// all, since `resolve` only ever checked the exact-issuer key).
    func testWildcardIssuerUserOverrideAppliesWhenNoExactIssuerOverrideExists() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)
        let credentialType = "urn:eu.europa.ec.eudi:pid:1"

        policy.setUserOverride(issuer: WscdSelectionPolicy.wildcardIssuer, credentialType: credentialType, pluginId: "fido2")

        let result = try await policy.resolve(
            issuer: "https://some-real-issuer.example.com", credentialType: credentialType,
            requiredTier: "iso_18045_high", availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertEqual(result, "fido2", "a wildcard-issuer override must apply to any real issuer of that credential type")
    }

    func testExactIssuerUserOverrideWinsOverWildcardIssuerOverride() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)
        let issuer = "https://issuer.example.com"
        let credentialType = "urn:eu.europa.ec.eudi:pid:1"

        policy.setUserOverride(issuer: WscdSelectionPolicy.wildcardIssuer, credentialType: credentialType, pluginId: "fido2")
        policy.setUserOverride(issuer: issuer, credentialType: credentialType, pluginId: "r2ps")

        let result = try await policy.resolve(
            issuer: issuer, credentialType: credentialType,
            requiredTier: "iso_18045_high", availablePluginIds: ["softkey", "fido2", "r2ps"]
        )
        XCTAssertEqual(result, "r2ps", "a more-specific exact-issuer override must win over the wildcard-issuer fallback")
    }

    func testGlobalUserOverrideWinsOverTofuButLosesToPerIssuerOverride() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)
        let issuerA = "https://issuer-a.example.com"
        let issuerB = "https://issuer-b.example.com"
        let credentialType = "urn:eu.europa.ec.eudi:pid:1"

        // Seed TOFU for issuer A pointing at "fido2".
        _ = try await policy.resolve(
            issuer: issuerA, credentialType: credentialType,
            requiredTier: "iso_18045_high", availablePluginIds: ["fido2"]
        )

        policy.setGlobalUserOverride(pluginId: "r2ps")
        policy.setUserOverride(issuer: issuerA, credentialType: credentialType, pluginId: "fido2")

        // Issuer A has its own more-specific override ("fido2") - that wins
        // over the global override ("r2ps").
        let resultA = try await policy.resolve(
            issuer: issuerA, credentialType: credentialType,
            requiredTier: "iso_18045_high", availablePluginIds: ["fido2", "r2ps"]
        )
        XCTAssertEqual(resultA, "fido2", "a per-issuer override must win over the global override")

        // Issuer B has no per-issuer override and no TOFU entry at all - the
        // global override applies, winning over what would otherwise be a
        // fresh TOFU resolution.
        let resultB = try await policy.resolve(
            issuer: issuerB, credentialType: credentialType,
            requiredTier: "iso_18045_high", availablePluginIds: ["fido2", "r2ps"]
        )
        XCTAssertEqual(resultB, "r2ps", "the global override must win over a fresh TOFU resolution")
    }

    func testUserOverrideNoLongerSufficientFallsThrough() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)
        let issuer = "https://issuer.example.com"
        let credentialType = "urn:eu.europa.ec.eudi:pid:1"

        // Override points at "softkey" (basic tier only).
        policy.setUserOverride(issuer: issuer, credentialType: credentialType, pluginId: "softkey")

        // The credential type now demands "iso_18045_high" - the override
        // no longer qualifies, so it must fall through rather than being
        // used (and rather than throwing - there's still "fido2" to fall
        // back to).
        let result = try await policy.resolve(
            issuer: issuer, credentialType: credentialType,
            requiredTier: "iso_18045_high", availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertEqual(result, "fido2", "an override that no longer meets the required tier must be skipped, falling through")
    }

    func testUserOverrideToUnregisteredPluginFallsThrough() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)
        let issuer = "https://issuer.example.com"
        let credentialType = "urn:eu.europa.ec.eudi:pid:1"

        // Override points at "fido2", which meets the tier but isn't
        // actually registered on this resolution.
        policy.setUserOverride(issuer: issuer, credentialType: credentialType, pluginId: "fido2")

        let result = try await policy.resolve(
            issuer: issuer, credentialType: credentialType,
            requiredTier: "iso_18045_high", availablePluginIds: ["r2ps"]
        )
        XCTAssertEqual(result, "r2ps", "an override for an unregistered plugin must be skipped, falling through to what's actually registered")
    }

    func testGlobalOverrideNoLongerSufficientOrUnregisteredFallsThrough() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        policy.setGlobalUserOverride(pluginId: "softkey")

        let result = try await policy.resolve(
            issuer: "https://issuer.example.com",
            credentialType: "urn:eu.europa.ec.eudi:pid:1",
            requiredTier: "iso_18045_high",
            availablePluginIds: ["softkey", "fido2"]
        )
        XCTAssertEqual(result, "fido2", "an insufficient global override must be skipped, falling through")
    }

    func testCurrentUserOverridesReflectsPersistedEntriesAndClearWorks() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        XCTAssertEqual(policy.currentUserOverrides(), [:])
        policy.setUserOverride(issuer: "https://issuer-a.example.com", credentialType: "pid", pluginId: "fido2")
        policy.setUserOverride(issuer: "https://issuer-b.example.com", credentialType: "pid", pluginId: "r2ps")
        XCTAssertEqual(policy.currentUserOverrides().count, 2)

        policy.clearUserOverride(issuer: "https://issuer-a.example.com", credentialType: "pid")
        XCTAssertEqual(policy.currentUserOverrides(), ["https://issuer-b.example.com|pid": "r2ps"])
    }

    func testCurrentGlobalUserOverrideReflectsPersistedValueAndClearWorks() {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        XCTAssertNil(policy.currentGlobalUserOverride())
        policy.setGlobalUserOverride(pluginId: "r2ps")
        XCTAssertEqual(policy.currentGlobalUserOverride(), "r2ps")
        policy.clearGlobalUserOverride()
        XCTAssertNil(policy.currentGlobalUserOverride())
    }

    // MARK: - Concurrency (TOFU/override read-modify-write must not race)

    /// Regression test for the un-synchronized TOFU read-modify-write bug:
    /// many concurrent `resolve()` calls for DISTINCT (issuer,
    /// credentialType) pairs, each auto-picking its single eligible plugin
    /// and persisting it as TOFU. Before the `NSLock` fix, two concurrent
    /// persistTofu read-modify-write sequences could race and one's update
    /// would be silently dropped (last-writer-wins on a stale read) -
    /// asserting every single one of N entries survived is exactly the
    /// condition that fix guarantees.
    func testConcurrentResolutionsForDistinctKeysDoNotDropTofuEntries() async throws {
        let store = InMemorySessionStore()
        store.activeAccountId = "test:account"
        let policy = WscdSelectionPolicy(sessionStore: store)

        let count = 50
        try await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<count {
                group.addTask {
                    _ = try await policy.resolve(
                        issuer: "https://issuer-\(i).example.com",
                        credentialType: "urn:eu.europa.ec.eudi:pid:1",
                        requiredTier: "iso_18045_basic",
                        availablePluginIds: ["softkey"]
                    )
                }
            }
            for try await _ in group {}
        }

        XCTAssertEqual(policy.currentTofuMapping().count, count, "every concurrent resolution's TOFU entry must survive - none dropped by a lost read-modify-write race")
    }
}
