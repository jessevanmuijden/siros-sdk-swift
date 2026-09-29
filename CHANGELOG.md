# Changelog

All notable changes to the SIROS SDK for iOS/macOS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.14.1] - 2026-09-29

### Fixed
- **Presentation consent screen now shows a verified identity when there's
  no declared display name.** The backend no longer trusts/caches an
  unvalidated client-supplied `client_metadata.client_name` for the
  verifier consent screen, so a `nil` verifier name is now common. The
  consent screen now falls back to the verified `client_id`/DID/
  certificate subject, labeled "Verified identity", when there's no
  declared name (#167).
- **`did:`-scheme verifiers and issuers can now be resolved when the
  engine defers to the frontend.** go-wallet-backend sets
  `requires_resolution: true` / `request_jwt` / `resolution_subject_id`
  on a trust evaluation when it cannot resolve a `did:`-scheme subject's
  key material itself (no verifier PDP configured). Both the legacy
  engine path and the WMP transport now resolve the DID document via
  `POST /v1/resolve` and verify `request_jwt` against the EXACT
  verification method its JOSE `kid` names (comparing full normalized
  identifiers, never just fragments, so a method belonging to a
  different DID can't collide) - for a `credential_issuer`, which has no
  signed request object to verify against, every resolved verification
  method is forwarded instead. Fails closed on a denied AuthZEN
  `decision`, a missing/unmatched `kid`, or a signature that doesn't
  verify (#168).

## [0.14.0] - 2026-09-21

### Fixed
- **A credential is matched on the vct it carries, not on its metadata.**
  DCQL matching read `credential.metadata?.vct`, which is a rendering
  artefact rather than the credential's identity: it is absent until an
  issuance flow has an offer to build it from, and the hydration pass that
  repopulates it skips any credential whose metadata is already real. A
  freshly issued credential could therefore be present, valid, correctly
  typed and presentable, and still match nothing. Found on the Android side
  of the same bug, where an EBW-OID credential carrying
  `vct: uri:eu.ebw.oid.1` matched 0 candidates against a query naming exactly
  that.

  This package already had `CredentialUtils.declaredType`, whose own comment
  explains that what the holder received is not what the issuer advertised;
  nothing in the matcher used it. `vctOf` now reads the credential first and
  the metadata copy second, and all four places that declare what a
  credential *is* use it: `CredentialMatcher`, `SharedDcqlMatcher` (the
  shared Rust engine's input) and both `SirosWallet+Engine` sites. (#162)
- **An mdoc is matched on the docType in its own MSO.** `matchesDoctype` read
  `metadata?.doctype`, which is only populated when an issuer happens to
  expose an MDDL schema at a SIROS-internal endpoint — so a third-party mdoc,
  such as a real interop event's mDL, was unmatchable by DCQL while being
  perfectly presentable. Brings this package in line with the Android SDK,
  which fixed the same thing earlier. (#162)

## [0.13.0] - 2026-09-21

### Added
- **Local or remote mdoc trust evaluation is now a choice, per registry.**
  `MdocTrustEvaluationMode` — `.remoteWithLocalFallback` (the default, and
  what every previous release did), `.remoteOnly`, `.localOnly` — selectable
  independently for RICAL readers and VICAL issuers via
  `WalletConfig.readerTrustEvaluationMode` and `issuerTrustEvaluationMode`.
  The local path is deliberately the weaker of the two (plain X.509 path
  validation, no RICAL/VICAL CBOR parsing, no `trustConstraints`, no
  per-certificate `docType`), so which one runs is a security decision;
  `.remoteOnly` is for a deployment that would rather deny a presentation than
  accept one on the weaker check.
  - `WalletConfig.preferLocalReaderTrustEvaluation` and
    `preferLocalIssuerTrustEvaluation` keep working and keep their meaning
    (`true` is `.localOnly`) — they are now views onto the mode, so reading and
    writing both still behave — and are deprecated. An explicitly chosen mode
    always wins over them.

### Fixed
- **A reader or issuer that the backend *refused* no longer falls back to the
  local roots.** Both evaluators ended in a catch-all that dropped to local
  X.509 validation on any thrown error, so an expired token producing a `403`
  on `/v1/evaluate` silently downgraded a security-relevant deny — the Kotlin
  SDK has distinguished these since Geneva 2026, and this SDK did not. Only a
  genuine transport failure or a `5xx` now falls back.
  - Relatedly, `SirosError.network` is not a transport error in this SDK: every
    site that throws it does so for a protocol or configuration failure
    ("Invalid response", "Invalid URL"), and a real outage escapes as a bare
    `URLError` because the HTTP boundary does not wrap it. Unreachability is
    judged accordingly, and a cancelled request (`URLError.cancelled`) is not
    an outage.
- **An SD-JWT's docType comes from its format, not its bytes.** `toFfi` called
  `parseMdocDocument` for every stored credential whatever its format; only an
  mdoc has an MSO, so for an SD-JWT the parse returned nil and the bytes were
  left to decide the docType. It now parses only for `mso_mdoc`.
  (siros-sdk-kotlin#204 is the same bug, louder.)

### Changed
- **A wallet lifecycle refusal now says whether it ends one device or the whole
  wallet**, and the SDK acts on that rather than on prose. SIROS adopts the
  EUDI wallet-unit lifecycle semantics exactly: revoking one wallet instance
  ends that device and nothing else, and only deactivating the wallet - every
  instance revoked, the data erased server-side - is terminal and needs a new
  enrollment. Until now the wire could not tell those apart (`WALLET_REVOKED`
  meant both, and only the human-readable `message` differed), so the SDK
  deliberately kept the cached account on every refusal - forgetting it on a
  per-instance revocation would have destroyed passkeys that still work.
  go-wallet-backend#340 adds a machine-readable `scope` (`instance` / `wallet`)
  to the refusal body, and this release consumes it.
  - `SirosError.WalletLifecycleRefusal` gains a third case, `.deactivated`
    (`WALLET_REVOKED` at scope `wallet`), next to `.suspended` and the now
    strictly per-instance `.revoked`. Build one from the wire with
    `resolve(errorCode:scope:)`; `errorCode` is the wire code (`.revoked` and
    `.deactivated` share `WALLET_REVOKED`, which is the whole point). The type
    is no longer `String`-backed - `rawValue` and `init?(rawValue:)` remain as
    source-compatible shims, and the initialiser resolves a scope-less code
    conservatively.
  - `SirosError.serverScope` carries the raw `scope` next to `serverMessage`.
  - `WalletState.lifecycleBlocked` and
    `WalletEventListener.onWalletLifecycleBlocked` can now report
    `.deactivated`. Existing `switch`es over the enum must handle it.
  - Only `.deactivated` forgets the cached account, by the same path
    `deactivateWallet()` uses, and only the account the refusal is about: a
    login refused before its passkey resolved to a known account of this
    tenant and backend forgets nothing, since deleting the wrong account's
    passkeys is worse than leaving a stale entry on the login screen.
    `.suspended` and `.revoked` behave exactly as before: session ended
    locally, account and credentials kept.
  - `fetchPrivateData()` no longer swallows a lifecycle refusal. It is the
    first wallet-API call a login makes, so a suspended instance or a
    deactivated wallet is usually met right there; tolerated like any other
    fetch failure it became an empty container and then a keystore-unlock
    error, and the wallet never reached `WalletState.lifecycleBlocked` at
    all. Every other failure stays tolerated as before, and the function is
    now `throws`.
  - A backend older than #340 sends no `scope`, and `WALLET_REVOKED` then
    resolves to `.revoked` - so against every deployment that exists today the
    behaviour is bit-for-bit what it was. An unrecognised `scope` falls back
    the same way, and the `message` is never consulted.

## [0.12.0] - 2026-09-17

### Fixed
- **Type metadata is now resolved *by* the digest a credential pinned, not
  merely checked against it afterwards** (ports siros-sdk-kotlin#191). A
  credential carries `vct#integrity` so the issuer, rather than whoever serves
  the document, decides what its type means. The wallet treated that as a
  verdict on whatever its resolver produced, so when the resolver produced the
  wrong document the credential was simply refused - and a document cached
  before an issuer changed what it publishes kept being handed out, with no way
  for a server-side fix to reach the device.
  - `VctmFetcher.fetchDocument` takes `expectedIntegrity`. Each source is tried
    until one yields the document that hashes to it, rather than settling for
    the first parseable body, and a cached document that fails it is not a hit
    however fresh it is. With no expectation, behaviour is exactly as before.
  - `SirosWallet` re-resolves against the pin when the document it holds
    disagrees, and accepts the credential if the issuer's own document can
    still be found anywhere. Only a wallet that cannot find it at all refuses,
    so the security property is unchanged - a document that does not match the
    pin is never accepted - and a stale cache heals itself.

- **The wallet's own HTTP transport now reports error statuses.**
  `SirosWallet` built every client over a function that discarded the
  response, so a non-2xx arrived as a successful body: a `403` carrying
  `WALLET_SUSPENDED` / `WALLET_REVOKED` was parsed as a login response and
  surfaced as a generic decoding failure, and `409 ERASURE_INCOMPLETE` never
  reached its retry. Both had been unreachable in a real app since the
  refusal helper landed, while unit tests - which inject their own transport -
  stayed green. It now throws `SirosError.backendApi(code:message:body:)`
  like the two clients' own convenience initialisers.
- **The self-driven re-login no longer reuses a cut-off token.**
  `AuthServerClient` caches access tokens itself, so clearing `AuthTokens`
  left the pre-cut-off token to be served from that cache and refused with
  `401` on first use. The re-login now calls the new
  `AuthServerClient.clearTokenCache()`, which drops cached tokens without
  ending the session the way `logout()` would.

### Added
- **Wallet instance lifecycle: the SDK now speaks the whole protocol**
  (SID-AUTH-06, go-wallet-backend#319). The backend grew a token cut-off, an
  erasure retry and a passkey-ownership check on top of the instance API the
  SDK already called; the client side of each of those is here. Ports
  siros-sdk-kotlin's equivalent change.
  - `WalletState.lifecycleBlocked(reason:message:cachedAccounts:)` - a blocked
    wallet is a state, not an error. Entered from `login()`,
    `unlockKeystore()`, `resumeSession()` and from the SDK's own re-login
    whenever the authorization server answers `403` with `WALLET_SUSPENDED` or
    `WALLET_REVOKED`. Neither reason discards anything local - see the
    correction under **Changed** for why `WALLET_REVOKED` is not proof the
    wallet was erased - and the state carries the backend's own message so the
    app can tell the user which case it is.
  - **One self-driven re-login after a token cut-off.** Any lifecycle change
    refuses every token issued before it, so the reauthentication signal now
    drops the tokens, API client and engine session and attempts `login()`
    exactly once - never in a loop. A lifecycle `403` there goes straight to
    `.lifecycleBlocked`, a success continues as a normal login, anything else
    is the existing error path. `WalletEventListener.onReauthenticationRequired()`
    still fires first for hosts that drive their own prompt.
  - A successful `setWalletInstanceStatus` write re-logs in the same way, so
    suspending *this* device's own instance lands in
    `.lifecycleBlocked(reason: .suspended, ...)` rather than surfacing later as
    a stray 401.
  - `409 ERASURE_INCOMPLETE` is retried per the protocol: five attempts, 1 s →
    8 s, identical body. A `401` after such a `409` is the acting token being
    dropped with the erased key material and counts as complete.
  - `403 CREDENTIAL_NOT_OWNED` at WIA generation retries the request once
    without `credential_id` and clears the stale id, with a warning. The first
    link recorded for an instance wins, so the SDK never guesses another one.
  - `WalletInstance.isThisDevice` and `SirosWallet.thisInstanceId` - the
    instance-key JWK thumbprint the SDK already sends as `wallet_instance_id`
    - so a Devices screen can mark this installation and warn before
    suspending it.
  - Optional `WalletEventListener.onWalletLifecycleBlocked(reason:message:)`,
    with a no-op default.
  - **Security: the instance key now survives a logout.**
    `SessionStore.clearAccount()` deleted `instanceKeyId`, so the next login
    minted a new key and registered a **new, active** backend wallet instance.
    A *suspended* installation could therefore walk away from its own
    suspension simply by logging out and back in. Only `clearAll()` (a factory
    reset) drops it now.
  - A session generation makes the self-driven re-login happen once per
    *session* rather than once per call, aborts it when the caller logged out
    or destroyed the wallet while it was tearing the old session down, and
    keeps a token minted before a cut-off from being cached by either
    `AuthTokens` or `AuthServerClient` after the clear that the cut-off
    triggered.
  - A lifecycle block tears the session down locally instead of calling
    `logout()`: the unawaited `DELETE /auth/session` could otherwise land
    after the retry the app makes once a suspended instance is reactivated,
    invalidating the session that retry had just established.
  - `SirosError.apiErrorCode` and `SirosError.serverMessage`: the backend's
    stable error code and its user-facing explanation, without every call site
    re-parsing the body.

- **Sample app: a Devices screen and a blocked-wallet screen.** Settings →
  Devices lists this account's wallet instances (this-device badge, status,
  key storage, last attested, reason) with per-row Suspend / Reactivate /
  Remove and a footer that deactivates the wallet behind a typed confirmation,
  reporting whether the backend confirmed the erasure.
  `WalletState.lifecycleBlocked` gets its own screen - suspended explains and
  offers a retry, revoked explains and offers a fresh enrollment - instead of
  a generic error. Strings in `SampleApp/Resources/i18n/`.

### Changed
- **Correction: `WALLET_REVOKED` no longer forgets the cached account.** The
  design assumed that code meant the wallet had been deactivated and erased.
  It does not: the backend returns it for the login gate of a *single* revoked
  instance too, and only deactivates the wallet when the **last** non-revoked
  instance is revoked - the user's other devices keep logging in either way,
  and only the human-readable `message` distinguishes the two. Forgetting the
  account on a per-instance revocation destroyed the other passkeys that still
  worked. Both refusal reasons now end the session, keep the cached account,
  and show the backend's own message; re-enrollment is the user's call.
  `deactivateWallet(reason:)` is the one place that still forgets the account,
  where the caller asked for it and the outcome is unambiguous.
- **Source-breaking: `WalletState` has a new case.** `.lifecycleBlocked` means
  an exhaustive `switch` over `WalletState` no longer compiles without an arm
  for it (the SampleApp needed one). Add a case, or a `default`, when
  upgrading.
- **`SirosWallet.deactivateWallet(reason:)` and
  `BackendApiClient.revokeAllWalletInstances(reason:)` return
  `DeactivationOutcome(revoked:complete:)`** instead of a bare count. The
  revocations stand even when the backend's erasure cascade did not finish, so
  the local account is forgotten either way and `complete` is what the app
  tells the user (an incomplete erasure leaves residual server-side data for an
  administrator to clean up).

## [0.11.0] - 2026-09-17

### Fixed
- A presentation this wallet cannot satisfy is now answered honestly. The
  `credential_selection` step sent `decline` whenever nothing was selected -
  including when nothing matched and the user was never asked - which the
  engine reports to the verifier as `access_denied` / "User declined the
  request", a refusal nobody made. With nothing to present the SDK now sends
  `credentials_matched` with an empty match set and a reason;
  go-wallet-backend (#335/#336) ends the flow at once with
  `NO_MATCHING_CREDENTIAL`, naming the credential types the query asked for,
  and tells the verifier so its session ends rather than expiring. A user
  who was offered a credential they could actually present, and chose none,
  still declines, as before.
- A selection the wallet cannot present - the app may show exhausted copies
  so it can offer a renewal, and the user may pick one - took the same wrong
  path one step later: it threw, and the handler's catch reported a decline.
  It now reports the same empty match set, with a reason saying the copies
  are spent.
- `no_match_reason` is no longer dropped on either transport:
  `WalletEngineSession.sendMatchResponse` and the WMP profile's
  `match_response` both carry it (`MatchResult` gained `noMatchReason`).
- The legacy `match_request` handler answered nothing at all when the
  selected credential had no eligible copies left, leaving the engine's
  `RequestMatch` waiting for a response that never came; it now replies with
  an empty match set and that reason.

### Added
- `WalletEventListener.onNoMatchingCredential(flowId:requestedTypes:reason:redirectUri:)`
  - fires alongside `onFlowError` for a `NO_MATCHING_CREDENTIAL` failure,
  carrying the credential types the verifier asked for, so an app can say
  "you need a PID first" instead of showing a generic error. Optional: it has
  a default no-op implementation, and `onFlowError` still fires.
- `WalletEngineSession.sendCredentialsMatched(flowId:matches:noMatchReason:)`
  and `EngineErrorCodes.noMatchingCredential`.

## [0.10.0] - 2026-09-17

### Changed
- `siros-wscd-manager` XCFramework 0.8.1 -> 0.9.1: key ids minted by the
  softkey and FIDO2 plugins are now RFC 7638 JWK thumbprints (existing ids
  keep resolving); FIDO2 plugin state restored via
  `registerFido2PluginWithState` now rebinds its keys to the plugin.

## [0.9.0] - 2026-09-16

### Added
- **Bridge capability vocabulary** in `SirosTransport`: `BridgeCapabilityId`,
  one parameters struct per capability, `BridgeDescriptor` and
  `BridgeDescriptorBuilder` - the descriptor a web-view wrapper app advertises
  to the page it hosts, shaped like WMP's capability map. Generated from
  `spec/bridge-capabilities.json`, whose source of truth is siros-sdk-kotlin;
  CI checks the copy and the generated Swift stay in step.
- `docs/TWO-APIS.md`: the SDK's two entry points - the orchestrated API
  (`SirosWallet`) and the low-level, flow-free composition of keystore, auth
  and credentials - with the Swift specifics and the parity gaps against the
  Android SDK (no facade-free ZK presentation entry point, no circuit cache or
  prover residency, no Vega).

## [0.8.0] - 2026-09-10

First public SDK release, alongside siros-sdk-kotlin 0.14.0. The 0.7.0 tag
(2026-09-07) never rolled this section, so some entries below shipped in 0.7.0
already; everything since 0.6.1 is here. Consumers must raise their deployment
target to iOS 18 / macOS 15.

### Fixed
- **Login after logout could never unlock the wallet.** `logout()` clears the
  account-scoped session store, so the next `login()` had no PRF salt to
  offer: the ceremony carried no PRF and the separate probe derived one for
  a fresh random salt the container was never sealed with. Login now offers
  every cached account's passkey with its own salt in the single ceremony
  (WebAuthn `prf.evalByCredential`; `AuthenticateOptions.prfSaltsByCredential`,
  Apple's `perCredentialInputValues`), uses the salt of the credential the
  user actually picked for the probe, and restores that account's
  `hkdfSalt`/`hkdfInfo` from the registry - the Kotlin SDK's
  `loginCandidates` pattern. Surfaced by review on #139.

### Added
- `AuthenticateOptions.prfSaltsByCredential` and `prfSalt(for:)`; custom
  `AuthProvider`s should evaluate PRF for the salt of the credential used.
- `AccountRegistry.inMemory()` and a `SirosWallet.init(accountRegistry:)`
  parameter, so tests and previews do not touch the Keychain.

### Changed
- **`ASAuthorizationAuthProvider.getPrfOutput` fails closed.** It no longer
  falls back to `HKDF(credentialId, salt)` when the authenticator returns no
  PRF output; it throws `SirosError.auth("PRF extension not supported by
  this authenticator")`, as the Kotlin SDK's production provider always has.
  The credential ID is public, so a container sealed under that fallback was
  protected by nothing the user holds. Containers sealed under it - a
  security key on iOS/macOS below 26.4, where the security-key PRF API does
  not exist - can no longer be opened; there is deliberately no migration.
  The dev-only `LocalAuthProvider`s keep their own software PRF (Kotlin's
  keys the HMAC with `credentialId || "SIROS-LOCAL-PRF-v1"`, Swift's with
  `credentialId` alone); they never roam, so the divergence is documented
  rather than reconciled.
- **Platform floor is now iOS 18 / macOS 15** (was iOS 16 / macOS 13). The
  wallet's key material is derived from the login passkey's WebAuthn PRF
  output, and Apple's PRF extension exists from iOS 18; on 16 and 17 the
  package built and ran but login could not unlock the wallet. The
  `#available(iOS 18)` branches around PRF are gone (security-key PRF stays
  gated at 26.4); macOS is a build/test platform only. Consumers on an older
  deployment target must raise it to adopt this release.

### Added
- `HostAppRequirements`: what a host app must declare for each SDK feature
  (Info.plist usage descriptions, `CFBundleURLTypes` schemes, entitlements)
  and an `audit(bundle:)` that reports what the bundle is missing. iOS has
  no manifest merging, so this is the SDK's side of the integration
  contract; the sample app runs it at startup in debug builds.
- `URLSessionR2psTransport` moved into `SirosKeystore` as the default
  `R2psTransportProvider`, so a host app no longer copies it from the
  sample app.
- `DeepLinkClassifier.handledSchemes` (with `credentialOfferSchemes` /
  `presentationRequestSchemes`); `mdoc-openid4vp`, `haip-vp` and `haip-vci`
  are now classified by scheme, as the Kotlin SDK does.
- Wallet instance lifecycle (SID-AUTH-06, go-wallet-backend#319):
  `SirosWallet.listWalletInstances()`, `setWalletInstanceStatus(instanceId:status:reason:)`
  and `deactivateWallet(reason:)` (revokes every instance server-side, then
  forgets the local account), backed by the new `WalletInstance` type and
  `BackendApiClient` methods. WIA generation now sends the logged-in passkey's
  `credential_id` so the backend can link the instance to the passkey.
  `SirosError.walletLifecycleRefusal` reads the `WALLET_SUSPENDED` /
  `WALLET_REVOKED` codes off a 403 login refusal without adding an enum case.
- `PresentationRecord.zkProof` (`zk_proof`): whether a presentation was a
  zero-knowledge proof rather than a raw disclosure, set on the DC API and both
  engine selection paths; sample-app history shows a lock badge for it
- `SirosWallet.availableKeyIds` and an `isZkPresentation` resolver on
  `SirosWallet.eligibleInstances(from:)` / `CredentialUtils.eligibleInstances`

### Changed
- `CredentialUtils.eligibleInstances`/`isBelowRenewThreshold` now require
  `availableKeyIds` and, under every policy, exclude an instance whose bound
  signing key the keystore no longer holds
- `CredentialConsumptionPolicy.consumeNonZkp` now actually distinguishes a
  `mso_mdoc_zk` presentation (never consumed) from a raw one (consumed), decided
  by the first-match query per credential

### Fixed
- `PresentationRecord` decoding tolerates the enrichment fields being absent, so
  records reloaded from the encrypted container (which only carries the
  privatedata-spec-normative fields) no longer fail to decode

## [0.6.1]

Re-release of 0.6.0. No SDK or sample-app source changes.

v0.6.0's release build hung and was cancelled, so that release carries only an
SBOM — the same failure that left v0.3.0, v0.4.0 and v0.5.0 without artifacts.
The cause was the Release workflow's `Configure vendor package access` step,
whose global git `insteadOf` rewrite broke SwiftPM's binary-artifact downloader:
the three xcframework downloads stalled at zero bytes indefinitely. Nothing in
this repository needs that token — every dependency and binary target is public
— so the step was removed (#116), and both macOS jobs gained a 45-minute
timeout so a future stall fails fast instead of burning the 6-hour job limit.

### Changed
- Sample app: MARKETING_VERSION 0.6.1, build 4

## [0.6.0]

Highlights since v0.5.0 (4 commits). Sample app: MARKETING_VERSION 0.6.0, build 3.

### Added
- `BbsProofSystem`: the blind BBS presentation path (#113), plus the wallet's half
  of blind BBS issuance (#114)
- VICAL-based issuer-trust evaluation for mdoc presentation (#111)

### Changed
- `ZkProofSystem` generalized beyond mdoc-only, so non-mdoc credential formats can
  plug into the same proving interface (#112)

### Fixed
- BLE session-establishment race during proximity presentation (#111)
- SVG `<image>` height normalization in credential logo rendering (#111)
- `SampleApp/project.yml` hardcoded `CFBundleShortVersionString`/`CFBundleVersion`
  in its `info:` block, so `xcodegen generate` overwrote `Resources/Info.plist` and
  reset the built app to 0.1.0/1 — undoing the v0.4.0 fix. Both now substitute
  `$(MARKETING_VERSION)`/`$(CURRENT_PROJECT_VERSION)`.

## [0.5.0]

Highlights since v0.4.0 (10 commits).

### Added
- RICAL reader authentication: `MdocCose.verify1` plus `readerAuth` parsing and
  trust evaluation (ISO 18013-5 Annex F), with an AuthZEN reader-trust call, a
  local fallback, and a settings toggle (#110)

### Changed
- `SirosWallet.swift` split into focused files to clear SwiftLint
  `type_body_length`/`file_length` errors (#106)
- Sample app UX: unified SIROS ID identity-verification path and long-press offer
  detail (#105)
- `siros-wscd-manager` bumped to v0.7.4 (#109)

### Fixed
- `AddCredentialView` offer identity collision across issuers (#108)
- Three wallet bugs surfaced by the PR #106 review and deferred there (#107)

## [0.4.0]

Highlights since v0.3.0 (41 commits):

### Added
- Longfellow ZKP Phase 3: `ZkProofSystem` + `LongfellowZkProofSystem` integration, wired into
  the DC API ZK presentation path (#94)
- OID4VCI Phase 2 credential renewal (refresh_token flow), extracted into
  `SirosWallet+Renewal.swift` (#91, #93)
- FIDO2 CTAP2 transport wired into the sample app
- TS11 registry discovery: `Ts11RegistryClient` wired into `WscdSettingsView`
- Credential-type registry service integration (`go-wallet-backend`) with TTL-cached
  type-metadata fetches scoped to registry calls (#83, #84)
- WS-engine transport: DCQL matching + ZK presentation wiring
- WSCD AutoEnroll hint mechanism ported from Kotlin

### Changed
- WSCD Settings UI consolidation (task #214)
- Security/architecture review pass: SDK/sample-app boundary refactor, WSCD key sync
- Sample app: QR-detection/message-banner localization across remaining views
- Dependency bumps: `siros-wscd-manager` to v0.7.2 (#85)

### Fixed
- Cross-port ZK/pseudonym fixes: order-independent pseudonym re-derivation lookup,
  `pseudonym_seed` acceptance
- OID4VCI renewal data-loss/crash fixes; immediate re-auth on a 401 from the AS token endpoint
- Race fix in WSCD AutoEnroll's offered-once guard
- Recovery from transient CTAP2 disconnects instead of wedging
- TS11 wildcard-issuer override resolution fix
- Audience-validation enforcement; immediate sign-failure reporting (#86)
- Presentation flow parity: `redirect_uri` on error, verifier display name/chrome,
  `CredentialCardView` reuse, per-credential-type wizard steps (#89, #90)
- `sign_presentation` VP-part builder extraction
- NFC usage description/entitlement fixes
- Real test target wiring for `WalletViewModelTests`/`MessageBannerTests` (#98, #100, #101)

## [0.1.0]

### Added
- Initial SDK with 6 modules: SirosTransport, SirosAuth, SirosKeystore, SirosFlow, SirosCredentials, SirosWallet
- ASAuthorizationAuthProvider for iOS passkey support
- KeychainSessionStore for persistent session storage on Apple platforms
- CI pipeline with macOS test, iOS build, Linux test, and coverage gate (25%)
- README, CONTRIBUTING.md, ARCHITECTURE.md, CHANGELOG.md

### Fixed
- Replaced fatalError calls with failable init and thrown errors
- Eliminated NSLock-held-across-await deadlock in WmpSession (SendSerializer actor)
- Added Sendable conformance to WmpCodecError
- Added LocalizedError conformance to all error types
