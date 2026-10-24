# Changelog

All notable changes to the SIROS SDK for iOS/macOS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Account deletion: review fixes (#196).** The delete-begin response must carry a non-empty, well-formed
  `allowCredentials` list (no silent fall-back to a discoverable prompt), and only `410 STEP_UP_EXPIRED` reads as an
  expired step-up. The wipe now clears `AuthServerClient`'s token cache, reports failures of the credential store, the
  Keychain session store and the account registry (new members `CredentialStore.eraseAll()`,
  `SessionStoreProtocol.eraseAll()`, `AccountRegistry.eraseAll()`, with default implementations), refuses credential
  writes from an issuance that was in flight when it began, and covers every distinct registered keystore, erasing the
  signing keys held by `WscdKeystoreAdapter` (new `KeystoreManager.eraseKeyMaterial()`, default no-op; keys on an
  external authenticator are left alone) before locking. `ASAuthorizationAuthProvider` passes the requested
  `userVerification` to both assertion requests, and `LocalAuthProvider` assertions carry the UV flag (the key is gated
  by `.userPresence`).
  Write admission is one gate (`TeardownGate`): the wipe closes it synchronously before its first await, drains the
  admitted writes, and it reopens only when a new session starts (login, register, resume). Credential saves,
  presentation history writes (engine, DC API, proximity), flow completions and consent handlers all hold a ticket taken
  before their first await and write through the gate; `WscdKeystoreAdapter` key creation is closed by the erase and
  reopened by the new `KeystoreManager.reopenKeyOperations()`, not by an unlock.
- **WMP: a retry timer scheduled before a resume does nothing after it, and the event stream ends when a close fails.** A
  timed retry carries the resume generation it was scheduled in and is validated under the lock that claims the answer,
  so a resume (which resets the budgets and replays the queue) cannot be followed by stale retries. `WmpPeer.close`
  finishes `flowEvents()` whether or not the close notification got through. A catch-up after a resume drains only its own
  child, so an answer that exhausted its retries is not resent by another child's catch-up.
- **Host-resolution timeouts fire on their own queue.** `hostResolvesToOnlyPublicAddresses` raced its lookup against a
  timer on the same global queue, so a timer could wait behind lookups blocked in `getaddrinfo` (13 s against a 0.2 s
  bound on a CI iOS simulator, failing `testResolutionGivesUpAfterHostResolutionTimeout`). The timer now has a dedicated
  queue.

### Changed
- **Dependency: siros-dc-matcher XCFramework 0.6.2 -> 0.11.0.** Regenerated
  `Generated/siros_dc_matcher_ffi.swift` from the v0.11.0 tag (keeping the
  `#if os(iOS)` gate) and updated the `Package.swift` checksum to the release's
  published SPM checksum. Nothing in this SDK calls the renamed FFI yet, so this SDK's
  wiring is unchanged. **The engine's behaviour is not**: it is inherited from upstream
  0.7.0-0.11.0.
  - Matching: an absent `zk_required` now means the proof is optional (it was read as
    required); a verifier's `multiple` is honoured; duplicate DCQL identifiers are
    rejected; a verifier requiring cryptographic holder binding is honoured; the
    combination count says whether it is exact.
  - **BREAKING, nym_auth rulebook v0.4** (0.11.0): the format and its names are renamed,
    not aliased: `circuit_zk` -> `zkp_req`, `req` -> `_req`, item `id` -> `fn_id`,
    `circuit_id` -> `system_id`, and the response is the base64url CBOR `ZkpPresentation`
    `{system_id, proof, issuer_key_set, proof_time, results}` instead of JSON with
    `circuit_id` / `proof_system` / `x5chain`. FFI: `addCircuitZkSystem` ->
    `addZkpReqSystem`, `circuitZk` -> `zkpReq`, `circuitZkPlan` -> `zkpReqPlan`,
    `CircuitZkPlanError` -> `ZkpReqPlanError`. `birth_date`, `ssc`, `psc` and
    `secret_seed` of a nym_auth attestation are never matched through any other format.
  - Verified on a Mac mini (iOS simulator): with matcher 0.6.2 a `zk_system_type` request
    without `zk_required` offered no credential; with 0.10.0 it offers it. A targeted
    regression for that, and a human review of the inherited behaviour changes, are still
    needed before release.
- **Issuance fails closed on issuer trust (BEHAVIOUR-BREAKING for hosts that relied
  on untrusted issuance being stored).** A credential is stored only if its
  issuer's trust was established: on `flow_complete`, before anything is stored,
  superseded, captured or synced, `SirosWallet` refuses the whole issuance when
  the engine's own issuer evaluation (`trust_evaluated`, now joined to the
  completion by `WalletEngineSession` as `FlowCompleteMessage.issuerTrust`) said
  `trusted: false`, or when any `mso_mdoc` credential has no verifiable
  `issuerAuth` or a negative `evaluateIssuerTrust` result (an unreachable trust
  service with no positive local root counts as negative; on a platform without
  the Security framework an mdoc cannot be verified and is refused). An absent
  engine report is not treated as untrusted (the engine emits none in its
  permissive no-PDP mode). Before, the mdoc check was only logged and the
  credential was stored regardless. On refusal nothing is stored, no refresh token
  is captured, a renewal's old batch is kept, the OID4VCI `credential_failure`
  notification is sent (`issuer_not_trusted`) when the issuer asked for one, and
  the host gets the new `WalletEventListener.onIssuerNotTrusted(flowId:issuer:reason:)`
  (default no-op) followed by `onFlowError` with the English text "This issuer could
  not be verified as trusted, so the credential was not added." The Swift SDK has no
  per-credential trusted flag, so there is no "stored with `trusted=false`" state.
  A completion is judged by the issuance epoch its OWN flow started under: the
  wallet captures the epoch when the issuance guard is taken, a start cancelled
  while preparing unwinds instead of sending, the session carries the tag to
  `FlowCompleteMessage.startTag`, and a tag is tied to a flow id only when exactly
  one start is unanswered (the engine runs each `flow_start` in its own goroutine,
  so with two unanswered the order of replies is unknown: no tag, both refused; the starts that may still reply stay counted, so a late reply can never take a newer start's tag, and nothing expires on a timer). An OAuth resume carries the originating issuance's epoch (`PendingAuthorization.startEpoch`), never a fresh sample, and is not sent if that issuance was cancelled meanwhile. A finished flow's id stays known to the tag tracker until the socket is replaced, and an error naming no flow answers no start, so a late or anonymous error cannot consume another start's slot. A session change (logout, login, account replacement) now also invalidates the issuance epoch, so an OAuth callback pending across it is refused instead of resuming on the next account's engine and tokens, and a presentation's completion no longer clears the guards of an issuance in flight beside it. The same session change invalidates a start still preparing, a renewal's ownership check, source-batch assignment and send are one locked step, and `UNKNOWN_FLOW`/`TOO_MANY_REQUESTS` errors are never taken for the reply to a pending start.
  A completion that would store credentials, carries a negative report or carries
  issuance metadata (refresh token, issuer, configuration) but has no start tag is
  refused. For mdoc the docType
  sent to the trust service is checked against the signed MSO's and a mismatch (or
  no readable signed docType) is untrusted.
  Ports Kotlin SDK #276 (https://github.com/sirosfoundation/siros-sdk-kotlin/pull/276),
  items 1 to 3; the TTL trust-decision cache (item 4) is a separate change.
- **mdoc trust evaluation requests carry `resource.id == subject.id`.** The issuer
  and reader requests sent the issuer URL (or certificate hash) as `subject.id` but
  always the certificate hash as `resource.id`. go-trust requires them to be equal
  for every full evaluation, answers 400, and go-wallet-backend's authzen proxy
  turns that into a 502, after which the weaker local roots were used.
- **A 5xx no longer opens the weaker local trust roots by itself.** The local
  fallback is now taken only for a transport failure, or a 502/503/504 whose body is
  not a JSON error object (empty, `{}`, a gateway page): go-wallet-backend's authzen
  proxy also answers 502 when the PDP was reached and refused the request. A 500,
  `code == 0`, any 4xx, or a PDP error body is a refusal and no longer falls back.
- **One TTL trust-decision cache for every `/v1/evaluate` call (replaces `TrustCache`).**
  Every trust evaluation (mdoc issuer/reader, engine-relayed verifier/issuer,
  DC API) now goes through `TrustDecisionCache`: only successful decisions (allow
  and deny) are remembered, keyed by a hash of the whole request body plus the
  backend client that answered it, so a different certificate, doc type or context
  never reuses an entry; errors, timeouts and 4xx/5xx are never cached; an expired
  entry is never served, even when the backend is unreachable; identical concurrent
  requests share one backend call; 256 entries, least recently used evicted; in
  memory only; cleared whenever the backend connection is dropped or replaced
  (logout, account deletion, reconnect). New `WalletConfig.trustDecisionCacheTtl`
  (seconds, default 300, `0` disables). Trade-off: a revocation can take up to the
  TTL to take effect. **Behaviour change:** the old "degraded mode" is gone: an
  earlier positive verifier result no longer stands in for a failed evaluation
  (engine path and DC API path now fail closed), and the engine's informational
  `trust_evaluated` issuer report is no longer cached. `TrustCache` is removed (it
  had no public members). Ports Kotlin SDK #276, item 4
  (https://github.com/sirosfoundation/siros-sdk-kotlin/pull/276).
- **Keystore: containers are written at `S.schemaVersion` 4 (was 3).** Version 3
  readers (older SDKs, a wallet-frontend before spec 3.0) crash on or drop
  `S.extensions` and `S.credentials[].metadata`, which is why spec 3.0 moves them
  to version 4; they will not rewrite a version 4 container, which is the
  intended effect. Changing `S.extensions`
  (`setExtensionEntry`, `removeExtensionEntry`) now also appends a `set_extension`
  event (schemaVersion 4, a tombstone with `value` null for a removal) to
  `events`, chained by `parentHash` as wallet-frontend chains them (SHA-256 hex of
  the previous event's key-sorted JSON; `lastEventHash` for the first), as spec
  6.1.3 requires of a client with no event log; the SDK still has no event
  merger. It still writes the legacy `wscdCredentials` and
  `credentialRefreshTokens` members, which spec 6.2 forbids: replacing them means
  re-shaping per-plugin state into per-`kid` `org.siros.wscd` entries and defining
  the `org.siros.oid4vci.refresh` value, which the spec does not specify and which
  would have to match siros-sdk-kotlin, so that is left for its own change. **Rollout (spec 3.0):** this SDK writes version 4 on every
  write; a wallet-frontend that implements only version 3 refuses a version 4
  container (nothing is lost, the user cannot open the wallet there). No
  compatibility shim is provided. **Older native SDK releases are not
  protected by this:** they always wrote version 3 and rebuilt every credential
  entry from a closed list of members, so one that rewrites a version 4 container
  drops `metadata` and unknown credential members, with no refusal. Upgrade (or
  block from writing) every native client that shares an account before a
  version 4 container, or a delivered secret, exists in it; the version number
  alone cannot stop them.
- **Keystore: an issued credential is not stored, nor reported accepted to the
  issuer, while the container is unsupported** (`storeIssuedCredential` checks the
  new `KeystoreManager.unsupportedSchemaVersion`, default nil), because
  `CredentialStore.save` does not throw. Likewise `SirosWallet.eligibleInstances`
  offers no instance whose presentation the consumption policy would consume
  (all under `consumeAll`, raw disclosures under `consumeNonZkp`), since a
  consumption could not be persisted and the instance would become eligible
  again on reopening. Deleting or clearing a credential now also
  forgets its preserved container entry, so a credential later saved under the same
  id does not inherit the deleted one's `metadata`.
- **EC TS12 payment SCA: the `amr` now comes from the WSCD manager's own sign.**
  `siros-wscd-manager` XCFramework 0.9.1 -> 0.10.0 (vendored bindings
  regenerated). Before the user is shown a transaction the wallet asks the
  key's WSCD plugin (`authenticationCapability`, never prompts) whether two
  authentication categories are reachable and refuses up front otherwise. The
  SCA sign then asks the user for the PIN, claims in the signed KB-JWT exactly
  the factors that sign will apply (possession from the plugin, the knowledge
  class measured from that PIN) and signs through `signWithFactors` with
  `requireFreshUserAuthentication`; the presentation is discarded unless the
  sign itself reports exactly those factors. Only R2PS (OPAQUE) and FIDO2 (raw
  transport) keys can sign an SCA presentation; softkey, R2PS WebAuthn and
  UV-performing transports are refused (`insufficientAuthenticationFactors`).
  Non-SCA signing is unchanged. **Breaking (unreleased TS12 API):**
  `SirosWallet.authenticationFactorsProvider`, `AuthenticationFactorsProvider`
  and `InterimAuthenticationFactorsProvider` are removed (the SDK no longer
  derives factors from the key's storage kind or accepts host-asserted ones),
  `TransactionDataBinding` carries no factors (`kbJwtClaims(factors:)` takes the
  sign's), and `Signer` gains `authenticationCapability(keyId:)` and
  `signForSca(keyId:payload:)` (defaults refuse). The sample app's biometric
  provider is gone.

### Added
- **`SirosWallet.deleteAccount(confirmation:stepUp:)`: self-service account
  deletion (go-wallet-backend#352, backend PR #453).** A fresh passkey
  assertion (step-up, valid 2 minutes, single use) and the typed confirmation
  `DELETE` authorise the backend to erase the account. The assertion comes from
  the wallet's `AuthProvider`, or from the optional `stepUp` closure. The call
  does not throw for expected outcomes: it returns `DeleteAccountResult`
  (`deleted`, `cleanupPending`, `operatorRequired`, `retryNeeded(reason)`,
  `failed(failure)`). Only the first three wipe local state - keystore
  contents and key material, credentials, presentation records and history,
  every account's session store and Keychain items, the account registry, the
  trust and credential-status caches and the WSCD selection policy - and the
  wipe carries on past a failing step, reporting each in `LocalWipeReport`.
  A `409 DELETION_INCOMPLETE`, a failed, expired or missing step-up, a wrong
  confirmation, a rejected token or an unknown account keep local state.
  Stores the host app owns (transaction log, Digital Credentials API registry,
  file caches) are the host's to clear. Backed by
  `BackendApiClient.deleteAccountBegin()` and
  `deleteAccount(challengeId:credential:confirm:)`, which return an
  `AccountDeletionResponse` per backend outcome, and by
  `WscdSelectionPolicy.clearAll()`. The sample app's Devices screen offers it
  with a typed confirmation.
- **`IDVError.chipPhotoMismatch` (`chip_photo_mismatch`, `errorCode`
  `idv_chip_photo_mismatch`):** facetec-api now refuses a scan whose face does
  not match the photo stored on the document's chip
  (sirosfoundation/facetec-api#77). Until now the code would have reached the
  app as `providerError`. Both `FaceTecIDVProvider` and `RemoteIDVClient` map
  it, the same as siros-sdk-kotlin's `IDVException.ChipPhotoMismatch`. Adding a
  case breaks exhaustive `switch`es over `IDVError`. The sample app has a
  message for it in English and Swedish.
- **CI: the SwiftPM unit tests run on an iOS Simulator (`Test (iOS Simulator)`).** Until now nothing
  ran the `#if os(iOS)` code or tests: `Test (macOS)` compiles them out and `Build (iOS)` only
  compiles. Ten tests that fail only on iOS are skipped by name and tracked in
  https://github.com/sirosfoundation/siros-sdk-swift/issues/213, so a new iOS failure fails the job. The card-stack
  UI tests wait for the deck to be still before each gesture (they failed in different CI runs and passed
  on re-run).
- **The `nymauth-*` proving seam: `NymAuthNativeProver`, its registry and typed errors,
  with a refusing default.** One narrow async call (verified circuit bytes and the
  already-assembled inputs in, proof and pseudonym out; the circuit authors' ABI,
  mirrored from the Kotlin SDK). No native binding is shipped, so
  `NymAuthNativeProverRegistry` hands out `RefusingNymAuthNativeProver`, which refuses
  every request with `NymAuthNativeError(.noNativeProver)`; nothing is substituted.
  Binding failures map to coarse kinds (and, for a refusal, a coarse reason) and carry
  no message; the request (it holds the delivered seed) and response redact their
  description, debug description and mirror. The request mirrors the Kotlin ABI: `circuitId` is the catalog circuit id the presentation states as `system_id`, `artifactHash` the catalog hash of the verified circuit, `time` the PROVER-supplied `proof_time` (rulebook v0.4, exactly 20 bytes), `verifierInput` the SHA-256 of the PREFIXED verifier id. Not wired into the wallet.
- **`PresentationConsentCoordinator`: the ready-made `PresentationConsentHandler` for a host app.** It
  renders a request into the SDK's approved wording (`PresentationConsentText`) and hands the app one
  question at a time (`onChange`, `current`, `answer(true)` / `decline()`), built on `ConsentPrompt`: a single
  answer, declined on timeout (default 120 s), dismissal, supersede and cancellation, and with no UI set. A
  request the wording does not cover is declined without being shown.
- **`ConsentPrompt<Request, Answer>`: the SDK's one bridge from a question that needs a person to the host's UI.**
  The SDK side calls `ask(_:)`; the host sets `onChange` to show the question and calls `answer(_:)` /
  `decline()` on the `Pending` it is given (and `dismiss()` when its UI goes away). Guarantees: exactly one
  answer however the user, a timeout, a dismissal, a newer question and task cancellation race; decline by
  default (no UI set, dismissed, expired, superseded, cancelled); one question at a time; an outgoing
  question can never answer or clear a newer one. The sample app's three copied continuation boxes
  (proximity consent, TS12 transaction consent, WSCD choice) are replaced by it. Platform-neutral
  (SirosCredentials), tested on Linux.
- **`nym_auth` derived secrets: `NymPseudonym`, `SecretSeedCommitment`, and the
  `private_seed` derivation (v2, per issuer).** `NymPseudonym.derive` is the rulebook's
  `pseudonym-v1-sha256` (`SHA256(DST || seed || prover_input || verifier_input)`),
  with the four rulebook configs and the API-misuse errors, tested against the
  shared `nym-pseudonym-vectors.json`. `SecretSeedCommitment` reads `ssc` from an
  mdoc (the credential's own doctype namespace only) or an SD-JWT VC (bound to the
  signed `_sd`), checks `SHA256(seed) == ssc` in constant time and parses a
  delivered seed (32 lowercase hex). The internal `PrivateSeed` derives
  `HKDF-SHA256(mainKey, info = "org.siros.private_seed/v2" || lp(type) || lp(issuer))[:16]` and its
  `psc`; the keystore binding to `mainKey` follows separately. The nym vector
  files are byte-for-byte copies from siros-sdk-kotlin (PR 266 ed9f7e65, rulebook v0.4: function `pseudonym`, the PREFIXED verifier_id, the archive reference value `155f4337...aad1` reproduced), `derived-secrets.json` from
  privatedata-spec 1b796d2 (SPEC 2.7: per issuer, injective `lp` encoding, empty or
  over-65535-byte fields refused). Platform-neutral (swift-crypto
  on Linux), no secret is logged or returned by a public API.
- **`circuit_zk` consent model: `PresentationConsentHandler`, the consent request
  and a registry-driven builder.** The locale-free request a user approves before
  anything is signed or proved (items `pseudonym`, `predicate`, `claim`,
  `legacyPseudonym`, per credential, with the verifier label and, for hosts and
  tests only, the trust framework and `verifier_id_type`). Predicates apply to ANY
  claim, and the function set is open-ended, so predicate functions are data:
  `PredicateFunctions` (default: the nymauth `age_check`) declares per function id
  its claim, value type, param-to-comparison map, an optional minimum span and
  whether it reads as an age. Consent building, the local pre-check
  (`precheck`) and the cross-query merge (`combinedBoundsOk`, the strictest
  declared minimum span per credential and claim) are driven by it; a function not
  in the registry is refused before consent. The handler is a sibling of
  `TransactionConsentHandler`, not tied to the transaction-data flag: `false`, a
  throw or a timeout is a decline, and with no handler a `circuit_zk` request is
  refused. `PresentationConsentRequest.shortened(verifierId:)` is the display
  shortening. Tested against the shared `circuit-zk-consent-vectors.json` (copied
  byte-for-byte from siros-sdk-kotlin: 62 consent cases, 18 merge cases, 22
  pre-check cases). Numbers are compared as exact decimals: a value Decimal would
  round (over 38 digits) is refused, `in` members are deduplicated by value, the
  merge span is refused when it cannot be computed exactly, and a pre-check with a
  different number of lookups than functions is false; float operands must be finite
  and exact. `requestSigned` is a required argument (the signature result, never
  defaulted) and an empty query list is refused. A query may name the credential's namespace (labels come from `[namespace, element]` metadata only) and an item's `source` param is accepted when it names the function's own claim. The pseudonym function is `pseudonym` (rulebook v0.4; `ver` and `prf` params, not judged by consent), vectors from siros-sdk-kotlin PR 275 de6f1317. String operands are compared and deduplicated by their exact UTF-8 bytes (U+00E9 and U+0065 U+0301 are different, as in the other SDKs). A merge span whose bounds differ in scale by more than 4096 digits (`1` and `1e999999999`) is refused, never computed. `PresentationConsentText` renders a request into the approved wording (en, sv, fi, el, pt; other locales read English), generated from the Kotlin SDK's string resources so both SDKs say the same; date claims get date-specific sentences, numbers and strings the generic ones, an age keeps the age wording, and an unsupported pseudonym scope throws rather than being left out of the consent. Not wired into the wallet yet.
- **`ConsentPrompt<Request, Answer>`: the SDK's one bridge from a question that needs a person to the host's UI.**
  The SDK side calls `ask(_:)`; the host sets `onChange` to show the question and calls `answer(_:)` /
  `decline()` on the `Pending` it is given (and `dismiss()` when its UI goes away). Guarantees: exactly one
  answer however the user, a timeout, a dismissal, a newer question and task cancellation race; decline by
  default (no UI set, dismissed, expired, superseded, cancelled); one question at a time; an outgoing
  question can never answer or clear a newer one. The sample app's three copied continuation boxes
  (proximity consent, TS12 transaction consent, WSCD choice) are replaced by it. Platform-neutral
  (SirosCredentials), tested on Linux.
- **Sensible default display for a credential type that publishes none.** What a
  card draws when the issuer's type metadata has no rendering block, which is
  every type that comes from someone else's catalog.
  SDK: `CredentialUtils.buildMetadata` and `buildMdocMetadata` fall back to the
  offer's `issuerLogoUri` (the issuer's own mark) as the last `logo` fallback, and
  the new `CredentialUtils.buildFallbackMetadata(_:)` builds metadata for a
  credential that has none from what the credential itself carries (name from its
  configuration id, issuer name from the host of its issuer identifier, `vct` /
  `docType` from the credential); it sets no colours or logo, which are the
  issuer's to declare.
  Sample app card: a tint derived from the type identifier (FNV-1a over the
  UTF-16 code units, 24 hues x 3 tones, fixed lightness per theme; the same type
  gives the same colour on every device, in the Kotlin sample app too) instead of
  one accent colour for every type; text colour chosen by contrast ratio, not by
  a mid-grey threshold, so no background yields text under 4.5:1; the issuer row
  is left out when the credential names no issuer, the wire format is no longer a
  text slot of its own, and the type identifier takes its place beneath the name
  (dropping out when the name already says it). Mirrors siros-sdk-kotlin
  [#211](https://github.com/sirosfoundation/siros-sdk-kotlin/pull/211). Not
  ported: Kotlin's `hydration` marker on `CredentialMetadata` (Swift has no
  hydration pass).
- **Issuance start is visible at once.** `startIssuance(offerUri:)` and
  `startIssuanceByOffer(_:)` now publish `WalletState.flowActive` synchronously,
  before any network work, with `flowType` `"issuance"`, a placeholder `flowId`
  (`WalletState.FlowActive.pendingFlowId`, `WalletState.isPendingFlow`) and a
  client-side `status` that steps through `initializing`, `connecting_engine`,
  `establishing_session`, `checking_entitlement` (by-offer path only),
  `preparing_issuance` and `starting_flow` (`WalletState.FlowActive.step*`)
  until the engine's own progress events take over. Previously the wallet stayed
  `.ready` for several seconds on a mobile network (engine reconnect,
  entitlement check, metadata fetches), so hosts showed no feedback after the
  user chose a credential type. A start that fails (engine unreachable,
  entitlement refusal) returns the wallet to `.ready` and throws, as before;
  `cancelCurrentFlow()` during the start resets at once, sends nothing to the
  engine (there is no flow id), and the suspended start unwinds with
  `CancellationError` instead of reaching the engine; a cancelled start cannot
  clobber a newer one (admission, epoch checks, state commits, failure cleanup
  and cancel share one critical section on the wallet lock). The flow type stays `"issuance"` across the first engine
  progress event for flows begun this way (before, it became the step name).
  Both start paths now take the in-flight guard before connecting the engine.
  Hosts that switch on `flowId` should treat `isPendingFlow` as "no engine flow
  yet". Not ported yet: Kotlin's recognition of a flow cancelled after
  `flow_start` was sent but before the engine named it (needs per-connection
  generations in `WalletEngineSession`). Mirrors siros-sdk-kotlin
  [#277](https://github.com/sirosfoundation/siros-sdk-kotlin/pull/277).
- Sample app: labels for the new steps (en, sv); a user-cancelled start is no
  longer reported as an error.
- **`zkp_req` (nym_auth rulebook v0.4): planner, unsatisfiable rules, strict CBOR response validator,
  `proof_time`, prefixed `verifier_id`.** `ZkpReqPlanner` reads the v0.4 DCQL names (`zkp_req`, `_req`,
  `fn_id`, `return`, `meta.source_format`, `vp_formats_supported.zkp_req` with `system_id_values` and
  `proof_system_values`); `ZkpReqUnsatisfiable` is the rulebook's request-only rules (`pseudonym` with
  `ver` and `prf`, one `age_check` of at least 365 days, `verifier_context`, holder binding).
  `ZkpReqResponseValidator` checks the base64url CBOR `ZkpPresentation` `{system_id, proof,
  issuer_key_set (at most 8 DER certificates of at most 4096 bytes), proof_time, results}` with its own
  strict CBOR reader (definite lengths only, duplicate keys refused structurally, depth 16) that walks the
  raw bytes and its own JSON reader that keeps duplicate members. `ZkpReqProofTime` is the exact 20-byte
  `YYYY-MM-DDThh:mm:ssZ` form (shape first, parsed only to settle that the instant is real) with the verifier
  tolerance helper (recommended 60 s skew, 600 s age: the verifier's to configure). The time is the PROVER's;
  nothing reads a clock here. `ZkpReqPresentationBuilder` encodes a presentation and returns a `vp_token` only
  after the validator accepts it. `ZkpReqVerifierId` forms the PREFIXED `verifier_id`
  (`x509_san_dns:<dns>`, `semantic_id:<id>`) whose SHA-256 is `verifier_input`. Tested against the 241
  vectors of siros-dc-matcher 93047bc (digest 9f482d7a...), verbatim. Supersedes the JSON `circuit_zk`
  response shape. Not wired into the wallet; the prover seam still refuses.
- **`DeliveredSecretReceipt`: the wallet's side of delivered secrets (privatedata-spec 5A).**
  `receive` applies the rules to a Credential Response that carries
  `org.siros.secret_seed`: refused when the response is not JWE-encrypted, is a deferred
  response, has no `notification_id`, has a malformed member (1 to 8 namespaces of 1 to
  64 bytes, not `namespaces`, each seed 32 lowercase hex), has a non-object
  `credential_metadata`, or fails the commitment (`SHA256(seed) == ssc` for the designated
  namespace, constant time). It returns the `metadata` entries to store in each credential
  (in the order received), the display members WITHOUT the seed (strip before merge) and
  the seeds for the secret store only; `mergedDisplayMetadata` merges the stripped response
  over the issuer metadata and `advertisement` validates the issuer's namespace-names-only
  advertisement. Pure; the result and errors never print a seed. Tested against the
  privatedata-spec 1b796d2 delivered-secret vectors, verbatim. Not wired into the wallet yet.
- **`circuit_zk` response shape: `CircuitZkX5Chain` and `CircuitZkResponseValidator`.** The
  presentation now carries `x5chain`, the holder-supplied issuer chain: the credential's own
  Document Signer chain from `issuerAuth`'s unprotected header (COSE label 33), leaf first,
  padded STANDARD base64 of each DER certificate, at most 8 certificates and 4096 bytes each
  (a chain that breaks a limit is never built). `CircuitZkResponseValidator` checks the shape of a
  `circuit_zk` entry in a `vp_token` and its binding to the request (offer, handles, result
  shapes; a JSON `null` is a type error everywhere, duplicates are judged on the raw text,
  unknown functions and members are refused) and is run by a wallet on the response it built.
  Tested against the 80 shared vectors of siros-dc-matcher 932b07a, copied verbatim. The
  verification time `T` is not part of this change. Not wired into the wallet.
- **Keystore: privatedata-spec 3.0, `S.schemaVersion` 4.** `JweKeystore` (and
  `WscdKeystoreAdapter` through it) now writes `S.schemaVersion` 4; migrating a
  version 3 container changes that number and nothing else. It reads versions 1
  to 4 and **rewrites 3 and 4 only**. A container whose `S.schemaVersion`, or any
  event's `schemaVersion`, is not 3 or 4, or that has an event without an integer `schemaVersion` or with a
  `type` outside the ten that versions 1 to 4 define (the nine
  `wallet-frontend` types and `set_extension`), is still unlocked and readable but
  is never rewritten: `exportEncryptedContainer()` and the stores that exist to be
  exported (`saveCredential`, `deleteCredential`, `clearCredentials`,
  `savePresentationRecord`, `clearPresentationRecords`, `setExtensionEntry`,
  `removeExtensionEntry`) throw the new `KeystoreError.unsupportedSchemaVersion(UnsupportedSchemaVersion)`,
  which names the part (`.state`, `.event(index:)`, `.eventType(index:type:)`) and
  what it found, and `JweKeystore.unsupportedSchemaVersion` reports the reason
  after unlock. It is a distinct case, not a failed merge or a crypto error:
  retrying does not help, updating the app does. The container the caller holds
  is never overwritten. The rules are plain JSON in `WalletStateSchema`, so they
  are tested on Linux too. Every event must carry an integer `schemaVersion`
  (spec 3.0); one without it is refused.
- **Keystore: unknown credential members, `metadata` and unknown keypair members
  are written back unchanged, in order.** Every `S.credentials[]` entry is rebuilt
  from the entry the container had (previously from a closed list of eight
  members, which dropped everything else), the array keeps the container's order
  (new entries are appended by id; it used to follow dictionary order), keypair
  entries and their members survive likewise, and a keypair entry this build could
  not load, including one that is not an object, is carried verbatim in place. Presentation entries and the members of a key's JWKs are written back unchanged too, so a 3 to 4 migration changes only `schemaVersion`; a present `S` that is not an object is refused, and `set_extension` stamped 3 is accepted (a writer emits 4). `metadata: null` and `metadata: []` are not
  written back (spec section 6.0). This overlaps the credential-metadata work in
  progress (#202), which adds the `metadata` accessors.
- Test vectors: `Tests/SirosKeystoreTests/Resources/privatedata-spec/` is a
  verbatim copy of privatedata-spec `test-vectors/` at pull request 9, head
  `64315a5eae50e08a93772488217bbc913c82dd56`, with a recorded source and a
  digest check (`vectors.PROVENANCE.txt`, `vectors.SHA256SUMS`).
- **WMP HTTP+SSE transport: SSE event ids, `Last-Event-ID` and replay dedupe.** The
  transport now parses `text/event-stream` with `SseEventParser` (the `id` field, a
  persistent last event id, comments, multi-line `data`), sends `Last-Event-ID` when it
  reconnects, and drops an event whose id it already delivered (`SseReplayFilter`), so a
  replayed `wmp.flow.complete` is never handled twice. It also splits the byte stream
  itself (`SseLineSplitter`): `URLSession.AsyncBytes.lines` omits the blank line that
  ends an event. The parser, splitter and filter are pure and tested on Linux; the
  transport's use of them is Apple-only and not exercised by a test. The resume cursor advances only when a block's blank line arrives, an empty `id` resets it and is never a dedupe key, one leading byte order mark is ignored per response, and each response starts with clean buffers (a disconnect mid-event never joins two responses' data). An event's
  `description` never prints its data. The parser reads each line as Unicode scalars (the colon and the one optional
  space are delimiters even before a combining mark), the replay filter keys ids by their UTF-8 bytes
  (canonically equivalent but different ids are different events), and an `SseReaderGate` lets only one
  reader run, so two overlapping `connect()` calls cannot feed one parser from two tasks; a reader touches the parser and the replay filter only inside `ifCurrent`, which holds the gate for the step, and frees the gate and publishes `.disconnected` or `.failed` as one step under the gate lock (a consumer that reconnects at once finds it open, and a stale reader never overwrites its successor's state); a reader is claimed and installed in one step (`start`) and `disconnect()` invalidates it, cancels its task and publishes in one step (`stop`), so a reconnect cannot be cancelled by an earlier disconnect; `.connected` is published only while the reader is still current.
- **Keystore: per-credential `metadata` in the privatedata container
  (`S.credentials[].metadata`, schema version 4).** An optional array of
  `{"type": <non-empty string>, "value": <any JSON>}` entries, stored exactly as received (first use: an
  issuer-delivered `org.siros.secret_seed`; per privatedata-spec section 5A.2 one entry per response-level
  `credential_metadata` member, `value` the member's object verbatim, not a string; members of an entry
  beyond `type`/`value` are kept). `JweKeystore` (and `WscdKeystoreAdapter`) gain
  `credentialMetadata(id:)` and `setCredentialMetadata(id:_:)`. What is stored is an independent copy, and
  so is what the accessor returns. The container is always written at `S.schemaVersion` 4 (the member is a
  version 4 one), a container of a schema this build must not rewrite refuses `setCredentialMetadata` with
  `KeystoreError.unsupportedSchemaVersion`, and `null` or `[]` is never written. The member is the keystore's
  source of truth once unlocked: loaded with the container, replaced by the setter, and removed with the
  credential (`deleteCredential`, `clearCredentials`, `lock`). EVERY successful replacement of the container
  (a current one, a legacy one with no `S`, a first-time empty one) starts from no metadata. It is kept apart
  from `StoredCredential.metadata`, which is display metadata and is not persisted in the container. A
  malformed (non-array) `metadata` is written back verbatim. **Older clients drop the `metadata` member the
  next time they rewrite the container**, which is accepted for this change.
- **`FaceTecIDVProvider`: identity verification with the FaceTec 10 SDK and
  facetec-api's `/process-request`.** One FaceTec session (3D liveness,
  document scan with NFC chip read, photo match) relays every request blob
  to facetec-api, which issues the credential; the offer becomes the
  `IDVResult`. Configured with `FaceTecIDVConfig(processRequestUrl:authToken:deviceKeyIdentifier:)`
  (`requireNfc` defaults to true; `configureSession` runs after FaceTec has
  initialized, for customization). Follows siros-sdk-kotlin's
  `FaceTecIDVProvider` (same flow, config names and dedicated errors for
  `chip_untrusted`, `document_expired` and `session_expired`). It maps facetec-api's refusal codes to
  `IDVError`s: `nfc_*` to `documentChipNotVerified`, `liveness_failed` to
  `livenessFailed`, `match_failed`/`policy_rejected`/`document_unreadable` to
  `verificationFailed`, `chip_untrusted`/`document_expired`/`session_expired`
  to `chipUntrusted`/`documentExpired`/`sessionExpired`, anything else
  (`issuance_failed`, `internal_error`, ...) to `providerError` with the code
  kept (`errorCode` `idv_provider_<code>`).
  The provider sends **one `externalDatabaseRefID` per FaceTec session on
  every `/process-request`**, which facetec-api v0.16.0 requires: it refuses
  the final result with `liveness_failed` unless that session's liveness was
  proven under the same ID. See `docs/IDENTITY-VERIFICATION.md`.
- `HostAppRequirements` now lists, under `.identityVerification`, the NFC chip read's
  declarations: `NFCReaderUsageDescription`, the `com.apple.developer.nfc.readersession.formats`
  entitlement and the ISO 7816 select-identifiers (`faceTecChipApplicationIdentifiers`),
  with a new array-valued requirement kind `infoPlistStrings` that `audit` checks.
- The sample app uses it (device key from the `FACETEC_DEVICE_KEY_IDENTIFIER`
  build setting) and shows a localized message per `idv_*` error code (en, sv).
- **`IDVError.documentChipNotVerified(reason:message:)`: a refused issuance
  because the document's NFC chip was not read and authenticated.**
  facetec-api now issues nothing without an authenticated chip read
  (sirosfoundation/facetec-api#65) and refuses with an `nfc_*` code.
  `RemoteIDVClient` turns such a 422 into this error, with `reason` set to
  the code and `errorCode` to `idv_<code>`, instead of a generic
  `verificationFailed` carrying the raw body. Its `/v1/id-scan` endpoint
  only tells verified from not, so the reason there is always
  `nfc_skipped`; any other `nfc_*` code a backend sends maps the same way. Adding a case to `IDVError` breaks exhaustive `switch`es over it
  outside the SDK; add a `default` or handle the new case.
- **`IDVError.chipUntrusted`, `.documentExpired` and `.sessionExpired`:
  facetec-api's `chip_untrusted`, `document_expired` and `session_expired`
  refusals** (facetec-api v0.15.0 / v0.16.0), with `errorCode`s
  `idv_chip_untrusted`, `idv_document_expired` and `idv_session_expired`,
  mapped from a 422 by `RemoteIDVClient` like the `nfc_*` codes. They were
  a generic `verificationFailed` carrying the raw body. Every 422 that carries
  an `error_code` now goes through one table (`IDVError(refusalCode:message:)`):
  `liveness_failed` is `livenessFailed`, `match_failed`/`policy_rejected`/
  `document_unreadable` are `verificationFailed`, any other code is
  `providerError` with the code kept, all with the backend's `error` text as
  the message instead of the raw JSON body. A body without a code is unchanged.

### Removed
- **Breaking: `SirosWallet.deactivateWallet(reason:)` and
  `setWalletInstanceStatus(instanceId:status:reason:)`, with
  `BackendApiClient.revokeAllWalletInstances(reason:)` and
  `setWalletInstanceStatus(instanceId:status:reason:)`, `DeactivationOutcome`,
  `errorErasureIncomplete` and the `erasureRetryDelays` initializer parameter.**
  They called `POST /user/session/instances/revoke-all` and
  `PUT /user/session/instances/{id}/status`, which the backend no longer has.
  Use `deleteAccount(confirmation:stepUp:)`. `listWalletInstances()` stays.
### Changed
- **One TTL trust-decision cache for every `/v1/evaluate` call (replaces `TrustCache`).**
  Every trust evaluation (mdoc issuer/reader, engine-relayed verifier/issuer,
  DC API) now goes through `TrustDecisionCache`: only successful decisions (allow
  and deny) are remembered, keyed by a hash of the whole request body plus the
  backend client that answered it, so a different certificate, doc type or context
  never reuses an entry; errors, timeouts and 4xx/5xx are never cached; an expired
  entry is never served, even when the backend is unreachable; identical concurrent
  requests share one backend call; 256 entries, least recently used evicted; in
  memory only; cleared whenever the backend connection is dropped or replaced
  (logout, account deletion, reconnect). New `WalletConfig.trustDecisionCacheTtl`
  (seconds, default 300, `0` disables). Trade-off: a revocation can take up to the
  TTL to take effect. **Behaviour change:** the old "degraded mode" is gone: an
  earlier positive verifier result no longer stands in for a failed evaluation
  (engine path and DC API path now fail closed), and the engine's informational
  `trust_evaluated` issuer report is no longer cached. `TrustCache` is removed (it
  had no public members). Ports Kotlin SDK #276, item 4
  (https://github.com/sirosfoundation/siros-sdk-kotlin/pull/276).
- **Keystore: containers are written at `S.schemaVersion` 4 (was 3).** Version 3
  readers (older SDKs, a wallet-frontend before spec 3.0) crash on or drop
  `S.extensions` and `S.credentials[].metadata`, which is why spec 3.0 moves them
  to version 4; they will not rewrite a version 4 container, which is the
  intended effect. Changing `S.extensions`
  (`setExtensionEntry`, `removeExtensionEntry`) now also appends a `set_extension`
  event (schemaVersion 4, a tombstone with `value` null for a removal) to
  `events`, chained by `parentHash` as wallet-frontend chains them (SHA-256 hex of
  the previous event's key-sorted JSON; `lastEventHash` for the first), as spec
  6.1.3 requires of a client with no event log; the SDK still has no event
  merger. It still writes the legacy `wscdCredentials` and
  `credentialRefreshTokens` members, which spec 6.2 forbids: replacing them means
  re-shaping per-plugin state into per-`kid` `org.siros.wscd` entries and defining
  the `org.siros.oid4vci.refresh` value, which the spec does not specify and which
  would have to match siros-sdk-kotlin, so that is left for its own change. **Rollout (spec 3.0):** this SDK writes version 4 on every
  write; a wallet-frontend that implements only version 3 refuses a version 4
  container (nothing is lost, the user cannot open the wallet there). No
  compatibility shim is provided. **Older native SDK releases are not
  protected by this:** they always wrote version 3 and rebuilt every credential
  entry from a closed list of members, so one that rewrites a version 4 container
  drops `metadata` and unknown credential members, with no refusal. Upgrade (or
  block from writing) every native client that shares an account before a
  version 4 container, or a delivered secret, exists in it; the version number
  alone cannot stop them.
- **Keystore: an issued credential is not stored, nor reported accepted to the
  issuer, while the container is unsupported** (`storeIssuedCredential` checks the
  new `KeystoreManager.unsupportedSchemaVersion`, default nil), because
  `CredentialStore.save` does not throw. Likewise `SirosWallet.eligibleInstances`
  offers no instance whose presentation the consumption policy would consume
  (all under `consumeAll`, raw disclosures under `consumeNonZkp`), since a
  consumption could not be persisted and the instance would become eligible
  again on reopening. Deleting or clearing a credential now also
  forgets its preserved container entry, so a credential later saved under the same
  id does not inherit the deleted one's `metadata`.
- **EC TS12 payment SCA: the `amr` now comes from the WSCD manager's own sign.**
  `siros-wscd-manager` XCFramework 0.9.1 -> 0.10.0 (vendored bindings
  regenerated). Before the user is shown a transaction the wallet asks the
  key's WSCD plugin (`authenticationCapability`, never prompts) whether two
  authentication categories are reachable and refuses up front otherwise. The
  SCA sign then asks the user for the PIN, claims in the signed KB-JWT exactly
  the factors that sign will apply (possession from the plugin, the knowledge
  class measured from that PIN) and signs through `signWithFactors` with
  `requireFreshUserAuthentication`; the presentation is discarded unless the
  sign itself reports exactly those factors. Only R2PS (OPAQUE) and FIDO2 (raw
  transport) keys can sign an SCA presentation; softkey, R2PS WebAuthn and
  UV-performing transports are refused (`insufficientAuthenticationFactors`).
  Non-SCA signing is unchanged. **Breaking (unreleased TS12 API):**
  `SirosWallet.authenticationFactorsProvider`, `AuthenticationFactorsProvider`
  and `InterimAuthenticationFactorsProvider` are removed (the SDK no longer
  derives factors from the key's storage kind or accepts host-asserted ones),
  `TransactionDataBinding` carries no factors (`kbJwtClaims(factors:)` takes the
  sign's), and `Signer` gains `authenticationCapability(keyId:)` and
  `signForSca(keyId:payload:)` (defaults refuse). The sample app's biometric
  provider is gone.

### Fixed
- **WMP: a timed retry resends only its own answer, and a session closes locally whatever the close notification does.**
  A retry timer drains just the child that scheduled it (a resume still drains the whole queue), so an answer that spent
  its budget is not resent by another child's retry. `WmpSession.close` disconnects the transport, ends the session and
  fires the terminal hook even when the `wmp.session.close` notification fails, then reports the failure.
- **WMP child answers: the retry budget is per answer, and cancelled replays leave no marker.** The timed-retry budget
  belongs to each queued answer (cleared when it is sent, ends, or the session resumes), so an answer that used its
  retries up cannot starve the next. A replay's cancellation marker is removed when its send finishes whether or not its
  parent is still in the bounded ended-flow list, so markers cannot accumulate over a long session.
- **WMP child answers: failed sends are retried, and the queue handoff is atomic.** A send that fails on a healthy
  connection (a failed POST on a live stream) brings no resume event; the queued answer is now retried after a bounded
  backoff (`OpenID4xConfig.sendRetryDelaysMs`, default 1/2/4/8 s), then waits for the next resume. The task and
  cancellation state of a child whose answer is queued are removed in the same critical section that queues it.
- **WMP child flows: completed children are remembered, and a replaying child is cancelled like any other.** A start
  redelivered after the child's answer was sent (original send or replay) runs nothing. A parent ending while a replay
  send is suspended releases the claimed child's route at once, and the child's cancellation marker lives until that
  send finishes (not in the bounded ended-flow list), so a failing send is never requeued for a cancelled child.
- **WMP child flows, further review follow-ups.** A child cancelled while its replay send is suspended is not requeued
  when that send fails; a second resume during a suspended replay that then fails triggers another drain; a redelivered
  start for a cancelled child does not run its handler again; a child start refused for good (its flow ended, or the
  profile stopped) releases the route the peer registered for it.
- **WMP child flows and session end, review follow-ups.** Shutdown is one-shot, so a retired session's close
  cannot run the application's cleanup again after a replacement session has begun. A session created without a
  `resumption_token` now ends at once when its connection is lost (terminal hook, pending requests failed)
  instead of staying marked active, and the terminal hook is installed before `create`. A sign payload that does
  not decode is `INVALID_PARAMS`, not a sign failure. A child stays tracked until its terminal answer is sent, so
  a redelivered start cannot run a second handler; an answer that could not be sent (connection down) is kept and
  sent when the session resumes (`WmpSession.onResumed`, `WmpResumeProfile`), without running the handler again.
- **WMP: flow actions and trust answers now match go-wmp, and the old sign/match progress route is gone
  (no shim).** `trust_result` put `trusted`, `framework` and `reason` next to `action`; go-wmp's
  `FlowActionParams` reads them under `params`, so the engine saw an empty payload. They are sent under
  `params`. A trust progress is answered only when the engine marks it `trust_evaluation_required`
  (issuer `evaluating_trust`, verifier `evaluating_verifier_trust`, new `VPStep.evaluatingVerifierTrust`);
  the informational progress under the same step is passed to `onProgress` instead of being answered.
  `sign_request` / `match_request` / `generating_proof` / `matching_credentials` progress no longer runs
  the sign or match handler: the engine starts those as child flows. Verified against go-wmp and the Kotlin
  SDK's equivalent change only, not a live engine.
- **WMP: the wallet answered the orchestrator's `sign` and `match` requests on a route the orchestrator
  never reads.** The orchestrator (go-wallet-backend, WMP openid4x section 3.1.5) starts them as CHILD
  flows (`wmp.flow.start`, `flow_type` `sign` or `match`, the issuance or presentation in
  `parent_flow_id`) and waits for `wmp.flow.complete` ON THE CHILD flow id with the response JSON as
  `result`; a refusal is `wmp.flow.error` on the child flow with `data.reason` `rejected`. The profile
  registered only `oid4vci` and `oid4vp`, ignored the child `wmp.flow.start`, and answered a
  `wmp.flow.progress` step with `wmp.flow.action` `sign_response` on the parent, which the orchestrator
  parks until its sign timeout. `OpenID4xProfile` now registers `sign` and `match`, runs each child
  flow (the handler is given the PARENT flow id, which is what the wallet keys its state by) and
  answers as above, without holding the start request while the user decides. A child that is
  cancelled, whose parent is cancelled, completes or fails, or whose session closes (`WmpPeer.close`) is
  cancelled, released from the peer's tracking at once (not when its handler returns) and answers nothing,
  even if its handler returns normally; after `shutdown()` no child is started and a queued child never enters its handler; a cancel made locally (`WmpPeer.cancelFlow`) stops the flow here at once; a failing match child reports `MATCH_ERROR`; a child start for a parent that already ended, and a redelivered start for a child already running, are dropped; `shutdown()` also calls the application's `onShutdown`, and a finished child is released from the peer's tracking. The old progress-step route no longer runs sign or match handlers (see the entry below; no shim). **`wmp.flow.error` now carries the protocol's numeric code (-31006)**: go-wmp reads
  `code` as an int, so the string codes the profile sent made the whole notification undecodable and
  the refusal was lost; the application code moves to `data.error_code` and the text to `message`.
  An integer `code` from the peer now decodes (it was a decode failure).

### Deprecated
- **`FaceTecCaptureDelegate`.** It is written against the FaceTec 9 API
  (`createSessionVC` and the face-scan/ID-scan processors), which FaceTec 10
  removed, so it cannot compile against the SDK wallet-ios-wrapper ships.
  Use `FaceTecIDVProvider`. Its FaceTec 9 code is removed: it never compiled
  with FaceTec linked (it called `IDVError.cancelled(reason:)`, which has no
  associated value) and, with FaceTec 10 linked, it broke the whole package
  build. It now always throws `IDVError.unavailable`. `RemoteIDVProvider`
  is unchanged.

### Fixed
- **Presentation consent: nothing is approved that is not shown.** A host predicate renderer that returns no sentences
  (or only blank ones) is refused with `PresentationConsentTextError` instead of dropping the predicate from the screen.
  Age bounds of one credential that meet at a single day (`ge` == `le`, in one predicate or split across two) identify
  the exact birth date: the "not shared" age wording is dropped for them and every comparison is worded generically.
- **ConsentPrompt: an expired question is never shown.** A zero-duration timeout (a negative one is normalised to it) is
  declined before the question is installed, so a host that answers synchronously from `onChange` cannot approve it.
  The tests wait for the host to be told before they resolve a question, removing a scheduling race.
- **circuit_zk consent: claim paths and string operands.** Claim paths are compared by the UTF-8 bytes of their
  components (`ClaimPathKey`), so `caf\u{e9}` and `cafe\u{301}` are two claims for the `source` check, the bound merge
  and the label lookup. Age bounds that meet at a single day (one predicate, two predicates or two queries) identify the exact
  birth date, so the "not shared" age wording is dropped for them. String operands in the consent wording are double-quoted and escaped, so the sets `["SE, FI"]`
  and `["SE", "FI"]` no longer read alike.
- **Transport: `WalletEngineSession` keeps one engine socket at a time.** The
  engine keeps one session per (tenant, user) and closes the older socket when a
  second connects. The session used to open several at once: `forceReconnect`
  (after an OAuth redirect or a QR scan) cancelled the old socket, and the receive
  failure that cancel raises then scheduled a reconnect of its own, as did a
  failed send and a second `connect()` while still connecting; the sockets
  superseded each other and a flow's replies went to a socket the engine no longer
  knew. Now every socket has an epoch: opening one supersedes (and cancels) the
  previous one and any pending backoff attempt, a callback, frame or reconnect
  attempt of a superseded socket does nothing (a superseded token refresh no
  longer sets `.reauthRequired` over the new connection), a failed socket is no
  longer reported by `isConnected` during the backoff, and a duplicate failure of
  the same socket schedules one backoff, not two. Ports Kotlin SDK #282
  (https://github.com/sirosfoundation/siros-sdk-kotlin/pull/282). The client
  ping never closes the socket on a missing pong (Kotlin keeps its pong wait at
  10 s or more for the same reason), so no change was needed there. Tested through
  a fake socket (`EngineSocket`, a new internal seam); not run against a real
  `URLSessionWebSocketTask` on an Apple platform.

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
