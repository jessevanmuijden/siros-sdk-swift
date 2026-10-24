# Identity verification (FaceTec + facetec-api)

`FaceTecIDVProvider` (module `SirosWallet`) drives one FaceTec 10 session and
returns the credential offer that facetec-api issued. Use it through
`SirosWallet.verifyIdentityAndIssue(provider:presentingViewController:)`.

```swift
let provider = FaceTecIDVProvider(
    config: FaceTecIDVConfig(
        processRequestUrl: URL(string: "https://idv.example.com/v1/process-request")!,
        authToken: "Bearer \(token)",
        deviceKeyIdentifier: "<from FaceTec>"
    ),
    configureSession: { FaceTec.sdk.setCustomization(myCustomization) }  // optional
)
try await wallet.verifyIdentityAndIssue(provider: provider, presentingViewController: viewController)
```

The FaceTec iOS SDK is distributed privately, so this package does not depend
on it: link the xcframework into your app. Without it `isAvailable()` is
`false` and `startVerification` throws `IDVError.unavailable`.

### How the xcframework is picked up

The provider's FaceTec code is behind `#if canImport(FaceTecSDK)`, evaluated
while Xcode compiles the `SirosWallet` package target. Link
`FaceTecSDK.xcframework` (production: from SIROS's private repositories; the
wallet-ios-wrapper carries the development build) to the **host app target**
and build with Xcode / `xcodebuild`: the framework is then on the package
target's search path and the provider is compiled in. Nothing in
`Package.swift` is needed, and none is possible while the SDK is distributed
privately.

Verified on Xcode 26.6 with a minimal app target that depends on this package
as a local package and embeds `FaceTecSDKForDevelopment.xcframework`
(iOS Simulator build): the compiled `FaceTecIDVProvider` object references
`FaceTecSDK` symbols; the same app without the xcframework has none and the
provider reports itself unavailable. To check your own integration, build
the app and run `nm` on `FaceTecIDVProvider.o` in the build's intermediates,
looking for `FaceTecSDK` symbols. A bare `swift build` of this package never
has the framework, so it always builds the unavailable variant.

## What facetec-api expects of a client

Checked against facetec-api v0.16.0.

| Contract | How the provider keeps it |
|---|---|
| The **same `externalDatabaseRefID` on every `/process-request` of one FaceTec session**. facetec-api records FaceTec Server's liveness verdict under it and refuses the final result with `liveness_failed` unless that session's liveness was proven; a request without the ID is refused. | One `FaceTecSessionRelay` per `startVerification` call mints the ID (`siros-sdk-ios-<uuid>`) and sends it with every blob. A retry inside FaceTec's UI is the same session, so it keeps the ID. |
| A **new ID per session** (a key can only be enrolled once). | A new `startVerification` call is a new relay, so a new ID. |
| The liveness proof is **single-use and expires** (15 minutes by default). A refused or abandoned session cannot be resumed. | The provider never reuses a relay. After a refusal, the app starts a new scan. |
| **Every request of a session must reach the same facetec-api instance.** | Deployment concern: sticky routing, or one instance. |
| A **chip is required for every document** (`nfcAuthenticationStatusEnumInt` 4), checked by a PDP. | With `requireNfc` (default) the provider refuses to start on a device that cannot read NFC. Refusals come back as `nfc_*` / `chip_untrusted`. |
| The **face must match the photo stored on the chip** (FaceTec's `matchLevelNFCToFaceMap`), not only the printed photo (sirosfoundation/facetec-api#77). | Nothing to do on the device: facetec-api decides. A refusal comes back as `chip_photo_mismatch`. |

## Error codes

facetec-api reports a refusal in the process-request response as
`credentialIssueErrorCode` (message in `credentialIssueError`).
`FaceTecIDVProvider` maps it as below. siros-sdk-kotlin maps the same way, with the same dedicated errors (`IDVException.ChipUntrusted`, `ChipPhotoMismatch`, `DocumentExpired`, `SessionExpired`) and `errorCode`s.

The legacy `/v1` endpoints (`RemoteIDVClient`) answer 422 with `error_code`
instead, and `RemoteIDVClient` maps it the same way (`IDVError(refusalCode:message:)`),
with the backend's `error` text as the message. A 422 body without a code stays a `verificationFailed` (or
`livenessFailed` on the liveness step) carrying the raw body.

| Code | `IDVError` | `errorCode` |
|---|---|---|
| `liveness_failed` | `livenessFailed` | `idv_liveness_failed` |
| `match_failed`, `policy_rejected`, `document_unreadable` | `verificationFailed` | `idv_verification_failed` |
| `nfc_skipped`, `nfc_not_requested`, `nfc_device_not_capable`, `nfc_chip_read_failed`, `nfc_not_authenticated` | `documentChipNotVerified(reason:)` | `idv_<code>` |
| `chip_untrusted` | `chipUntrusted` | `idv_chip_untrusted` |
| `chip_photo_mismatch` | `chipPhotoMismatch` | `idv_chip_photo_mismatch` |
| `document_expired` | `documentExpired` | `idv_document_expired` |
| `session_expired` | `sessionExpired` | `idv_session_expired` |
| `issuance_failed`, `internal_error`, any future code | `providerError(code:)` | `idv_provider_<code>` |
| user left the face or ID scan | `cancelled` | `idv_cancelled` |
| camera denied or broken, no NFC, no FaceTec SDK, no device key | `unavailable` | `idv_unavailable` |
| facetec-api unreachable during the session | `networkError` | `idv_network_error` |

Notes:

- `session_expired` is only answered by the legacy `/v1/id-scan` path. On
  `/process-request` an expired or used-up liveness proof shows as
  `liveness_failed`.
- `match_failed`, `policy_rejected` and `document_unreadable` share one
  `errorCode`; the backend's text is in the error's description.
- `errorCode` is a stable key for localization. The sample app maps each one
  to a message in `SampleApp/Resources/i18n` (`idv.errors.*`).
