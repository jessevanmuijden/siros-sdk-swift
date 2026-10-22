# The SDK's two APIs: orchestrated and low-level

The SIROS SDK for iOS/macOS is one Swift package but two ways in, and which one
you take is the first integration decision. The reasoning is the same as for
the Android SDK ([siros-sdk-kotlin/docs/TWO-APIS.md](https://github.com/sirosfoundation/siros-sdk-kotlin/blob/main/docs/TWO-APIS.md));
this page is the Swift specifics.

| | Orchestrated ("flow-full") | Low-level ("flow-free") |
|---|---|---|
| Entry point | `SirosWallet` (product `SirosWallet`) | `SirosKeystore`, `SirosAuth`, `SirosCredentials` composed by you |
| Who runs OID4VCI / OID4VP | the SDK, through the engine backend over WMP | **you** - typically a web page in your `WKWebView`, or your own engine client |
| Who owns the private-data container | the SDK (login, sync, lock) | you import and export it around each operation |
| Typical host | a native wallet app (the SampleApp) | a web-view wrapper app, or an app with its own protocol stack |

Both are the same code: `SirosWallet` is a facade over the lower modules. The
module graph keeps them apart - only `SirosWallet` depends on `SirosFlow`, and
`SirosFlow` is where the OID4VCI/OID4VP orchestration and the engine
conversation live:

```
SirosCredentials <- SirosKeystore <- SirosAuth <- SirosFlow <- SirosWallet
        ^                ^              ^            ^
   SirosTransport -------+--------------+------------+
```

Composing the three lower modules never constructs the facade and never
starts an engine session. Both APIs ship in the same release and follow the
same deprecation policy.

## Choosing

Use the **orchestrated API** when your app *is* the wallet. Start from the
SampleApp.

Use the **low-level API** when your app hosts the SIROS web wallet (or another
page) that already runs the flows and native is there for keys, proving and
proximity; when you have your own OID4VCI/OID4VP client; or when you need one
capability - a reader over BLE, issuer-trust evaluation - without a wallet.

Do not mix the two for the same container in the same process: the facade
assumes it is the only writer of the container it unlocked.

## The low-level composition

| Module | Type | Needs | Gives |
|---|---|---|---|
| SirosKeystore | `JweKeystore` | nothing | the PRF-sealed container: `unlock(prfOutput:encryptedContainer:hkdfSalt:hkdfInfo:)`, `exportEncryptedContainer()`, `generateKey`, `sign`, SD-JWT KB-JWT / mdoc device auth |
| SirosKeystore | `UniFFISigner(config:authProvider:)` + `WscdKeystoreAdapter(signer:)` | a `WscdAuthProvider` for PIN prompts if a plugin needs one | the same `KeystoreManager` surface with keys held by a WSCD plugin (software, FIDO2 security key over CTAP2, R2PS) |
| SirosKeystore | `MdocProximitySession` | callbacks for credentials, consent, device signature, reader trust | a complete ISO 18013-5 session over BLE (`BleCentralClient` / `BlePeripheralServer`), NFC static handover |
| SirosKeystore | `LongfellowZkProofSystem(zkCircuitClient:)`, `MdocDeviceResponseBuilder.buildZkDeviceResponse` | a `ZkCircuitClient` | ZK proof generation and the ZK mdoc device response |
| SirosAuth | `ASAuthorizationAuthProvider` | a presentation anchor | passkey registration/assertion with PRF (iOS 18+); security keys over the SDK's CTAP2 transports |
| SirosAuth | `AuthServerClient(baseUrl:tenantId:)` | nothing | the passkey challenge/response conversation with SIROS's auth server, if you use it |
| SirosCredentials | `CredentialMatcher`, `MdocCbor`, `SdJwtParts`, `VctmFetcher`, `ZkCircuitClient` | nothing | parsing, DCQL matching, display metadata, circuit catalog |
| SirosTransport | `BridgeDescriptorBuilder` | nothing | the capability descriptor a wrapper advertises to its page |

Container round trip for a host that owns the keys (stage B of the bridge
plan):

```swift
let keystore = JweKeystore()   // or WscdKeystoreAdapter(signer: try UniFFISigner(config: config, authProvider: pinProvider))
try await keystore.unlock(prfOutput: prf, encryptedContainer: containerFromPage, hkdfSalt: hkdfSalt, hkdfInfo: hkdfInfo)
let keyId = try await keystore.generateKey(algorithm: "ES256")
let signature = try await keystore.sign(keyId: keyId, payload: payload, algorithm: "ES256")
let updated = try await keystore.exportEncryptedContainer()   // hand back to the page
keystore.lock()
```

The PRF output comes from a passkey assertion:
`ASAuthorizationAuthProvider.authenticate(options: AuthenticateOptions(rpId:challenge:prfSaltsByCredential:))`
returns `AuthenticateResult.prfOutput`; the salt per credential is whatever the
container was sealed with.

## Gaps relative to the Android SDK

Tracked as Swift parity work for the bridge plan; until they land, a
low-level host on iOS does these itself:

- **No facade-free ZK presentation entry point yet.** Android has
  `ZkMdocPresentation` (registry + `present(request, signer)` +
  `systemIds()`); on iOS the equivalent assembly is still a private helper of
  `SirosWallet`. A low-level host composes `LongfellowZkProofSystem`/
  `VegaProofSystem` and `MdocDeviceResponseBuilder.buildZkDeviceResponse`
  directly.
- **Vega** ships in the Swift SDK (`VegaProofSystem`, iOS-only like
  Longfellow), sharing a `ZkProverResidency` with `LongfellowZkProofSystem`
  so the process holds at most one resident prover at a time (ported from
  Android's `ZkProverResidency` - see that type's doc comment for why this
  exists). `SirosWallet.init` wires both in automatically; a low-level host
  constructing either directly must supply the same `ZkProverResidency`
  instance to both to get that guarantee itself.
- **Issuer identity for trust evaluation** (`MdocIssuerIdentity`) lives in the
  `SirosWallet` module on both platforms; a low-level host that evaluates
  issuer trust re-derives the issuer URL from the IACA certificate's SAN
  itself until it moves down.

## What the low-level API deliberately does not include

The engine conversation and OID4VCI/OID4VP orchestration (`SirosFlow`),
private-data sync with go-wallet-backend, and account bookkeeping
(`AccountRegistry`, session stores). Those are facade concerns; the low-level
API takes PRF output and container bytes as inputs and remembers nothing.
