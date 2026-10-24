# SIROS SDK for iOS/macOS (Swift)

[![Swift CI](https://github.com/sirosfoundation/siros-sdk-swift/actions/workflows/swift.yml/badge.svg)](https://github.com/sirosfoundation/siros-sdk-swift/actions/workflows/swift.yml)
[![codecov](https://codecov.io/gh/sirosfoundation/siros-sdk-swift/graph/badge.svg)](https://codecov.io/gh/sirosfoundation/siros-sdk-swift)
[![Swift 5.10+](https://img.shields.io/badge/Swift-5.10+-orange.svg)](https://swift.org)
[![Platform](https://img.shields.io/badge/platform-iOS%2016%2B%20%7C%20macOS%2013%2B-lightgrey.svg)](https://developer.apple.com)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/sirosfoundation/siros-sdk-swift/badge)](https://scorecard.dev/viewer/?uri=github.com/sirosfoundation/siros-sdk-swift)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)

Native Swift SDK for integrating SIROS ID wallet infrastructure into iOS and macOS apps.

## Modules

| Module | Description |
|--------|-------------|
| `SirosTransport` | WMP client (WebSocket), JSON-RPC codec, engine session |
| `SirosAuth` | WebAuthn/passkey authentication, backend API client |
| `SirosKeystore` | JWE-encrypted keystore, HKDF key derivation, VP signing |
| `SirosFlow` | OID4VCI/OID4VP flow orchestration over WMP |
| `SirosCredentials` | Credential storage, DCQL matching, VCTM, SD-JWT utilities |
| `SirosWallet` | Top-level wallet API combining all modules |

## Requirements

- iOS 18+ (macOS 15+ for building and running the test suite only; the native XCFrameworks ship iOS slices)
- Swift 5.10+
- Xcode 16+ (for Apple platforms)

## Installation

Add the package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/sirosfoundation/siros-sdk-swift.git", from: "0.1.0"),
]
```

Or in Xcode: File → Add Package Dependencies → enter the repository URL.

## Quick Start

```swift
import SirosWallet
import SirosAuth

let config = WalletConfig(
    backendUrl: "https://wallet.example.com",
    tenantId: "your-tenant-id"
)

// On iOS, use the built-in ASAuthorization provider:
let authProvider = ASAuthorizationAuthProvider(presentationAnchor: window)

// Use Keychain for persistent session storage:
let sessionStore = KeychainSessionStore(service: "com.example.wallet")

guard let wallet = SirosWallet(
    config: config,
    authProvider: authProvider,
    sessionStore: sessionStore
) else {
    fatalError("Failed to initialize wallet (missing keystore on this platform)")
}

// Register / login
try await wallet.register(userName: "alice")
try await wallet.login()
```

## Key Features

### WMP (Wallet Messaging Protocol) Support

Full WMP implementation as an alternative to the legacy WebSocket engine protocol:

- **`WmpPeer`** — JSON-RPC 2.0 dispatch with profile-based routing
- **`OpenID4xProfile`** — OID4VCI/OID4VP flow handling (sign, match, trust evaluation)
- **`WmpHttpSseTransport`** — HTTP+SSE transport (Apple platforms)
- **`WmpWebSocketTransport`** — WebSocket transport with `wmp.v1` subprotocol

Enable via `WalletConfig(useWmpProtocol: true)`. Requires backend with WMP endpoint.

### Engine URL Auto-Discovery

The SDK auto-discovers the engine WebSocket URL from `/.well-known/wallet-configuration`:

```swift
let config = WalletConfig(
    backendUrl: "https://wallet.example.com"
    // engineUrl defaults to "" → auto-discovered at runtime
)
```

### Batch Credential Issuance

`KeystoreManager.generateProof(freshKey:)` supports batch VCI conformance — each credential in a batch is bound to a unique key to prevent verifier linkability.

### Identity Verification (FaceTec)

`FaceTecIDVProvider` runs FaceTec 10's liveness, document scan with NFC chip
read and photo match as one session against facetec-api, and returns the
credential offer. Refusals arrive as typed `IDVError`s. See
[docs/IDENTITY-VERIFICATION.md](docs/IDENTITY-VERIFICATION.md) for the
facetec-api contract the provider keeps and the error-code table.

### Adding a passkey

```swift
switch try await wallet.addPasskey(nickname: "Laptop") {
case .added:
    break  // the new passkey can now unlock the wallet's data too
case .sessionChanged:
    break  // the backend accepted it for the account it was started for, but the
           // active session changed meanwhile, so nothing was applied locally
case .localCommitFailed:
    break  // the backend accepted it and the cached container has it; the wallet
           // locked its keystore - unlock again to pick the new entry up
case .authorizationRequired, .authorizationFailed, .retryNeeded, .privateDataConflict:
    break  // nothing changed; call again (the backend's challenge was spent)
case .authorizerUnavailable, .passkeyCreationUnavailable, .prfUnsupported,
     .registrationRejected, .walletLocked, .insufficientScope, .sessionRevoked:
    break  // nothing changed
}
```

An existing passkey authorises the addition (from the wallet's `AuthProvider`,
or the optional `authorizer:` closure); an account with no passkey needs none.
The keystore must be unlocked: the new passkey is given its own key to the
container, sent with it.

### Deleting the account

```swift
switch await wallet.deleteAccount(confirmation: "DELETE") {
case .deleted, .cleanupPending, .operatorRequired:
    break  // the account is gone (or being removed); local state was wiped
case .retryNeeded(let reason):
    break  // nothing was wiped; call again, a new passkey assertion is asked for
case .failed(let failure):
    break  // nothing was wiped
}
```

A fresh passkey assertion from the wallet's `AuthProvider` (or the optional
`stepUp:` closure) authorises the deletion. Only an accepted deletion wipes the
local state; the `LocalWipeReport` lists anything that could not be removed.

## Two APIs: orchestrated and low-level

`SirosWallet` runs the whole wallet for you. Hosts that already run the
OID4VCI/OID4VP flows - a web-view wrapper around the SIROS web wallet, an app
with its own protocol client - compose `SirosKeystore`, `SirosAuth` and
`SirosCredentials` directly, without `SirosFlow` or the facade. Both are
supported; see [docs/TWO-APIS.md](docs/TWO-APIS.md).

## Architecture

```
┌─────────────────────────────────────────┐
│           Your iOS/macOS App            │
│  ┌───────────────────────────────────┐  │
│  │          SIROS SDK                │  │
│  │  ┌─────────┐  ┌───────────────┐  │  │
│  │  │  Flow   │  │  Credentials  │  │  │
│  │  ├─────────┤  ├───────────────┤  │  │
│  │  │Keystore │  │   Transport   │  │  │
│  │  ├─────────┤  ├───────────────┤  │  │
│  │  │  Auth   │  │    Wallet     │  │  │
│  │  └─────────┘  └───────────────┘  │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

## Build & Test

```bash
# Run all tests
swift test --parallel

# Build for iOS Simulator
swift build \
  --sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" \
  --triple arm64-apple-ios18.0-simulator
```

## Documentation

API documentation is generated using [DocC](https://www.swift.org/documentation/docc/).

```bash
# Generate documentation
swift package generate-documentation --target SirosWallet
```

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.
