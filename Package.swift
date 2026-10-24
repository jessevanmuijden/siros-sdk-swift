// swift-tools-version: 5.10
// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import PackageDescription

let package = Package(
    name: "SirosSDK",
    platforms: [
        // iOS 18 is the real floor: the wallet's key material is derived from
        // the WebAuthn PRF output of the login passkey, and Apple's PRF
        // extension (ASAuthorizationPublicKeyCredentialPRFAssertionInput)
        // exists from iOS 18 / macOS 15. On 16 and 17 the package compiled and
        // ran, and login then could not unlock anything. Security-key PRF is
        // gated higher still (26.4) and stays a runtime check.
        .iOS("18.0"),
        // macOS is a CI/test platform only: the native XCFrameworks ship iOS
        // slices, and everything FFI-backed is iOS-gated. Nothing here is a
        // macOS wallet.
        .macOS("15.0"),
    ],
    products: [
        .library(name: "SirosCredentials", targets: ["SirosCredentials"]),
        .library(name: "SirosTransport", targets: ["SirosTransport"]),
        .library(name: "SirosAuth", targets: ["SirosAuth"]),
        .library(name: "SirosKeystore", targets: ["SirosKeystore"]),
        .library(name: "SirosFlow", targets: ["SirosFlow"]),
        .library(name: "SirosWallet", targets: ["SirosWallet"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-docc-plugin", from: "1.4.3"),
        .package(url: "https://github.com/valpackett/SwiftCBOR", from: "0.5.0"),
        // Cross-platform SHA-256 for ZkCircuitClient's artifact hash
        // verification. On Apple platforms CryptoKit is used directly (see
        // ZkCircuitClient.swift's `#if canImport(CryptoKit)`); swift-crypto's
        // `Crypto` module is only actually compiled/linked in on Linux,
        // where CryptoKit doesn't exist at all.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.0"),
        // Circuits fetched from go-zk-circuits (see ZkCircuitClient,
        // SirosCredentials) are zstd-compressed; zk-cred-longfellow's
        // initializeProver expects already-decompressed bytes (confirmed
        // against wallet-frontend's feat/longfellow-zk reference
        // implementation) - decompression is the caller's responsibility,
        // not the native crate's. facebook/zstd ships its own SPM manifest
        // (a plain C target, no Swift wrapper) exposing this as `libzstd`.
        .package(url: "https://github.com/facebook/zstd.git", from: "1.5.6"),
        // VegaProofSystem's ECDSA witness needs a real modular inverse
        // (s^-1 mod the P-256 curve order) - the same operation Kotlin's
        // port does via java.math.BigInteger.modInverse, a trusted
        // platform bignum facility rather than a hand-rolled one. Swift/
        // CryptoKit has no arbitrary-precision integer type at all; this is
        // the de facto standard pure-Swift BigInt (no dependencies of its
        // own), for the same reason: use a well-tested library for this
        // rather than hand-rolling extended-Euclidean-algorithm code in a
        // cryptographic path.
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
        // SVG logo rasterization (pure Swift, zlib licence). Exact pin: it
        // parses untrusted issuer-supplied SVG, so upgrades are deliberate.
        // The refusal guard in SvgLogoRenderer.swift runs BEFORE it.
        .package(url: "https://github.com/swhitty/SwiftDraw.git", exact: "0.29.0"),
    ],
    targets: [
        // --- zk-cred-longfellow UniFFI bindings (XCFramework) ---
        // Built by `make xcframework` in the zk-cred-longfellow crate; the
        // module name is the crate name + "FFI" (`zk_cred_longfellowFFI`),
        // matching siros_wscd_managerFFI's own naming convention below -
        // confirmed by inspecting the real published XCFramework's
        // module.modulemap.
        .binaryTarget(
            name: "zk_cred_longfellowFFI",
            url: "https://github.com/sirosfoundation/zk-cred-longfellow/releases/download/v0.1.1/zk_cred_longfellow.xcframework.zip",
            checksum: "dcbbaaeb5b1075d9794e1c2be830218742558a62aa19276b7b789dd05c6727f6"
        ),

        // --- zk-cred-bbs UniFFI bindings (XCFramework) ---
        // Built by `make xcframework` in the zk-cred-bbs crate. Same naming
        // convention as the two above: crate name + "FFI". Its headers are
        // nested under zk_cred_bbsFFI/ inside the XCFramework precisely so
        // that linking it alongside those two does not collide on a shared
        // include/module.modulemap - see that crate's Makefile.
        .binaryTarget(
            name: "zk_cred_bbsFFI",
            url: "https://github.com/sirosfoundation/zk-cred-bbs/releases/download/v0.0.6/zk_cred_bbs.xcframework.zip",
            checksum: "cfa8afea27c2e2d9b671193ce2a923cef462dc185a953dda5ba5c518f749bac9"
        ),

        // --- siros-dc-matcher UniFFI bindings (XCFramework) ---
        // The shared DCQL engine: the same Rust code the Android credential
        // picker runs as matcher.wasm, so the wallet's own answer and the
        // picker's cannot drift apart. Built by `make xcframework` in that
        // crate; module name is the crate name + "FFI", as with the three
        // below. Headers nest under siros_dc_matcher_ffiFFI/ so that linking
        // it alongside the others does not collide on a shared
        // Headers/module.modulemap.
        .binaryTarget(
            name: "siros_dc_matcher_ffiFFI",
            url: "https://github.com/sirosfoundation/siros-dc-matcher/releases/download/v0.11.0/siros_dc_matcher_ffi.xcframework.zip",
            checksum: "7f7a1050eb645265830dd0fa3962c351ba1553ea04d8456612982cbb5b8c6c7b"
        ),

        // --- zk-cred-vega UniFFI bindings (XCFramework) ---
        // Built by `make xcframework` in the zk-cred-vega crate (Swift/iOS
        // support added there as a prerequisite - sirosfoundation/zk-cred-vega#9,
        // merged, released as v0.0.6). Same naming convention as the three
        // above: crate name + "FFI", headers nested under zk_cred_vegaFFI/
        // to avoid the same module.modulemap collision.
        .binaryTarget(
            name: "zk_cred_vegaFFI",
            url: "https://github.com/sirosfoundation/zk-cred-vega/releases/download/v0.0.6/zk_cred_vega.xcframework.zip",
            checksum: "f95cf6d304862e1b3ba7274bda654ed19d99ff3dd30d03cb97109863606779a0"
        ),

        // --- Credentials: data models, DCQL matcher, VCTM types ---
        .target(
            name: "SirosCredentials",
            dependencies: [
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
                .product(name: "SwiftDraw", package: "SwiftDraw"),
                // AnyCodable (for ZkCircuitDescriptor.params' generic
                // map[string]any) already exists in SirosTransport - reused
                // here rather than duplicated. SirosTransport has no
                // dependencies of its own, so this doesn't introduce a cycle.
                "SirosTransport",
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
                // zk_cred_longfellowFFI's XCFramework only ships iOS slices
                // (device + simulator) - no macOS slice exists, and this
                // package's CI builds/tests the whole thing on bare macOS
                // too, so this dependency must be scoped to iOS only.
                // FFI-dependent code in this target is correspondingly
                // wrapped in `#if os(iOS)` (see Generated/zk_cred_longfellow.swift).
                .target(name: "zk_cred_longfellowFFI", condition: .when(platforms: [.iOS])),
                // Same story, same gate: zk_cred_bbsFFI ships iOS slices
                // only, and BbsProofSystem.swift plus
                // Generated/zk_cred_bbs.swift are wrapped in `#if os(iOS)`
                // to match.
                .target(name: "zk_cred_bbsFFI", condition: .when(platforms: [.iOS])),
                // Same story, same gate: iOS slices only, and both
                // SharedDcqlMatcher.swift and
                // Generated/siros_dc_matcher_ffi.swift are `#if os(iOS)` to
                // match. On macOS CredentialMatcher keeps its own parsing
                // path, which is what it used everywhere until now.
                .target(name: "siros_dc_matcher_ffiFFI", condition: .when(platforms: [.iOS])),
                // Same story, same gate: zk_cred_vegaFFI ships iOS slices
                // only (zk-cred-vega's own halo2curves dependency can't
                // cross-compile for the legacy x86_64 iOS simulator, so
                // only aarch64 device + simulator slices exist at all -
                // see that crate's Makefile), and VegaProofSystem.swift
                // plus Generated/zk_cred_vega.swift are `#if os(iOS)` to
                // match.
                .target(name: "zk_cred_vegaFFI", condition: .when(platforms: [.iOS])),
            ],
            path: "Sources/SirosCredentials"
        ),
        .testTarget(
            name: "SirosCredentialsTests",
            dependencies: [
                "SirosCredentials",
                "SirosTransport",
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
            ],
            path: "Tests/SirosCredentialsTests",
            // The BBS fixture, generated by `make sdk-fixture` in the
            // zk-cred-bbs crate and read through `Bundle.module`. The zkp_req
            // conformance vectors keep their directories (several share file names).
            resources: [.process("Resources"), .copy("ZkpReqVectors")]
        ),

        // --- Transport: WebSocket + WMP protocol ---
        .target(
            name: "SirosTransport",
            path: "Sources/SirosTransport"
        ),
        .testTarget(
            name: "SirosTransportTests",
            dependencies: ["SirosTransport"],
            path: "Tests/SirosTransportTests"
        ),

        // --- Auth: WebAuthn / passkey authentication ---
        .target(
            name: "SirosAuth",
            dependencies: ["SirosTransport", "SirosCredentials", "SirosKeystore"],
            path: "Sources/SirosAuth"
        ),
        .testTarget(
            name: "SirosAuthTests",
            dependencies: ["SirosAuth"],
            path: "Tests/SirosAuthTests"
        ),

        // --- siros-wscd-manager UniFFI bindings (XCFramework) ---
        // Built by `make xcframework` in the siros-wscd-manager crate;
        // the module name is the crate name + "FFI"
        // (`siros_wscd_managerFFI`, NOT a friendlier name like
        // "SirosWscdFFI" - confirmed by inspecting the real published
        // XCFramework's module.modulemap).
        .binaryTarget(
            name: "siros_wscd_managerFFI",
            url: "https://github.com/sirosfoundation/siros-wscd-manager/releases/download/v0.10.0/siros_wscd_manager.xcframework.zip",
            checksum: "a2119f1c96499acec8ce64468ea99233872e1529fa65fa099dadb1ebb111fb2a"
        ),

        // --- Keystore: JWE-encrypted key management ---
        .target(
            name: "SirosKeystore",
            dependencies: [
                "SirosCredentials",
                // siros_wscd_managerFFI's XCFramework only ships iOS slices
                // (device + simulator) - no macOS slice exists, and this
                // package's CI builds/tests the whole thing on bare macOS
                // too (swift.yml's test-macos job), so this dependency must
                // be scoped to iOS only. FFI-dependent code in this target
                // is correspondingly wrapped in `#if os(iOS)`.
                .target(name: "siros_wscd_managerFFI", condition: .when(platforms: [.iOS])),
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
                // Only used by LongfellowZkProofSystem.swift and
                // VegaProofSystem.swift, both themselves `#if os(iOS)`-gated
                // (see those files) since the native FFI they each wrap is
                // iOS-only.
                .product(name: "libzstd", package: "zstd", condition: .when(platforms: [.iOS])),
                // Only used by VegaProofSystem.swift's ECDSA witness
                // (a real modular inverse mod the P-256 curve order) -
                // itself `#if os(iOS)`-gated, same reason as libzstd above.
                .product(name: "BigInt", package: "BigInt", condition: .when(platforms: [.iOS])),
            ],
            path: "Sources/SirosKeystore"
        ),
        .testTarget(
            name: "SirosKeystoreTests",
            dependencies: [
                "SirosKeystore",
                // Needed by LongfellowZkVectorTests for the vendored
                // zk_cred_longfellow UniFFI bindings (initializeProver,
                // proveWithPpid, CircuitVersion), which live in
                // SirosCredentials's own module, not SirosKeystore's.
                "SirosCredentials",
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
                .product(name: "libzstd", package: "zstd", condition: .when(platforms: [.iOS])),
            ],
            path: "Tests/SirosKeystoreTests",
            resources: [.copy("Resources")]
        ),

        // --- Flow: OID4VCI / OID4VP flow orchestration ---
        .target(
            name: "SirosFlow",
            dependencies: ["SirosTransport", "SirosKeystore", "SirosAuth"],
            path: "Sources/SirosFlow"
        ),
        .testTarget(
            name: "SirosFlowTests",
            dependencies: ["SirosFlow"],
            path: "Tests/SirosFlowTests"
        ),

        // --- Wallet: main facade ---
        .target(
            name: "SirosWallet",
            dependencies: [
                "SirosTransport",
                "SirosAuth",
                "SirosKeystore",
                "SirosFlow",
                "SirosCredentials",
                // Same arrangement as SirosCredentials: CryptoKit on Apple
                // platforms, swift-crypto's API-identical `Crypto` on Linux,
                // so the certificate hashes the trust evaluation sends are
                // real SHA-256 digests on every platform the tests run on.
                .product(name: "Crypto", package: "swift-crypto", condition: .when(platforms: [.linux])),
            ],
            path: "Sources/SirosWallet"
        ),
        .testTarget(
            name: "SirosWalletTests",
            dependencies: [
                "SirosWallet",
                // Needed to build a realistic mdoc StoredCredential fixture
                // for SirosWalletCredentialStatusRaceTests (a claims-free
                // MSO - neither validityInfo nor status - the one shape
                // `credentialStatus(of:)`'s own parsing can produce nil
                // claims for).
                .product(name: "SwiftCBOR", package: "SwiftCBOR"),
            ],
            path: "Tests/SirosWalletTests"
        ),
    ]
)
