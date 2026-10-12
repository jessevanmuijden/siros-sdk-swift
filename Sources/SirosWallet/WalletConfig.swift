// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosCredentials
import SirosKeystore

/// Configuration for ``SirosWallet``.
public struct WalletConfig: Sendable {
    /// The wallet backend URL (e.g. "https://wallet.sirosid.dev").
    public var backendUrl: String

    /// Ordered list of base URLs each expected to serve the same
    /// `go-zk-circuits` `/v1` catalog (a primary hosting service plus any
    /// mirror/fallback hosts) - see `ZkCircuitClient`'s doc comment for why
    /// this is a list tried in order, not a single URL: unlike a
    /// registry-aggregation setting, these are mirrors of one catalog, so
    /// the SDK tries each in turn and stops at the first success rather
    /// than merging results. Defaults to
    /// `[ZkCircuitClient.defaultZkCircuitUrl]` (the real deployed service,
    /// `https://zk-circuits.fly.dev`). Not yet wired into any active ZK
    /// proof-generation flow - no such flow exists yet - this only makes a
    /// configured `ZkCircuitClient` available on `SirosWallet` for future
    /// phases of the Longfellow ZKP work.
    public var zkCircuitUrls: [String]

    /// Tenant identifier. Defaults to "default".
    public var tenantId: String

    /// Engine base URL (e.g. "https://engine.sirosid.dev"). The SDK appends
    /// the WebSocket path (`/api/v2/wallet?...`) automatically. When empty,
    /// the SDK auto-discovers it from `/.well-known/wallet-configuration`
    /// or falls back to `backendUrl`.
    public var engineUrl: String

    /// OAuth redirect URI for authorization code flows.
    public var redirectUri: String

    /// Custom ``CredentialStore`` implementation. When `nil`, uses
    /// a keystore-backed encrypted store.
    public var credentialStore: (any CredentialStore)?

    /// Optional function to rewrite URLs before they are opened in the browser.
    public var urlRewriter: (@Sendable (String) -> String)?

    /// When true, biometric/device authentication is required for passkey operations.
    public var requireUserAuth: Bool

    /// Use the WMP (Wallet Messaging Protocol) JSON-RPC 2.0 transport instead
    /// of the legacy engine protocol. Requires go-wallet-backend with WMP support.
    public var useWmpProtocol: Bool

    /// Initial value of ``SirosWallet/transactionDataEnabled`` (EC TS12
    /// payment SCA). Default `false`. A runtime setting, not a build flag:
    /// the wallet exposes the live value and a change applies to flows
    /// started afterwards. Even when `true`, TS12 handling is effective only
    /// once a consent handler is registered.
    public var transactionDataEnabled: Bool

    /// Every WSCD plugin the host app has a ready `KeystoreManager` instance
    /// for, keyed by plugin ID (`"softkey"` / `"r2ps"` / `"fido2"` today -
    /// see `WscdPluginCapabilities`), each with its own platform transport
    /// (BLE/USB/CoreNFC/etc) already wired up - only the host app can
    /// construct these, since that transport wiring is deliberately kept out
    /// of the SDK. `nil` (the default) is fully backward compatible: none of
    /// `WscdSelectionPolicy`'s selection logic engages, and credential-
    /// issuance key generation behaves exactly as it does today, always
    /// using the wallet's single `keystore`. An explicitly *empty*
    /// dictionary is NOT the same as `nil` - it means the host app opted
    /// into multi-plugin selection but has zero plugins registered right
    /// now, so a credential type that declares a key-storage requirement
    /// still gets `WscdSelectionError.noEligiblePlugin` rather than a
    /// silent fallback to the default keystore. Only set this to opt into
    /// multi-plugin selection.
    public var availableKeystores: [String: KeystoreManager]?

    /// Host-app-supplied default `(issuer, credentialType) -> pluginId`
    /// mapping (key: `"\(issuer)|\(credentialType)"`), consulted by
    /// `WscdSelectionPolicy` before falling back to auto-pick/user-prompt -
    /// lets an integrator that already knows the right answer skip the
    /// prompt entirely. Only consulted when `availableKeystores` is set.
    public var defaultWscdMapping: [String: String]?

    /// Asks the host app to pick a WSCD plugin when more than one
    /// registered plugin meets a credential type's declared key-storage
    /// requirement and neither TOFU nor `defaultWscdMapping` resolves it -
    /// see `RequestWscdChoice`'s doc comment. Only consulted when
    /// `availableKeystores` is set.
    public var requestWscdChoice: RequestWscdChoice?

    /// Base URL for go-wallet-backend's credential-type registry service
    /// (TS11-backed, cached, includes `attestation_los`/required-key-storage-
    /// tier data) - queried as `<registryUrl>/type-metadata?vct=<id>` for
    /// both SD-JWT `vct` values and ISO 18013-5 mdoc `doctype` values (one
    /// handler/store serves both formats under the same generic query param
    /// name). This is the SAME service the reference wallet-frontend
    /// implementation always calls for VCT/mdoc type-metadata lookups
    /// (`VCT_REGISTRY_URL`), never the issuer directly.
    ///
    /// `nil` (the common case) derives this automatically as
    /// `<backendUrl>/registry` - the registry route is mounted under a
    /// `/registry` path prefix on the same host/port as the rest of
    /// go-wallet-backend's public API. Set this explicitly only to point at
    /// a registry deployment independent of `backendUrl` (e.g. a different
    /// environment's registry, or a standalone registry service), matching
    /// `VCT_REGISTRY_URL` being a distinct, independently-settable config
    /// value in wallet-frontend.
    public var registryUrl: String?

    /// PEM-encoded RICAL (Reader Identity CA List, ISO/IEC 18013-5 second
    /// edition Annex F) root certificate(s) for `SirosWallet.evaluateReaderTrust`'s
    /// local fallback path - plain X.509 path validation against these
    /// anchors, with none of the RICAL CBOR/COSE document parsing or
    /// `trustConstraints` enforcement the remote go-trust `mdocrical`
    /// registry does. Empty by default: until an operator configures at
    /// least one root here, local reader-trust evaluation always reports
    /// untrusted rather than silently no-oping.
    public var readerTrustRootCertificatesPem: [String]

    /// How `SirosWallet.evaluateReaderTrust` answers a RICAL question:
    /// remotely against go-trust, locally against the roots above, or
    /// remotely with local as a fallback. Defaults to
    /// `.remoteWithLocalFallback`, which is what every previous release did.
    public var readerTrustEvaluationMode: MdocTrustEvaluationMode

    /// Forces `SirosWallet.evaluateReaderTrust` to always use the local
    /// X.509 fallback (see `readerTrustRootCertificatesPem`) instead of
    /// attempting the remote AuthZEN call first.
    ///
    /// Now a view onto `readerTrustEvaluationMode`, so reading and writing
    /// it both still work: `true` is `.localOnly`, and setting it to `false`
    /// restores `.remoteWithLocalFallback`.
    ///
    /// - Warning: Superseded by `readerTrustEvaluationMode`, which can also
    ///   express "remotely, and fail closed if go-trust is unreachable" -
    ///   a choice a boolean cannot make.
    @available(*, deprecated, message: "Use readerTrustEvaluationMode. `true` is .localOnly, `false` is .remoteWithLocalFallback.")
    public var preferLocalReaderTrustEvaluation: Bool {
        get { readerTrustEvaluationMode == .localOnly }
        set { readerTrustEvaluationMode = newValue ? .localOnly : .remoteWithLocalFallback }
    }

    /// PEM-encoded VICAL (Verified Issuer CA List, ISO/IEC 18013-5 Annex C)
    /// root certificate(s) for `SirosWallet.evaluateIssuerTrust`'s local
    /// fallback path - plain X.509 path validation against these anchors,
    /// with none of the VICAL CBOR/COSE document parsing or per-certificate
    /// `docType` enforcement the remote go-trust `vical` registry does.
    /// Empty by default: until an operator configures at least one root
    /// here, local issuer-trust evaluation always reports untrusted rather
    /// than silently no-oping - same convention as `readerTrustRootCertificatesPem`.
    public var issuerTrustRootCertificatesPem: [String]

    /// How `SirosWallet.evaluateIssuerTrust` answers a VICAL question. Same
    /// convention as `readerTrustEvaluationMode`, and independent of it: a
    /// wallet may reasonably insist on remote issuer trust at issuance time
    /// while tolerating local reader trust at an offline checkpoint.
    public var issuerTrustEvaluationMode: MdocTrustEvaluationMode

    /// Forces `SirosWallet.evaluateIssuerTrust` to always use the local
    /// X.509 fallback (see `issuerTrustRootCertificatesPem`) instead of
    /// attempting the remote AuthZEN call first.
    ///
    /// - Warning: Superseded by `issuerTrustEvaluationMode`. Same convention
    ///   as `preferLocalReaderTrustEvaluation`.
    @available(*, deprecated, message: "Use issuerTrustEvaluationMode. `true` is .localOnly, `false` is .remoteWithLocalFallback.")
    public var preferLocalIssuerTrustEvaluation: Bool {
        get { issuerTrustEvaluationMode == .localOnly }
        set { issuerTrustEvaluationMode = newValue ? .localOnly : .remoteWithLocalFallback }
    }

    /// The interoperability profile this wallet speaks when nothing more
    /// specific is known - see ``InteropProfile``. Both HAIP and DIIP are
    /// implemented and a wallet holds credentials from both; this decides only
    /// which shape an OID4VCI proof takes when the Issuer's own metadata says
    /// nothing. Presentation always follows the credential's own `cnf`, so
    /// this never affects a credential the wallet already holds.
    public var interopProfile: InteropProfile

    /// Per-Issuer overrides of ``interopProfile``, keyed by credential issuer
    /// identifier (matched by prefix so a path under it counts).
    ///
    /// An escape hatch for an Issuer whose metadata is wrong, not the normal
    /// path: the binding is normally negotiated from what the Issuer
    /// advertises - see `SirosWallet.holderBinding(for:)`.
    public var issuerInteropProfiles: [String: InteropProfile]

    /// The DIIP profile version this wallet targets when it speaks
    /// ``InteropProfile/diip`` - see ``DiipProfile``.
    ///
    /// Defaults to the newest this SDK implements. Each version is additive
    /// over the one before, so the default does not drop support for an
    /// ecosystem still on an older release; pin an older one only when a
    /// deployment needs the wire details of that release exactly.
    public var diipProfile: DiipProfile

    /// Leeway, in seconds, applied when checking a credential's validity
    /// window and a Status List Token's own lifetime - so a credential is not
    /// shown as expired because of a few seconds of clock skew. Matches the
    /// tolerance wallet-frontend applies to signature verification.
    public var clockTolerance: TimeInterval

    /// The blind-BBS credential types (JWP `vct` values) this deployment
    /// actually issues, if any - mirrors Kotlin's
    /// `WalletConfig.bbsCredentialTypes`. `BbsProofSystem` has its holder
    /// state in this wallet's own keystore (see `BbsHolderStateVault`),
    /// unlike `LongfellowZkProofSystem`/`VegaProofSystem`, which need no
    /// wallet-local state at all - so it is registered here, in
    /// `SirosWallet.init`, rather than being a fixed member of the mdoc ZK
    /// registry. Empty (the default) means this deployment issues no BBS
    /// credentials, and `BbsProofSystem` is not registered at all: an empty
    /// set is not "support nothing in particular", it is "this type does not
    /// exist here" - `BbsProofSystem.supportedCredentialTypes` maps straight
    /// from this set, and `ZkProofSystemRegistry.resolve` already requires
    /// that set to contain the requested credential type before
    /// `matchingSpec` is even consulted, so a verifier's `zk_system_type`
    /// request for BBS could never actually resolve against an empty set
    /// regardless of registration (Copilot review, PR #194: an earlier
    /// version of this comment claimed the opposite - that registering
    /// anyway would let such a request resolve and only fail later at
    /// presentation time - which `resolve`'s own logic already rules out).
    /// The real, observable reason to skip registration is narrower:
    /// `ZkProofSystemRegistry.registeredSystemIds` is this wallet's
    /// diagnostics/settings-UI surface for "what can I actually present" -
    /// advertising a system id there that can never resolve a real request
    /// would be a pointless, misleading entry.
    public var bbsCredentialTypes: Set<String>

    public init(
        backendUrl: String,
        tenantId: String = "default",
        engineUrl: String = "",
        redirectUri: String = "",
        credentialStore: (any CredentialStore)? = nil,
        urlRewriter: (@Sendable (String) -> String)? = nil,
        requireUserAuth: Bool = true,
        useWmpProtocol: Bool = false,
        transactionDataEnabled: Bool = false,
        availableKeystores: [String: KeystoreManager]? = nil,
        defaultWscdMapping: [String: String]? = nil,
        requestWscdChoice: RequestWscdChoice? = nil,
        registryUrl: String? = nil,
        zkCircuitUrls: [String] = [ZkCircuitClient.defaultZkCircuitUrl],
        readerTrustRootCertificatesPem: [String] = [],
        preferLocalReaderTrustEvaluation: Bool = false,
        issuerTrustRootCertificatesPem: [String] = [],
        preferLocalIssuerTrustEvaluation: Bool = false,
        readerTrustEvaluationMode: MdocTrustEvaluationMode? = nil,
        issuerTrustEvaluationMode: MdocTrustEvaluationMode? = nil,
        interopProfile: InteropProfile = .default,
        issuerInteropProfiles: [String: InteropProfile] = [:],
        diipProfile: DiipProfile = .latest,
        clockTolerance: TimeInterval = 60,
        bbsCredentialTypes: Set<String> = []
    ) {
        self.backendUrl = backendUrl
        self.tenantId = tenantId
        self.engineUrl = engineUrl
        self.redirectUri = redirectUri
        self.credentialStore = credentialStore
        self.urlRewriter = urlRewriter
        self.requireUserAuth = requireUserAuth
        self.useWmpProtocol = useWmpProtocol
        self.transactionDataEnabled = transactionDataEnabled
        self.availableKeystores = availableKeystores
        self.defaultWscdMapping = defaultWscdMapping
        self.requestWscdChoice = requestWscdChoice
        self.registryUrl = registryUrl
        self.zkCircuitUrls = zkCircuitUrls
        self.readerTrustRootCertificatesPem = readerTrustRootCertificatesPem
        self.issuerTrustRootCertificatesPem = issuerTrustRootCertificatesPem
        // An explicitly chosen mode always wins; the deprecated boolean only
        // decides when no mode was passed at all. The parameter is optional
        // rather than defaulted precisely so that "unset" and "explicitly
        // .remoteWithLocalFallback" are distinguishable - comparing against
        // the default value cannot tell them apart, which would silently
        // downgrade a caller who asked for the fallback mode by name.
        self.readerTrustEvaluationMode = readerTrustEvaluationMode
            ?? (preferLocalReaderTrustEvaluation ? .localOnly : .remoteWithLocalFallback)
        self.issuerTrustEvaluationMode = issuerTrustEvaluationMode
            ?? (preferLocalIssuerTrustEvaluation ? .localOnly : .remoteWithLocalFallback)
        self.interopProfile = interopProfile
        self.issuerInteropProfiles = issuerInteropProfiles
        self.diipProfile = diipProfile
        self.clockTolerance = clockTolerance
        self.bbsCredentialTypes = bbsCredentialTypes
    }

    /// Discover the engine base URL from the backend's
    /// `/.well-known/wallet-configuration` endpoint.
    ///
    /// Returns `nil` if discovery fails — the caller should fall back
    /// to `backendUrl` (single-port deployment).
    public static func discoverEngineUrl(backendUrl: String) async -> String? {
        let urlString = backendUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            + "/.well-known/wallet-configuration"
        guard let url = URL(string: urlString) else { return nil }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let engine = json["engine_url"] as? String,
                  !engine.isEmpty else {
                return nil
            }
            return engine
        } catch {
            return nil
        }
    }
}

/// See `SirosWallet.capabilities`.
public struct WalletCapabilities: Sendable {
    public let nativeAttestation: Bool
    public let wscd: Bool
}
