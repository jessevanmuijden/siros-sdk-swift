// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosWallet
import SirosAuth
import SirosCredentials
import SirosKeystore

/// Which of the two mdoc trust paths runs — remote AuthZEN against go-trust,
/// or local X.509 validation against configured RICAL/VICAL roots — is a
/// security decision, not a performance one: the local path parses no
/// RICAL/VICAL CBOR and enforces neither `trustConstraints` nor `docType`.
///
/// These tests pin apart the three outcomes that must never collapse into one
/// another: a backend that said no, a backend that refused *us*, and a backend
/// that was not there at all.
final class MdocTrustEvaluationModeTests: XCTestCase {

    /// The wallet never authenticates in these tests - every path under test
    /// either short-circuits before the backend or has its remote half
    /// injected - so this only needs to exist, not work.
    private final class NoopAuthProvider: AuthProvider {
        struct NotImplemented: Error {}
        func register(options: RegisterOptions) async throws -> RegisterResult { throw NotImplemented() }
        func authenticate(options: AuthenticateOptions) async throws -> AuthenticateResult { throw NotImplemented() }
        func getPrfOutput(credentialId: Data, salt: Data) async throws -> PrfOutput { throw NotImplemented() }
    }

    /// Enough of a keystore to let `SirosWallet` initialise. Passing one
    /// explicitly rather than `#if canImport(CryptoKit)`-gating the file keeps
    /// these tests running on Linux CI too - the trust routing under test is
    /// platform-independent, and gating it would mean the Linux job proves
    /// nothing about it.
    private final class StubKeystoreManager: KeystoreManager, @unchecked Sendable {
        var isUnlocked: Bool { true }
        func unlock(prfOutput: Data, encryptedContainer: Data, hkdfSalt: Data, hkdfInfo: Data) async throws {}
        func lock() {}
        func generateKey(algorithm: String) async throws -> String { "key" }
        func sign(keyId: String, payload: Data, algorithm: String) async throws -> Data { Data() }
        func generateProof(audience: String, nonce: String, freshKey: Bool) async throws -> String { "proof" }
        func signPresentation(nonce: String, audience: String, credentialIds: [Int64], kid: String?) async throws -> String { "" }
        func signVpToken(credential: String, disclosedClaims: [String]?, nonce: String, audience: String, kid: String?) async throws -> String { "" }
        func exportEncryptedContainer() async throws -> Data { Data() }
        func listKeys() -> [KeyInfo] { [] }
        func saveCredential(id: Int64, json: String) async throws {}
        func getCredential(id: Int64) async throws -> String? { nil }
        func getAllCredentials() async throws -> [Int64: String] { [:] }
        func deleteCredential(id: Int64) async throws {}
        func clearCredentials() async throws {}
        func savePresentationRecord(id: Int64, json: String) async throws {}
        func getAllPresentationRecords() async throws -> [Int64: String] { [:] }
        func clearPresentationRecords() async throws {}
        func generateKeypairs(count: Int) async throws -> [KeypairInfo] { [] }
    }

    private func makeWallet(_ config: WalletConfig) -> SirosWallet {
        let wallet = SirosWallet(config: config, authProvider: NoopAuthProvider(), keystore: StubKeystoreManager())
        XCTAssertNotNil(wallet, "wallet should initialise when given an explicit keystore")
        return wallet!
    }

    private func config(
        reader: MdocTrustEvaluationMode = .remoteWithLocalFallback,
        issuer: MdocTrustEvaluationMode = .remoteWithLocalFallback
    ) -> WalletConfig {
        WalletConfig(
            backendUrl: "https://example.invalid",
            readerTrustEvaluationMode: reader,
            issuerTrustEvaluationMode: issuer
        )
    }

    // MARK: - The deprecated boolean still means what it meant

    @available(*, deprecated, message: "Exercises the deprecated property on purpose.")
    func testLegacyPreferLocalBooleanMapsToLocalOnly() {
        var config = WalletConfig(backendUrl: "https://example.invalid")
        XCTAssertEqual(config.readerTrustEvaluationMode, .remoteWithLocalFallback)

        config.preferLocalReaderTrustEvaluation = true
        XCTAssertEqual(config.readerTrustEvaluationMode, .localOnly)
        XCTAssertTrue(config.preferLocalReaderTrustEvaluation)

        // Setting it back is not a one-way door.
        config.preferLocalReaderTrustEvaluation = false
        XCTAssertEqual(config.readerTrustEvaluationMode, .remoteWithLocalFallback)
    }

    func testLegacyBooleanInTheInitializerStillSelectsLocalOnly() {
        let config = WalletConfig(
            backendUrl: "https://example.invalid",
            preferLocalReaderTrustEvaluation: true,
            preferLocalIssuerTrustEvaluation: true
        )
        XCTAssertEqual(config.readerTrustEvaluationMode, .localOnly)
        XCTAssertEqual(config.issuerTrustEvaluationMode, .localOnly)
    }

    /// The point of the precedence rule: a caller who asks for `.remoteOnly`
    /// must not be silently downgraded by a legacy `false` they never set.
    func testAnExplicitModeWinsOverTheLegacyBoolean() {
        let config = WalletConfig(
            backendUrl: "https://example.invalid",
            preferLocalReaderTrustEvaluation: true,
            readerTrustEvaluationMode: .remoteOnly
        )
        XCTAssertEqual(config.readerTrustEvaluationMode, .remoteOnly)
    }

    /// The awkward case: `.remoteWithLocalFallback` is also the value an unset
    /// mode resolves to, so comparing against the default cannot tell "the
    /// caller asked for the fallback mode" from "the caller said nothing". The
    /// init parameter is optional so that it can.
    func testExplicitlyChoosingTheFallbackModeIsNotDowngradedByTheLegacyBoolean() {
        let reader = WalletConfig(
            backendUrl: "https://example.invalid",
            preferLocalReaderTrustEvaluation: true,
            readerTrustEvaluationMode: .remoteWithLocalFallback
        )
        XCTAssertEqual(reader.readerTrustEvaluationMode, .remoteWithLocalFallback)

        let issuer = WalletConfig(
            backendUrl: "https://example.invalid",
            preferLocalIssuerTrustEvaluation: true,
            issuerTrustEvaluationMode: .remoteWithLocalFallback
        )
        XCTAssertEqual(issuer.issuerTrustEvaluationMode, .remoteWithLocalFallback)
    }

    // MARK: - Reachable-but-refused is not the same as unreachable

    func testOnlyTransportFailuresAndServerErrorsCountAsUnreachable() {
        let wallet = makeWallet(config())

        // `.network` wrapping a real transport error is an outage...
        XCTAssertTrue(wallet.isRemoteTrustEvaluationUnreachable(
            SirosError.network(message: "connection refused", underlying: URLError(.cannotConnectToHost))))
        // ...but on its own it is what this SDK throws for a protocol or
        // configuration failure ("Invalid response", "Invalid URL"), and a
        // misconfigured base URL must not open the weaker local roots.
        XCTAssertFalse(wallet.isRemoteTrustEvaluationUnreachable(
            SirosError.network(message: "Invalid URL: https://example.invalid/v1/evaluate")))
        XCTAssertFalse(wallet.isRemoteTrustEvaluationUnreachable(
            SirosError.network(message: "Invalid response")))
        XCTAssertTrue(wallet.isRemoteTrustEvaluationUnreachable(
            SirosError.backendApi(code: 503, message: "upstream down")))
        // Code 0 is not a status the backend answered with (Kotlin SDK #276).
        XCTAssertFalse(wallet.isRemoteTrustEvaluationUnreachable(
            SirosError.backendApi(code: 0, message: "no response")))
        // A plain 500 is the backend failing, not its upstream being absent.
        XCTAssertFalse(wallet.isRemoteTrustEvaluationUnreachable(
            SirosError.backendApi(code: 500, message: "boom", body: "")))

        // A 403 on /v1/evaluate means the backend was there and rejected the
        // CALLER, not the trust question. Treating it as unreachable would let
        // an expired token silently downgrade a security-relevant deny — which
        // is exactly what happened live at Geneva 2026.
        XCTAssertFalse(wallet.isRemoteTrustEvaluationUnreachable(
            SirosError.backendApi(code: 403, message: "forbidden")))
        XCTAssertFalse(wallet.isRemoteTrustEvaluationUnreachable(
            SirosError.backendApi(code: 404, message: "not found")))
        XCTAssertFalse(wallet.isRemoteTrustEvaluationUnreachable(
            SirosError.wallet(message: "Not connected")))
    }

    /// `BackendApiClient`'s default HTTP function calls URLSession directly,
    /// so a real outage surfaces as a bare `URLError`. Classifying that as
    /// "reachable" would make the default mode fail closed on exactly the
    /// condition the local fallback exists for.
    func testBareTransportErrorsFromURLSessionCountAsUnreachable() {
        let wallet = makeWallet(config())

        for code: URLError.Code in [.notConnectedToInternet, .timedOut, .cannotFindHost, .networkConnectionLost] {
            XCTAssertTrue(
                wallet.isRemoteTrustEvaluationUnreachable(URLError(code)),
                "URLError.\(code) should count as unreachable"
            )
        }

        // A cancelled task is not an outage. If it counted as one, cancelling
        // the remote evaluation would be a way to reach the weaker local roots.
        XCTAssertFalse(wallet.isRemoteTrustEvaluationUnreachable(URLError(.cancelled)))
    }

    // MARK: - Each mode routes where it says it does

    func testLocalOnlyNeverAsksTheBackend() async {
        let wallet = makeWallet(config(reader: .localOnly))
        var remoteWasCalled = false

        let result = await wallet.evaluateMdocTrust(
            mode: .localOnly,
            framework: "mdocrical",
            entityLabel: "reader",
            registryName: "RICAL",
            remote: {
                remoteWasCalled = true
                return TrustResult(trusted: true, framework: "mdocrical")
            },
            local: { TrustResult(trusted: true, framework: "local-rical-root") }
        )

        XCTAssertFalse(remoteWasCalled, "localOnly must not reach the network at all")
        XCTAssertEqual(result.framework, "local-rical-root")
    }

    func testRemoteWithLocalFallbackDropsToLocalOnlyWhenUnreachable() async {
        let wallet = makeWallet(config())

        let result = await wallet.evaluateMdocTrust(
            mode: .remoteWithLocalFallback,
            framework: "mdocrical",
            entityLabel: "reader",
            registryName: "RICAL",
            remote: { throw URLError(.notConnectedToInternet) },
            local: { TrustResult(trusted: true, framework: "local-rical-root") }
        )

        XCTAssertTrue(result.trusted)
        XCTAssertEqual(result.framework, "local-rical-root")
    }

    func testRemoteWithLocalFallbackFailsClosedWhenTheBackendRefusesTheCaller() async {
        let wallet = makeWallet(config())
        var localWasCalled = false

        let result = await wallet.evaluateMdocTrust(
            mode: .remoteWithLocalFallback,
            framework: "mdocrical",
            entityLabel: "reader",
            registryName: "RICAL",
            remote: { throw SirosError.backendApi(code: 403, message: "forbidden") },
            local: {
                localWasCalled = true
                return TrustResult(trusted: true, framework: "local-rical-root")
            }
        )

        XCTAssertFalse(localWasCalled, "a 403 must not open the weaker local path")
        XCTAssertFalse(result.trusted)
        XCTAssertEqual(result.framework, "mdocrical")
    }

    func testRemoteOnlyDoesNotFallBackEvenWhenUnreachable() async {
        let wallet = makeWallet(config(reader: .remoteOnly))
        var localWasCalled = false

        let result = await wallet.evaluateMdocTrust(
            mode: .remoteOnly,
            framework: "mdocrical",
            entityLabel: "reader",
            registryName: "RICAL",
            remote: { throw URLError(.notConnectedToInternet) },
            local: {
                localWasCalled = true
                return TrustResult(trusted: true, framework: "local-rical-root")
            }
        )

        XCTAssertFalse(localWasCalled, "remoteOnly must never reach the local path")
        XCTAssertFalse(result.trusted)
        // The reason has to say which of the two it was, or an operator cannot
        // tell a deliberate remote-only deny from a genuine untrusted reader.
        XCTAssertTrue(
            result.reason?.contains("remote-only") == true,
            "reason should name the configured mode, got: \(result.reason ?? "nil")"
        )
    }

    func testAnEmptyChainIsUntrustedInEveryMode() async {
        for mode in MdocTrustEvaluationMode.allCases {
            let wallet = makeWallet(config(reader: mode, issuer: mode))

            let reader = await wallet.evaluateReaderTrust([])
            XCTAssertFalse(reader.trusted, "\(mode): an empty readerAuth chain is not trusted")

            let issuer = await wallet.evaluateIssuerTrust([], docType: "org.iso.18013.5.1.mDL")
            XCTAssertFalse(issuer.trusted, "\(mode): an empty issuerAuth chain is not trusted")
        }
    }
}
