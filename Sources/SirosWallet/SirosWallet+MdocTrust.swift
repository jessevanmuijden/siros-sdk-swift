// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import SirosAuth
import SirosCredentials
import SirosKeystore
#if canImport(CryptoKit)
import CryptoKit
#else
// swift-crypto's `Crypto` module mirrors CryptoKit's API 1:1, including
// SHA256 - see Package.swift's SirosWallet dependencies.
import Crypto
#endif
#if canImport(Security)
import Security
#endif

/// Shared remote-AuthZEN-call and local-X.509-fallback implementation for
/// `SirosWallet.evaluateReaderTrust` (RICAL, action `mdoc-reader-auth`) and
/// `SirosWallet.evaluateIssuerTrust` (VICAL, action `mdoc-issuer-auth`) -
/// both mirror the same request/response shape, differing only in the
/// action name, the default `framework` label (used when go-trust's
/// response omits its own), an optional `context` block (VICAL's `doc_type`
/// enforcement hint), and the local-fallback framework/entity/registry
/// labels. Extracted into this file (rather than duplicating both trust
/// checks end to end) to avoid the Kotlin SDK's own first-pass mistake of
/// writing VICAL as a near-verbatim copy of RICAL and only refactoring
/// afterward under SonarCloud's duplication gate - see the Kotlin SDK's
/// `evaluateMdocTrustRemote`/`evaluateMdocTrustLocally` for the reference
/// this file ports.
extension SirosWallet {
    /// - Parameter subjectId: what the registry is asked about. Defaults to
    ///   the leaf certificate's SHA-256, which identifies the certificate
    ///   itself (RICAL/VICAL validate the chain and ignore it); a caller
    ///   whose registry resolves an entity by name passes that name instead.
    ///   `resource.id` always equals `subject.id`: go-trust requires it for
    ///   every full (non resolution-only) evaluation and answers 400 otherwise,
    ///   which go-wallet-backend's authzen proxy turns into a 502. The key
    ///   material stays in `resource.key`. (Kotlin SDK #276.)
    func evaluateMdocTrustRemote(
        x5chain: [[UInt8]],
        actionName: String,
        defaultFramework: String,
        subjectId: String? = nil,
        extraContext: [String: Any]? = nil
    ) async throws -> TrustResult {
        lock.lock(); let client = apiClient; lock.unlock()
        guard let client else { throw SirosError.wallet(message: "Not connected") }

        let certificateId = sha256Hex(x5chain[0])
        let resolvedSubjectId = subjectId ?? certificateId
        let x5c = x5chain.map { Data($0).base64EncodedString() }

        var evaluationRequest: [String: Any] = [
            "subject": ["type": "key", "id": resolvedSubjectId],
            "resource": ["type": "x5c", "id": resolvedSubjectId, "key": x5c],
            "action": ["name": actionName],
        ]
        if let extraContext {
            evaluationRequest["context"] = extraContext
        }

        let response = try await client.evaluateTrust(evaluationRequest)
        let decision = response["decision"] as? Bool ?? false
        let respContext = response["context"] as? [String: Any]

        return TrustResult(
            trusted: decision,
            framework: (respContext?["framework"] as? String) ?? defaultFramework,
            reason: (respContext?["reason"] as? String) ?? (respContext?["message"] as? String),
            entityName: respContext?["entity_name"] as? String,
            identifier: resolvedSubjectId
        )
    }

    /// Plain X.509 path validation against `rootCertificatesPem` - no
    /// RICAL/VICAL CBOR parsing, no `trustConstraints`/`docType`
    /// enforcement, since this path exists purely as an offline/unreachable-
    /// backend fallback for the stable, known-in-advance official root(s),
    /// not a full reimplementation of go-trust's `mdocrical`/`vical`
    /// registries.
    ///
    /// Distinguishes "nothing configured" from "configured but every entry
    /// failed to parse" - matching the Kotlin port's identical distinction
    /// (a single message here would otherwise mask misconfiguration, since
    /// unparsable PEM entries are silently dropped by the caller after
    /// logging the parse failure at the point it occurs).
    func evaluateMdocTrustLocally(
        x5chain: [[UInt8]],
        rootCertificatesPem: [String],
        frameworkLabel: String,
        entityLabel: String,
        registryName: String
    ) -> TrustResult {
        let subjectId = sha256Hex(x5chain[0])
        #if canImport(Security)
        let roots = mdocTrustRootCertificates(fromPem: rootCertificatesPem)
        guard !roots.isEmpty else {
            let reason = rootCertificatesPem.isEmpty
                ? "Local \(entityLabel) trust evaluation is unavailable: no \(registryName) root certificate configured"
                : "Local \(entityLabel) trust evaluation is unavailable: \(rootCertificatesPem.count) " +
                    "\(registryName) root certificate(s) configured but none could be parsed"
            return TrustResult(trusted: false, framework: frameworkLabel, reason: reason, identifier: subjectId)
        }
        guard let certificates = certificateChain(from: x5chain) else {
            return TrustResult(
                trusted: false,
                framework: frameworkLabel,
                reason: "Failed to parse the certificate chain",
                identifier: subjectId
            )
        }

        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()
        guard SecTrustCreateWithCertificates(certificates as CFTypeRef, policy, &trust) == errSecSuccess,
              let trust else {
            return TrustResult(
                trusted: false,
                framework: frameworkLabel,
                reason: "Failed to build a certificate trust object",
                identifier: subjectId
            )
        }
        SecTrustSetAnchorCertificates(trust, roots as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)

        var trustError: CFError?
        if SecTrustEvaluateWithError(trust, &trustError) {
            let leafName = (SecCertificateCopySubjectSummary(certificates[0]) as String?)
            return TrustResult(
                trusted: true,
                framework: frameworkLabel,
                reason: "Validated locally against a configured \(registryName) root certificate",
                entityName: leafName,
                identifier: subjectId
            )
        } else {
            return TrustResult(
                trusted: false,
                framework: frameworkLabel,
                reason: "Local \(registryName) root validation failed: \(trustError.map { String(describing: $0) } ?? "unknown error")",
                identifier: subjectId
            )
        }
        #else
        return TrustResult(
            trusted: false,
            framework: frameworkLabel,
            reason: "Local \(entityLabel) trust evaluation requires the Security framework (unsupported on this platform)",
            identifier: subjectId
        )
        #endif
    }

    #if canImport(Security)
    func certificateChain(from x5chain: [[UInt8]]) -> [SecCertificate]? {
        var certificates: [SecCertificate] = []
        for der in x5chain {
            guard let cert = SecCertificateCreateWithData(nil, Data(der) as CFData) else { return nil }
            certificates.append(cert)
        }
        return certificates
    }

    private func mdocTrustRootCertificates(fromPem pems: [String]) -> [SecCertificate] {
        pems.compactMap { pem in
            guard let der = Self.decodePem(pem) else { return nil }
            return SecCertificateCreateWithData(nil, der as CFData)
        }
    }

    /// Strips PEM armor (`-----BEGIN/END CERTIFICATE-----`) and base64-decodes
    /// the body - `SecCertificateCreateWithData` requires raw DER bytes.
    /// Trims whitespace/CR from each line before joining: PEM pasted from
    /// many sources (e.g. Windows-authored files, copy-paste) carries `\r`
    /// or trailing spaces, which `Data(base64Encoded:)` rejects outright.
    static func decodePem(_ pem: String) -> Data? {
        let lines = pem
            .split(whereSeparator: { $0 == "\n" || $0 == "\r\n" || $0 == "\r" })
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("-----") }
        return Data(base64Encoded: lines.joined())
    }
    #endif

    /// Whether `error` means the remote AuthZEN backend could not be reached
    /// (transport failure, backend outage) - the only condition under which
    /// `.remoteWithLocalFallback` may drop to the weaker local X.509 check.
    ///
    /// An explicit 4xx means the backend was reachable and rejected the
    /// CALLER - an authorization failure - not the trust QUESTION. Falling
    /// back on that would let anything that makes the backend return e.g.
    /// 403 silently downgrade a security-relevant deny. That is not
    /// hypothetical: it was confirmed live at Geneva 2026, where a 403 on
    /// `/v1/evaluate` was treated exactly the same as an unreachable
    /// backend. Ported from the Kotlin SDK's
    /// `isRemoteTrustEvaluationUnreachable`, which this SDK was missing.
    func isRemoteTrustEvaluationUnreachable(_ error: Error) -> Bool {
        switch error {
        case SirosError.network(_, let underlying):
            // `.network` is not a transport error in this SDK. Every site
            // that throws it does so for a protocol or configuration failure -
            // "Invalid response" for a non-HTTP response, "Invalid URL" for a
            // misconfigured base URL - and a real transport failure never
            // reaches it at all, because the HTTP boundary lets `URLError`
            // escape unwrapped (see below). Only an instance that actually
            // wraps something counts, which keeps the door open for a future
            // caller that does wrap a transport error, and keeps a
            // misconfigured URL from opening the weaker local roots.
            //
            // The Kotlin SDK's `NetworkException` is genuinely transport-only
            // - it is thrown from exactly one place, always around a real
            // transport exception - so this is what parity with it means, not
            // a blanket match on the case.
            return underlying != nil
        case SirosError.backendApi(let code, _, let body):
            // 502/503/504 are what a gateway answers when it cannot reach its
            // upstream, but go-wallet-backend's authzen proxy ALSO answers 502
            // when the PDP was reached and refused the request as invalid
            // (go-trust 400). So these count as unreachable only when the
            // response carries no upstream error body: empty, `{}`, or a
            // non-JSON gateway page. A JSON object body is the PDP speaking -
            // a refusal, not an outage. Any other status (500 included) and a
            // code of 0 are not "unreachable". (Kotlin SDK #276.)
            return [502, 503, 504].contains(code) && !carriesUpstreamErrorBody(body)
        default:
            // `BackendApiClient`'s default HTTP function calls
            // `URLSession.shared.data(for:)` directly, so a DNS failure, a
            // timeout or a refused connection arrives here as a bare
            // `URLError`, never wrapped in `SirosError.network`. Without this
            // case a real network outage - the condition the local fallback
            // exists for - would fail closed instead of falling back.
            //
            // Cancellation is excluded: `URLSession` reports a cancelled task
            // as `URLError.cancelled`, and a cancelled evaluation is not an
            // unreachable backend. Treating it as one would let cancelling the
            // remote call be a way to reach the weaker local roots.
            if let urlError = error as? URLError {
                return urlError.code != .cancelled
            }
            return false
        }
    }

    /// Whether `body` is a non-empty JSON object, i.e. an error the PDP itself
    /// produced rather than a gateway's own page.
    private func carriesUpstreamErrorBody(_ body: String?) -> Bool {
        guard let body, !body.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let data = body.data(using: .utf8),
              let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        return !parsed.isEmpty
    }

    /// The shared mode/fallback decision behind `evaluateReaderTrust` and
    /// `evaluateIssuerTrust`, so the two cannot drift apart on a security
    /// decision. `remote` and `local` are the registry-specific halves.
    func evaluateMdocTrust(
        mode: MdocTrustEvaluationMode,
        framework: String,
        entityLabel: String,
        registryName: String,
        remote: () async throws -> TrustResult,
        local: () -> TrustResult
    ) async -> TrustResult {
        if mode == .localOnly {
            return local()
        }
        do {
            return try await remote()
        } catch {
            guard isRemoteTrustEvaluationUnreachable(error) else {
                return TrustResult(
                    trusted: false,
                    framework: framework,
                    reason: "Remote \(entityLabel) trust evaluation failed: \(error.localizedDescription)"
                )
            }
            if mode == .remoteOnly {
                return TrustResult(
                    trusted: false,
                    framework: framework,
                    reason: "Remote \(entityLabel) trust evaluation is unreachable and this wallet is configured " +
                        "for remote-only evaluation, so local \(registryName) root validation was not attempted: " +
                        "\(error.localizedDescription)"
                )
            }
            return local()
        }
    }

    func sha256Hex(_ bytes: [UInt8]) -> String {
        SHA256.hash(data: Data(bytes)).map { String(format: "%02x", $0) }.joined()
    }
}
