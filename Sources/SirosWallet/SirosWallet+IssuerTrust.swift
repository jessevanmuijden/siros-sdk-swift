// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
import SirosKeystore
@preconcurrency import SwiftCBOR
#if canImport(Security)
import Security
#endif

extension SirosWallet {
    /// Evaluates an mdoc credential's issuer authenticated identity for trust
    /// (ISO/IEC 18013-5 Annex C, `issuerAuth`) - the wallet-side counterpart
    /// to `evaluateReaderTrust`, called defensively when a newly-issued
    /// `mso_mdoc` credential is about to be stored, before it's trusted.
    /// Mirrors `evaluateReaderTrust`'s exact remote-then-local-fallback
    /// shape with a `"mdoc-issuer-auth"` action name; go-trust answers it
    /// from whichever issuer registry the deployment has - `mdociaca` (keyed
    /// on the issuer URL the DS certificate names, see
    /// `evaluateIssuerTrustRemote`) or `vical`. Only ever called with an x5chain whose `issuerAuth`
    /// COSE_Sign1 signature has ALREADY verified locally (see
    /// `MdocCose.verify1`) - this method is purely the trust decision.
    /// Ported from the Kotlin SDK's `SirosWallet.evaluateIssuerTrust`.
    ///
    /// Which path runs is `WalletConfig.issuerTrustEvaluationMode`, with the
    /// same three choices and the same refused-versus-unreachable rule as
    /// `evaluateReaderTrust`. The default, `.remoteWithLocalFallback`,
    /// prefers the remote AuthZEN call: it is the only path that honors
    /// VICAL's dynamic updates.
    ///
    /// - Parameter x5chain: the issuer's DER-encoded certificate chain, leaf first.
    /// - Parameter docType: the credential's mdoc doctype (e.g.
    ///   `"org.iso.18013.5.1.mDL"`), used for VICAL's per-certificate
    ///   docType enforcement - only enforced remotely (go-trust's `vical`
    ///   registry skips, not denies, if omitted); the local fallback never
    ///   enforces it, same as RICAL's fallback skipping `trustConstraints`.
    public func evaluateIssuerTrust(_ x5chain: [[UInt8]], docType: String?) async -> TrustResult {
        guard !x5chain.isEmpty else {
            return TrustResult(trusted: false, reason: "issuerAuth has no certificate chain")
        }
        return await evaluateMdocTrust(
            mode: config.issuerTrustEvaluationMode,
            framework: "vical",
            entityLabel: "issuer",
            registryName: "VICAL",
            remote: { try await self.evaluateIssuerTrustRemote(x5chain, docType: docType) },
            local: { self.evaluateIssuerTrustLocally(x5chain) }
        )
    }

    /// The subject is the issuer's URL as its DS certificate names it (see
    /// `MdocIssuerIdentity`), not the certificate's hash: go-trust's
    /// `mdociaca` registry - the one that validates an mdoc chain against
    /// the issuer's published IACAs - keys its allowlist and its IACA fetch
    /// on that URL, and it is the identity the verifier side derives for the
    /// same certificate, so both ends ask about the same subject. A `vical`
    /// registry ignores the subject and validates the chain, so it is
    /// unaffected. Falls back to the hash only for a certificate that names
    /// no URL at all, which no registry can resolve either way.
    private func evaluateIssuerTrustRemote(_ x5chain: [[UInt8]], docType: String?) async throws -> TrustResult {
        try await evaluateMdocTrustRemote(
            x5chain: x5chain,
            actionName: "mdoc-issuer-auth",
            defaultFramework: "vical",
            subjectId: MdocIssuerIdentity.fromDer(x5chain[0]),
            extraContext: docType.map { ["doc_type": $0] }
        )
    }

    /// Plain X.509 path validation against
    /// `WalletConfig.issuerTrustRootCertificatesPem` - no VICAL CBOR
    /// parsing, no per-certificate `docType` enforcement, since this path
    /// exists purely as an offline/unreachable-backend fallback for the
    /// stable, known-in-advance official root(s), not a full
    /// reimplementation of go-trust's `vical` registry.
    private func evaluateIssuerTrustLocally(_ x5chain: [[UInt8]]) -> TrustResult {
        evaluateMdocTrustLocally(
            x5chain: x5chain,
            rootCertificatesPem: config.issuerTrustRootCertificatesPem,
            frameworkLabel: "local-vical-root",
            entityLabel: "issuer",
            registryName: "VICAL"
        )
    }

    /// Verifies an mdoc credential's `issuerAuth` COSE_Sign1 (ISO 18013-5
    /// Annex C) against its own embedded x5chain, then hands that chain to
    /// `evaluateIssuerTrust` for the actual trust decision - the issuance-
    /// time counterpart to `MdocProximitySession`'s presentation-time
    /// readerAuth check. Returns nil (skip, don't block storage) if
    /// `issuerAuth` has no x5chain or its signature doesn't verify,
    /// mirroring that same "no badge, not untrusted" convention for a check
    /// that can't even be attempted.
    ///
    /// - Parameter issuerAuth: the credential's `issuerAuth` COSE_Sign1 4-element array.
    /// - Parameter docType: the credential's mdoc doctype, for VICAL docType enforcement.
    func verifyAndEvaluateIssuerTrust(_ issuerAuth: CBOR, docType: String) async -> TrustResult? {
        #if canImport(Security)
        let chain = MdocCose.extractX5Chain(issuerAuth)
        guard !chain.isEmpty else { return nil }
        guard let issuerCert = SecCertificateCreateWithData(nil, Data(chain[0]) as CFData),
              let secKey = SecCertificateCopyKey(issuerCert) else { return nil }
        var error: Unmanaged<CFError>?
        guard let publicKeyX963 = SecKeyCopyExternalRepresentation(secKey, &error) as Data? else { return nil }

        guard case .array(let arr) = issuerAuth, arr.count == 4, case .byteString(let msoBytes) = arr[2] else { return nil }
        guard MdocCose.verify1(issuerAuth, payload: msoBytes, publicKeyX963: [UInt8](publicKeyX963)) else { return nil }

        // The docType the trust service is asked about must be the SIGNED one: the
        // envelope's is unsigned. A mismatch, or no way to compare, is untrusted.
        if let reason = Self.issuerAuthDocTypeRefusal(msoPayload: msoBytes, envelopeDocType: docType) {
            return TrustResult(trusted: false, reason: reason)
        }

        return await evaluateIssuerTrust(chain, docType: docType)
        #else
        return nil
        #endif
    }

    /// The `docType` inside the signed MobileSecurityObject: the `issuerAuth`
    /// payload is `#6.24(bstr(MSO))` (a bare MSO map is accepted too). Nil if it
    /// cannot be read.
    static func signedDocType(msoPayload: [UInt8]) -> String? {
        guard let top = try? CBOR.decode(msoPayload) else { return nil }
        var mso = top
        if case .tagged(let tag, let inner) = top, tag == .encodedCBORDataItem {
            guard case .byteString(let bytes) = inner, let decoded = try? CBOR.decode(bytes) else { return nil }
            mso = decoded
        }
        guard case .map(let map) = mso, case .utf8String(let docType)? = map["docType"] else { return nil }
        return docType
    }

    /// Fail closed: the unsigned envelope's docType must equal the signed one;
    /// "cannot compare" refuses. Nil means they agree.
    static func issuerAuthDocTypeRefusal(msoPayload: [UInt8], envelopeDocType: String) -> String? {
        guard let signed = signedDocType(msoPayload: msoPayload) else {
            return "the signed MSO has no readable docType to compare the credential's docType with"
        }
        return signed == envelopeDocType
            ? nil
            : "the credential's docType '\(envelopeDocType)' differs from the signed MSO's '\(signed)'"
    }
}
