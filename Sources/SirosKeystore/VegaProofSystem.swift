// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// The native `zk-cred-vega` XCFramework only ships iOS slices (see
// Package.swift's `zk_cred_vegaFFI` binary target, and
// `Generated/zk_cred_vega.swift`'s own `#if os(iOS)` gating) - this entire
// concrete implementation is correspondingly iOS-only, same as
// `LongfellowZkProofSystem`.
#if os(iOS)

import Foundation
import Security
import BigInt
import SwiftCBOR
import SirosCredentials

/// `ZkProofSystem` implementation wrapping the `zk-cred-vega` native crate -
/// Swift port of the Kotlin SDK's `VegaProofSystem`, matching its shape
/// closely (see that file's own doc comment for the design/provenance
/// history this carries over unchanged).
///
/// **Do not present this to a real relying party yet.** `zk-cred-vega` is
/// public and tagged, and its own expert security review is running in
/// parallel with SDK-side testing rather than gating it - but that review
/// hasn't landed, so nothing here should be trusted as a real trust anchor
/// yet. This class is for early-testing end-to-end use (own prover verified
/// by own verifier, plus real wallet <-> verifier interop against
/// `sirosfoundation/vc`), same caveat Longfellow shipped under before its
/// own multipaz interop testing. The `go-zk-circuits` catalog's
/// `vega-mc-p256-v1-{prover,verifier}-key-r12` entries are published for
/// early testing (`zkCircuitClient` can fetch them directly), carrying the
/// same "PUBLISHED FOR EARLY TESTING ONLY" notice.
///
/// `buildWitness` is real (ECDSA witness from `issuerAuth`'s x5chain +
/// signature, MSO body from `issuerAuth`'s payload, fixed 4-slot claim
/// selection) - see its own doc comment for the slot-selection policy. The
/// `prepProve`/`prove` FFI wiring mirrors `LongfellowZkProofSystem`'s own
/// shape, with two deliberate differences: pseudonym handling (Vega has no
/// pseudonym-derivation concept at all, confirmed in the Kotlin port's own
/// design research, so that aspect instead matches `BbsProofSystem`'s
/// constant `.notSupportedBySystem`) and state reuse - unlike Longfellow,
/// `generateProof` does NOT fold-and-reuse `priorState`; see its own doc
/// comment for why.
public actor VegaProofSystem: ZkProofSystem {

    /// The circuit's fixed claim-slot count (`MAX_CLAIMS_V1` in the Rust
    /// crate) - Vega's v1 circuit is compiled for exactly this many claim
    /// slots, unlike Longfellow's own per-attribute-count circuit variants.
    /// A request for more claims than this can't be satisfied by this
    /// system at all.
    public static let maxClaimsV1 = 4

    /// This system's `ZkSystemSpec.system` value - aliases the cross-platform
    /// `vegaZkSystemId` (this type's own iOS-only `#if os(iOS)` gating means
    /// non-iOS code, e.g. `SirosWallet+DCAPI.swift`'s Vega-only
    /// `claimSlotDigestIds` wire field, cannot reference THIS type to get
    /// at it, so that constant - not this one - is the actual single
    /// source of truth).
    public static let systemIdValue = vegaZkSystemId

    /// COSE algorithm identifier for ES256 (RFC 8152 §8.1) - the only alg
    /// `buildEcdsaWitness` accepts.
    private static let coseAlgES256: Int64 = -7

    /// COSE_Key EC2 type-specific parameter labels (RFC 8152 §13.1.1).
    /// CBOR negative integers encode as `-1 - n`, so label -2 is
    /// `.negativeInt(1)` and -3 is `.negativeInt(2)`.
    private static let coseKeyLabelX: CBOR = .negativeInt(1)
    private static let coseKeyLabelY: CBOR = .negativeInt(2)

    /// P-256 field-element/coordinate width in bytes.
    private static let p256CoordinateBytes = 32

    /// P-256 (secp256r1) curve order `n`, per SEC 2 §2.4.2.
    private static let p256Order = BigUInt("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", radix: 16)!

    nonisolated public let systemId = VegaProofSystem.systemIdValue

    /// The circuit itself is docType-agnostic (buildWitness just walks
    /// whatever single namespace the mdoc has, with no docType-specific
    /// logic) - the real constraint is `maxClaimsV1`'s exact-4-elements
    /// requirement, not docType. mdoc-only, same as Longfellow - Vega's
    /// broader circuit ambitions (e.g. SD-JWT VC) are a planned future
    /// circuit, not this one.
    nonisolated public let supportedCredentialTypes: Set<CredentialTypeRef> = [
        CredentialTypeRef(format: .msoMdoc, typeId: "org.iso.18013.5.1.mDL"),
        CredentialTypeRef(format: .msoMdoc, typeId: "eu.europa.ec.eudi.pid.1"),
    ]

    private let zkCircuitClient: ZkCircuitClient

    /// Where the loaded prover key lives - shared with any other proof
    /// system (e.g. `LongfellowZkProofSystem`) a host constructs, so the
    /// process holds one resident prover at a time. See `ZkProverResidency`'s
    /// own doc comment for why this exists.
    private let residency: ZkProverResidency

    public init(zkCircuitClient: ZkCircuitClient, residency: ZkProverResidency = ZkProverResidency()) {
        self.zkCircuitClient = zkCircuitClient
        self.residency = residency
    }

    /// Residency key: circuit/spec id - a single prover key handle serves
    /// every presentation with that circuit.
    private func residencyKey(spec: ZkSystemSpec) -> String { "\(systemId):\(spec.id)" }

    /// Matches any requested spec declaring `system == systemId` for a proof
    /// over AT MOST `maxClaimsV1` claims - unlike Longfellow's exact-match
    /// requirement (a circuit compiled per attribute count), Vega's circuit
    /// is fixed-shape at `maxClaimsV1` slots regardless of how many claims a
    /// given presentation actually discloses (unused slots are filled from
    /// the credential's own other elements, not left blank - see
    /// `buildWitness`'s doc comment).
    nonisolated public func matchingSpec(_ requestedSpecs: [ZkSystemSpec], numAttributes: Int) -> ZkSystemSpec? {
        guard numAttributes <= Self.maxClaimsV1 else { return nil }
        return requestedSpecs.first { $0.system == systemId }
    }

    public func generateProof(
        spec: ZkSystemSpec,
        document: CredentialDocument,
        sessionTranscript: [UInt8],
        requestedClaims: [String],
        verifierIdentity: VerifierIdentity?,
        signer: @escaping ZkWitnessSigner,
        priorState: [UInt8]?
    ) async throws -> ZkProofResult {
        // Vega has no pseudonym-derivation concept at all (see this type's
        // own doc comment). `generateProof` always reports
        // `.notSupportedBySystem` below regardless, but a caller that also
        // listed `zkPseudonymClaim` in `requestedClaims` has asked this
        // system to disclose something it structurally cannot - silently
        // succeeding would hand the verifier a presentation missing a claim
        // it explicitly requested (the caller only ever inspects
        // `result.pseudonym`, never `pseudonymOutcome`, when assembling the
        // disclosed-claims wire list). Reject up front instead, mirroring
        // `LongfellowZkProofSystem`'s identical "can't honor this request,
        // don't pretend to" guard.
        guard !requestedClaims.contains(zkPseudonymClaim) else {
            throw MdocError.malformed(
                "\(systemId) cannot prove '\(zkPseudonymClaim)' - this system has no pseudonym-derivation support"
            )
        }

        guard case let .mdoc(credentialBytes) = document else {
            throw MdocError.malformed("\(systemId) proves over mdoc only, got \(document.formatName)")
        }
        let mdoc = try MdocCbor.parseStoredCredential(credentialBytes)

        return try await residency.use(
            key: residencyKey(spec: spec),
            load: { try await self.loadProverKey(spec: spec) }
        ) { proverKey in
            let (claims, ecdsaWitness, msoBody) = try Self.buildWitness(document: mdoc, requestedClaims: requestedClaims)

            // prepProve/prove are synchronous, CPU-bound native calls (~5s
            // for this circuit) - this actor's own isolation already keeps
            // them off the caller's isolation domain (see
            // LongfellowZkProofSystem's matching doc comment on why an
            // `actor`, not a plain class, is what actually buys this).
            //
            // `priorState` is deliberately NEVER honored here, and no
            // reusable `nextState` is ever handed back (Copilot review,
            // PR #182): in zk-cred-vega v0.0.6, feeding a previous call's
            // state back into `prove` carries the SAME digest-blinding
            // nonce forward (the crate's own docs warn about exactly this),
            // so two presentations that reused state would disclose
            // identical blinded digests and become correlatable to each
            // other - defeating per-presentation unlinkability even when
            // they disclose different claim subsets. `priorState` stays in
            // this method's signature only for `ZkProofSystem` protocol
            // parity with `LongfellowZkProofSystem`'s own state-threading;
            // every Vega proof prepares fresh until the native API can
            // refresh this nonce safely on reuse.
            let state = try prepProve(pk: proverKey, claims: claims, ecdsaWitness: ecdsaWitness, msoBody: msoBody)
            let result = try prove(pk: proverKey, claims: claims, ecdsaWitness: ecdsaWitness, msoBody: msoBody, priorState: state)

            return ZkProofResult(
                proofBytes: [UInt8](result.proofBytes),
                // Vega has no pseudonym-derivation concept at all (confirmed
                // in the Kotlin port's own design research) - always report
                // this, regardless of whether verifierIdentity was
                // supplied, rather than silently dropping a pseudonym
                // request.
                pseudonymOutcome: .notSupportedBySystem
            )
        }
    }

    /// Builds this presentation's witness data from a real, stored mdoc
    /// credential.
    ///
    /// **ECDSA witness**: `qx`/`qy` (the issuer's public key) come from the
    /// leaf certificate in `issuerAuth`'s x5chain (COSE header label 33),
    /// reusing `MdocCose.extractX5Chain` rather than reinventing it. `r`/`s`
    /// are `issuerAuth`'s own COSE_Sign1 signature bytes (first/second
    /// 32-byte half - this type only supports ES256/P-256, matching
    /// `supportedCredentialTypes`' single circuit). `sInv` is a real modular
    /// inverse against the P-256 curve order (via `BigInt` - get this wrong
    /// and proofs fail to verify with no clear error, same class of mistake
    /// `zk-cred-vega`'s own `ecdsa.rs` module doc warns about for the
    /// *circuit* side of this same computation).
    ///
    /// **MSO body witness**: `MdocCbor.decodeMso(issuerAuth:)` gives
    /// `deviceKeyInfo.deviceKey.{x,y}` and
    /// `validityInfo.{signed,validFrom,validUntil}`, each reformatted to the
    /// exact 20-byte ASCII RFC 3339 form the native crate requires - an
    /// MSO's own timestamp string isn't guaranteed to already be exactly 20
    /// bytes.
    ///
    /// **Fixed-slot-count claim selection** (same resolution the Kotlin port
    /// settled on): the circuit has EXACTLY `maxClaimsV1` claim slots, each
    /// bound to a genuine credential element - no blank/padding slots. This
    /// requires the credential's single disclosed namespace to have EXACTLY
    /// `maxClaimsV1` elements (a real v1 scope limit, not a bug - Vega's
    /// circuit is sized for small, fixed-shape credentials like the real
    /// 4-claim mDL test vector, not arbitrarily large ones). Slot assignment
    /// is the namespace's own document order (stable per credential,
    /// independent of which claims a given presentation discloses) -
    /// `disclose` only varies per slot based on membership in
    /// `requestedClaims`, which MUST already be a subset of the namespace's
    /// own element identifiers (see the `requested`/`unknown` guard below -
    /// an identifier the credential does not carry cannot be disclosed, so
    /// this rejects the request rather than silently proving over it with
    /// every slot's `disclose` left `false`). This per-slot stability is
    /// what would make `ZkProofResult.nextState` reuse sound across repeat
    /// presentations of a credential, if `generateProof` reused it - which
    /// it deliberately does not; see `generateProof`'s own doc comment for
    /// why.
    // Not `private`: `VegaProofSystemTests` (`@testable import`) exercises
    // the docType/namespace/digestID guards below directly against
    // hand-built `DocumentMdoc` fixtures, without needing a real signed
    // credential or the native prover - `private` (file-scoped) would put
    // this out of reach from a different file even with `@testable`.
    static func buildWitness(
        document: DocumentMdoc,
        requestedClaims: [String]
    ) throws -> ([VegaFfiClaim], FfiEcdsaWitness, FfiMsoBodyWitness) {
        let issuerAuth = document.issuerSigned.issuerAuth
        guard let namespace = zkMdocNamespaceByDocType[document.docType] else {
            throw MdocError.malformed("VegaProofSystem: mdoc credential has unsupported docType '\(document.docType)'")
        }
        guard let namespaceItems = document.issuerSigned.nameSpaces[namespace] else {
            throw MdocError.malformed("VegaProofSystem: mdoc credential '\(document.docType)' has no disclosed '\(namespace)' namespace")
        }
        guard namespaceItems.count == maxClaimsV1 else {
            throw MdocError.malformed(
                "VegaProofSystem requires the credential's namespace to have exactly \(maxClaimsV1) " +
                "elements (Vega v1's circuit is fixed-shape, no padding slots) - found \(namespaceItems.count)"
            )
        }

        let requested = Set(requestedClaims)
        // A requested identifier the credential's own namespace does not
        // carry can never be disclosed - silently proceeding would prove
        // successfully with every slot's `disclose` left `false` (none of
        // them match), handing the verifier a presentation quietly missing
        // a claim it explicitly asked for, the same presentation-
        // correctness failure `generateProof`'s pseudonym guard above
        // exists to prevent (Copilot review, PR #182).
        let available = Set(namespaceItems.map { $0.item.elementIdentifier })
        let unknown = requested.subtracting(available)
        guard unknown.isEmpty else {
            throw MdocError.malformed(
                "VegaProofSystem: requested claim(s) \(unknown.sorted()) are not present in credential namespace '\(namespace)' " +
                "(available: \(available.sorted()))"
            )
        }
        let claims: [VegaFfiClaim] = try namespaceItems.map { entry in
            // `digestID` is a CBOR unsigned int, i.e. a `UInt64` in
            // `IssuerSignedItem` - an issuer-controlled value with no spec
            // ceiling. The native FFI contract (`zk_cred_vega.swift`'s
            // generated doc comment on `FfiClaim.digestId`) requires digest
            // IDs below `2^31` - ISO 18013-5's own digest IDs are a
            // CBOR-encodable non-negative int with no upper bound in the
            // spec text, but the native crate asserts the `< 2^31` bound
            // while reconstructing the MSO and panics rather than returning
            // an error if it's violated, so this has to reject the same
            // range Swift-side rather than only guarding against overflowing
            // `UInt32` outright (Copilot review, PR #182).
            guard let digestId = UInt32(exactly: entry.item.digestId), digestId < (1 << 31) else {
                throw MdocError.malformed(
                    "VegaProofSystem: digestID \(entry.item.digestId) for '\(entry.item.elementIdentifier)' " +
                    "is not in the native crate's supported range (0..<2^31)"
                )
            }
            return VegaFfiClaim(
                issuerSignedItemBytes: Data(entry.original.encode()),
                disclose: requested.contains(entry.item.elementIdentifier),
                digestId: digestId
            )
        }

        let ecdsaWitness = try buildEcdsaWitness(issuerAuth: issuerAuth)
        let msoBody = try buildMsoBodyWitness(issuerAuth: issuerAuth)

        return (claims, ecdsaWitness, msoBody)
    }

    /// See `buildWitness`'s "ECDSA witness" section for the reasoning here.
    // Not `private`: `VegaProofSystemTests` exercises the COSE alg
    // overflow guard directly against a hand-crafted `issuerAuth` CBOR
    // array - see `buildWitness`'s matching access-level comment above.
    static func buildEcdsaWitness(issuerAuth: CBOR) throws -> FfiEcdsaWitness {
        guard case .array(let coseSign1) = issuerAuth, coseSign1.count == 4 else {
            throw MdocError.malformed("VegaProofSystem: issuerAuth is not a COSE_Sign1 array")
        }
        guard case .byteString(let protectedBytes) = coseSign1[0],
              let protectedHeaders = try? CBOR.decode(protectedBytes) else {
            throw MdocError.malformed("VegaProofSystem: issuerAuth protected header is not decodable")
        }
        // A malformed protected header can encode a CBOR integer above
        // `Int64.max` (e.g. close to `UInt64.max`) - `Int64(v)` traps on
        // that, crashing proof generation over untrusted credential data
        // instead of surfacing the intended unsupported-algorithm error.
        // `Int64(exactly:)` returns `nil` instead of trapping; the
        // subsequent `alg == coseAlgES256` comparison then correctly falls
        // through to the "unsupported alg" error for any out-of-range value.
        let alg: Int64?
        switch protectedHeaders[.unsignedInt(1)] {
        case .unsignedInt(let v): alg = Int64(exactly: v)
        case .negativeInt(let v): alg = Int64(exactly: v).map { -1 - $0 }
        default: alg = nil
        }
        guard alg == coseAlgES256 else {
            throw MdocError.malformed("VegaProofSystem only supports ES256/P-256 issuerAuth signatures, got COSE alg \(String(describing: alg))")
        }

        guard let leafCertBytes = MdocCose.extractX5Chain(issuerAuth).first else {
            throw MdocError.malformed("VegaProofSystem: issuerAuth has no x5chain to extract the issuer's public key from")
        }
        guard let cert = SecCertificateCreateWithData(nil, Data(leafCertBytes) as CFData),
              let secKey = SecCertificateCopyKey(cert) else {
            throw MdocError.malformed("VegaProofSystem: issuerAuth's leaf certificate is not parseable")
        }
        var exportError: Unmanaged<CFError>?
        guard let publicKeyX963 = SecKeyCopyExternalRepresentation(secKey, &exportError) as Data?,
              publicKeyX963.count == 1 + p256CoordinateBytes * 2, publicKeyX963.first == 0x04 else {
            throw MdocError.malformed("VegaProofSystem: issuerAuth's leaf certificate is not an EC public key")
        }
        let qx = publicKeyX963.subdata(in: 1..<(1 + p256CoordinateBytes))
        let qy = publicKeyX963.subdata(in: (1 + p256CoordinateBytes)..<(1 + 2 * p256CoordinateBytes))

        guard case .byteString(let signature) = coseSign1[3], signature.count == p256CoordinateBytes * 2 else {
            throw MdocError.malformed("VegaProofSystem: expected a \(p256CoordinateBytes * 2)-byte raw ECDSA signature")
        }
        let r = BigUInt(Data(signature[0..<p256CoordinateBytes]))
        let s = BigUInt(Data(signature[p256CoordinateBytes...]))
        guard let sInv = s.inverse(p256Order) else {
            throw MdocError.malformed("VegaProofSystem: issuerAuth's signature 's' has no modular inverse mod the P-256 order")
        }

        return FfiEcdsaWitness(
            qx: qx,
            qy: qy,
            r: pad32(r),
            s: pad32(s),
            sInv: pad32(sInv)
        )
    }

    /// See `buildWitness`'s "MSO body witness" section for the reasoning here.
    private static func buildMsoBodyWitness(issuerAuth: CBOR) throws -> FfiMsoBodyWitness {
        let mso = try MdocCbor.decodeMso(issuerAuth: issuerAuth)
        let deviceKey = mso["deviceKeyInfo"]?["deviceKey"]
        guard case .byteString(let deviceX)? = deviceKey?[coseKeyLabelX],
              case .byteString(let deviceY)? = deviceKey?[coseKeyLabelY] else {
            throw MdocError.malformed("VegaProofSystem: MSO deviceKeyInfo.deviceKey missing x/y")
        }

        // Reformats whatever valid ISO 8601 variant the MSO carries (with
        // or without fractional seconds) into the exact 20-byte
        // "yyyy-MM-ddTHH:mm:ssZ" form the native crate requires - mirrors
        // the Kotlin port's `Instant.parse(iso).truncatedTo(SECONDS).toString()`.
        // A fresh `ISO8601DateFormatter()`'s default `formatOptions` is
        // already exactly `[.withInternetDateTime]` (confirmed: this is
        // the same formatter `LongfellowZkProofSystem` already uses,
        // unconfigured, for its own 20-byte `time` value) - no fractional
        // seconds, so it's only safe to use for OUTPUT once the fractional
        // part has already been truncated away.
        func timestamp(_ field: String) throws -> Data {
            guard let raw = mso["validityInfo"]?[.utf8String(field)] else {
                throw MdocError.malformed("VegaProofSystem: MSO validityInfo missing '\(field)'")
            }
            let iso: String
            switch raw {
            case .tagged(_, .utf8String(let s)): iso = s
            case .utf8String(let s): iso = s
            default:
                throw MdocError.malformed("VegaProofSystem: MSO validityInfo.\(field) is not a date-time string")
            }
            let fractionalFormatter = ISO8601DateFormatter()
            fractionalFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            guard let date = fractionalFormatter.date(from: iso) ?? ISO8601DateFormatter().date(from: iso) else {
                throw MdocError.malformed("VegaProofSystem: MSO validityInfo.\(field) '\(iso)' is not a valid date-time")
            }
            let truncated = Date(timeIntervalSince1970: date.timeIntervalSince1970.rounded(.down))
            return Data(ISO8601DateFormatter().string(from: truncated).utf8)
        }

        return FfiMsoBodyWitness(
            deviceX: Data(deviceX),
            deviceY: Data(deviceY),
            signedTs: try timestamp("signed"),
            validFromTs: try timestamp("validFrom"),
            validUntilTs: try timestamp("validUntil")
        )
    }

    /// Unsigned big-endian, left-padded/truncated to exactly `p256CoordinateBytes`.
    private static func pad32(_ value: BigUInt) -> Data {
        var bytes = [UInt8](value.serialize())
        precondition(bytes.count <= p256CoordinateBytes, "value does not fit in \(p256CoordinateBytes) bytes")
        if bytes.count < p256CoordinateBytes {
            bytes = [UInt8](repeating: 0, count: p256CoordinateBytes - bytes.count) + bytes
        }
        return Data(bytes)
    }

    private func loadProverKey(spec: ZkSystemSpec) async throws -> VegaProverKey {
        let descriptor = try await zkCircuitClient.fetchCircuit(id: spec.id)
        try Self.validateCircuitParams(descriptor)
        let compressedBytes = try await zkCircuitClient.downloadArtifact(descriptor)
        let keyBytes = try decompressZkCircuitArtifact(compressedBytes, descriptor: descriptor)
        return try deserializeProverKey(bytes: keyBytes)
    }

    /// Checks the catalog's own published `params` for this circuit against
    /// what this type hardcodes (P-256, exactly `maxClaimsV1` claim slots)
    /// *before* spending a real download+decompress (a 100+MB artifact) on
    /// a circuit this type can't actually use - failing fast, locally, with
    /// a clear diagnostic naming the mismatch, instead of discovering a
    /// circuit-shape change only via an opaque native prove()/verify()
    /// failure much later. Ports Kotlin's `VegaProofSystem.validateCircuitParams`
    /// (siros-sdk-kotlin#244) - see that PR for why `maxClaimBytes` isn't
    /// checked here either (a per-claim-byte-count mismatch is the issuer's
    /// claim content at fault, not a circuit-shape assumption this type
    /// makes, and already surfaces with its own clear native-layer error)
    /// and why `saltBytes` can't be validated yet (the catalog doesn't
    /// publish it - sirosfoundation/go-zk-circuits#29).
    static func validateCircuitParams(_ descriptor: ZkCircuitDescriptor) throws {
        let curve = descriptor.params["curve"]?.stringValue
        guard curve == "P-256" else {
            throw MdocError.malformed(
                "Vega circuit '\(descriptor.id)' declares curve '\(curve ?? "nil")', but \(systemIdValue) only supports P-256"
            )
        }
        let numClaims = descriptor.params["numClaims"]?.stringValue.flatMap(Int.init)
        guard numClaims == maxClaimsV1 else {
            throw MdocError.malformed(
                "Vega circuit '\(descriptor.id)' declares numClaims=\(String(describing: numClaims)), but \(systemIdValue) is built for exactly \(maxClaimsV1) claim slots"
            )
        }
    }
}

#endif // os(iOS)
