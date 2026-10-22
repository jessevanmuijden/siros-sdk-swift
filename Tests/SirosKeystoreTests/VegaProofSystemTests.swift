// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// The native zk_cred_vega XCFramework only ships iOS slices - see
// VegaProofSystem.swift's own `#if os(iOS)` gating.
#if os(iOS)

import XCTest
import SwiftCBOR
import SirosCredentials
@testable import SirosKeystore

/// `VegaProofSystem.validateCircuitParams` - checks the real circuit
/// catalog's own published `params` (confirmed live against the deployed
/// `vega-mc-p256-v1-*-key-r12` entries: `curve: "P-256"`, `numClaims: "4"`)
/// against what this type hardcodes, so a future circuit version whose
/// shape has genuinely changed fails fast and locally, with a clear
/// diagnostic - instead of only surfacing as an opaque native
/// prove()/verify() failure much later. Ports Kotlin's `VegaProofSystemTest`
/// (siros-sdk-kotlin#244) - same four cases.
final class VegaProofSystemTests: XCTestCase {

    private func descriptor(_ params: [String: String]) -> ZkCircuitDescriptor {
        ZkCircuitDescriptor(
            id: "vega-mc-p256-v1-prover-key-r12",
            system: "vega-mc",
            systemVersion: "12",
            published: true,
            status: "active",
            params: params.mapValues { .string($0) },
            publishedAt: "2026-08-27T20:53:51Z"
        )
    }

    func testValidateCircuitParams_realCatalogShape_passes() throws {
        try VegaProofSystem.validateCircuitParams(
            descriptor(["curve": "P-256", "numClaims": "4", "maxClaimBytes": "176"])
        )
    }

    func testValidateCircuitParams_wrongCurve_throws() {
        XCTAssertThrowsError(
            try VegaProofSystem.validateCircuitParams(descriptor(["curve": "P-384", "numClaims": "4"]))
        )
    }

    func testValidateCircuitParams_wrongNumClaims_throws() {
        XCTAssertThrowsError(
            try VegaProofSystem.validateCircuitParams(descriptor(["curve": "P-256", "numClaims": "8"]))
        )
    }

    func testValidateCircuitParams_missingParams_throws() {
        XCTAssertThrowsError(try VegaProofSystem.validateCircuitParams(descriptor([:])))
    }

    // MARK: - generateProof: pseudonym rejection

    /// Vega has no pseudonym-derivation concept - a caller that still lists
    /// `pairwise_pseudonym` in `requestedClaims` must be rejected up front,
    /// not silently honored with the claim missing from what gets disclosed
    /// (a real presentation-correctness bug Copilot review caught on PR #182:
    /// nothing downstream ever inspected `pseudonymOutcome`, it only checked
    /// whether `result.pseudonym` was non-nil, which for Vega it never is).
    /// Garbage mdoc bytes are fine here - this guard must fire before the
    /// document is even parsed, let alone before any native/network call.
    func testGenerateProof_requestedPseudonymClaim_throws() async throws {
        let system = VegaProofSystem(zkCircuitClient: ZkCircuitClient())
        let spec = ZkSystemSpec(id: "vega-mc-p256-v1-prover-key-r12", system: VegaProofSystem.systemIdValue)

        do {
            _ = try await system.generateProof(
                spec: spec,
                document: .mdoc([0x00]),
                sessionTranscript: [],
                requestedClaims: ["age_over_18", zkPseudonymClaim],
                verifierIdentity: VerifierIdentity(clientId: "verifier", ppidContext: nil),
                signer: { _, _ in [] },
                priorState: nil
            )
            XCTFail("expected generateProof to throw for a pseudonym-claim request")
        } catch let error as MdocError {
            guard case .malformed(let reason) = error else {
                return XCTFail("expected .malformed, got \(error)")
            }
            XCTAssertTrue(reason.contains(zkPseudonymClaim), "error should name the rejected claim: \(reason)")
        }
    }

    // MARK: - buildWitness: deterministic namespace selection

    private func namespaceItem(digestId: UInt64, elementIdentifier: String = "age_over_18") -> NamespaceItem {
        let item = IssuerSignedItem(digestId: digestId, random: [0x01], elementIdentifier: elementIdentifier, elementValue: .boolean(true))
        return NamespaceItem(item: item, original: .map([:]))
    }

    private func fourItemNamespace() -> [NamespaceItem] {
        (0..<UInt64(VegaProofSystem.maxClaimsV1)).map { namespaceItem(digestId: $0, elementIdentifier: "claim\($0)") }
    }

    func testBuildWitness_unsupportedDocType_throws() {
        let document = DocumentMdoc(
            docType: "com.example.unsupported",
            issuerSigned: IssuerSignedMdoc(nameSpaces: ["org.iso.18013.5.1": fourItemNamespace()], issuerAuth: .null)
        )
        XCTAssertThrowsError(try VegaProofSystem.buildWitness(document: document, requestedClaims: [])) { error in
            guard case MdocError.malformed(let reason) = error else { return XCTFail("expected .malformed") }
            XCTAssertTrue(reason.contains("unsupported docType"), reason)
        }
    }

    /// A real mDL can carry a SECOND, jurisdiction-specific namespace
    /// alongside the primary `org.iso.18013.5.1` one - picking
    /// `nameSpaces.values.first` (the pre-fix behavior) could silently prove
    /// over the wrong namespace instead of failing. The fixed, docType-keyed
    /// lookup must reject a credential whose primary namespace is simply
    /// absent, even when SOME other namespace is present.
    func testBuildWitness_primaryNamespaceAbsentButOtherPresent_throws() {
        let document = DocumentMdoc(
            docType: "org.iso.18013.5.1.mDL",
            issuerSigned: IssuerSignedMdoc(nameSpaces: ["org.iso.18013.5.1.US_extension": fourItemNamespace()], issuerAuth: .null)
        )
        XCTAssertThrowsError(try VegaProofSystem.buildWitness(document: document, requestedClaims: [])) { error in
            guard case MdocError.malformed(let reason) = error else { return XCTFail("expected .malformed") }
            XCTAssertTrue(reason.contains("no disclosed 'org.iso.18013.5.1' namespace"), reason)
        }
    }

    // MARK: - buildWitness: digestID range

    func testBuildWitness_digestIdExceedsUInt32_throws() {
        var items = fourItemNamespace()
        items[0] = namespaceItem(digestId: UInt64(UInt32.max) + 1, elementIdentifier: "claim0")
        let document = DocumentMdoc(
            docType: "org.iso.18013.5.1.mDL",
            issuerSigned: IssuerSignedMdoc(nameSpaces: ["org.iso.18013.5.1": items], issuerAuth: .null)
        )
        XCTAssertThrowsError(try VegaProofSystem.buildWitness(document: document, requestedClaims: [])) { error in
            guard case MdocError.malformed(let reason) = error else { return XCTFail("expected .malformed") }
            XCTAssertTrue(reason.contains("supported range"), reason)
        }
    }

    /// The native crate's own documented contract is `digestId < 2^31`, a
    /// tighter bound than `UInt32.max` (`2^32 - 1`) - a digest ID in
    /// `2^31..<2^32` passes a bare `UInt32(exactly:)` check but is still
    /// outside what the crate supports (Copilot review, PR #182: without
    /// this test, a regression that reverted to the looser `UInt32.max`
    /// bound would go unnoticed since `testBuildWitness_digestIdExceedsUInt32_throws`
    /// only exercises a value above `UInt32.max` itself).
    func testBuildWitness_digestIdAtOrAbove2Pow31_throws() {
        var items = fourItemNamespace()
        items[0] = namespaceItem(digestId: UInt64(1) << 31, elementIdentifier: "claim0")
        let document = DocumentMdoc(
            docType: "org.iso.18013.5.1.mDL",
            issuerSigned: IssuerSignedMdoc(nameSpaces: ["org.iso.18013.5.1": items], issuerAuth: .null)
        )
        XCTAssertThrowsError(try VegaProofSystem.buildWitness(document: document, requestedClaims: [])) { error in
            guard case MdocError.malformed(let reason) = error else { return XCTFail("expected .malformed") }
            XCTAssertTrue(reason.contains("supported range"), reason)
        }
    }

    /// The last digest ID the crate's documented `< 2^31` contract still
    /// accepts must NOT be rejected - the boundary test above only proves
    /// the first rejected value is actually rejected; this proves the fix
    /// didn't overshoot into rejecting legitimate values one below it.
    ///
    /// `issuerAuth: .null` (same fixture every other test here uses) is not
    /// a real COSE_Sign1, so `buildWitness` still fails downstream in
    /// `buildEcdsaWitness` - that failure is expected and not what this test
    /// checks. The point is narrower: whatever error comes back must NOT be
    /// the digestID range rejection, since this value is one below the
    /// boundary this guard exists to enforce.
    func testBuildWitness_digestIdJustBelow2Pow31_succeeds() throws {
        var items = fourItemNamespace()
        items[0] = namespaceItem(digestId: (UInt64(1) << 31) - 1, elementIdentifier: "claim0")
        let document = DocumentMdoc(
            docType: "org.iso.18013.5.1.mDL",
            issuerSigned: IssuerSignedMdoc(nameSpaces: ["org.iso.18013.5.1": items], issuerAuth: .null)
        )
        do {
            _ = try VegaProofSystem.buildWitness(document: document, requestedClaims: [])
        } catch MdocError.malformed(let reason) {
            XCTAssertFalse(reason.contains("supported range"), "digestID one below the 2^31 boundary must not be rejected: \(reason)")
        }
    }

    // MARK: - buildWitness: unknown requested claims

    /// A `requestedClaims` entry the credential's namespace does not carry
    /// must be rejected up front - previously it was silently treated as
    /// "not disclosed" (every slot's `disclose` stayed `false`, since none
    /// matched), so `generateProof` would succeed and hand the verifier a
    /// presentation quietly missing a claim it explicitly asked for
    /// (Copilot review, PR #182 - the same presentation-correctness failure
    /// the pseudonym-claim guard in `generateProof` exists to prevent).
    func testBuildWitness_unknownRequestedClaim_throws() {
        let document = DocumentMdoc(
            docType: "org.iso.18013.5.1.mDL",
            issuerSigned: IssuerSignedMdoc(nameSpaces: ["org.iso.18013.5.1": fourItemNamespace()], issuerAuth: .null)
        )
        XCTAssertThrowsError(try VegaProofSystem.buildWitness(document: document, requestedClaims: ["not_a_real_claim"])) { error in
            guard case MdocError.malformed(let reason) = error else { return XCTFail("expected .malformed") }
            XCTAssertTrue(reason.contains("not_a_real_claim"), reason)
        }
    }

    // MARK: - buildEcdsaWitness: COSE alg range

    /// A protected header whose alg label (1) is an unsigned int above
    /// `Int64.max` must not trap `Int64(v)` - it must fail as "unsupported
    /// alg", the same outcome as any other non-ES256 value.
    func testBuildEcdsaWitness_algAboveInt64Max_throwsUnsupportedAlg() throws {
        let hugeAlg = CBOR.map([.unsignedInt(1): .unsignedInt(UInt64.max)])
        let protectedBytes = hugeAlg.encode()
        let issuerAuth = CBOR.array([.byteString(protectedBytes), .map([:]), .byteString([]), .byteString([UInt8](repeating: 0, count: 64))])
        XCTAssertThrowsError(try VegaProofSystem.buildEcdsaWitness(issuerAuth: issuerAuth)) { error in
            guard case MdocError.malformed(let reason) = error else { return XCTFail("expected .malformed") }
            XCTAssertTrue(reason.contains("only supports ES256"), reason)
        }
    }
}

#endif // os(iOS)
