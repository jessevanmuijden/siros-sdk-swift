// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

// The native zk_cred_vega XCFramework only ships iOS slices - see
// VegaProofSystem.swift's own `#if os(iOS)` gating.
#if os(iOS)

import Foundation
import XCTest
import libzstd
import SirosCredentials

/// Exercises the real, vendored `zk_cred_vega` UniFFI bindings directly
/// against the exact real setup keys (`dump_setup`) and the native crate's
/// own real, signed test vector (`test-vectors/mdl_4claims_mixed_disclosure.json`
/// - a genuinely realistic mdoc credential with real CBOR framing, real
/// per-element salts, and a real ECDSA-P256 signature over the real MSO
/// `Sig_structure`, not a self-fabricated toy fixture) - not through
/// `VegaProofSystem`, for the same reason `LongfellowZkVectorTests` doesn't
/// go through `LongfellowZkProofSystem`: this vector's device/issuer
/// signatures are fixed, already-baked-in values with no private key to
/// re-sign a freshly-built witness with. This instead validates the exact
/// same low-level calls a real `VegaProofSystem.generateProof` makes
/// (`deserializeProverKey`/`deserializeVerifierKey`, `prepProve`, `prove`,
/// `verify`), confirming the FFI wiring genuinely works end-to-end from
/// Swift - not just that it compiles. Mirrors the Kotlin SDK's
/// `VegaZkVectorTest` (its own `androidTest` equivalent) exactly, including
/// its two test cases and its resources (copied verbatim - `setup()` is
/// deterministic, so these are byte-identical to what a real r12 catalog
/// fetch would return).
final class VegaZkVectorTests: XCTestCase {

    private struct TestVectorJSON: Decodable {
        struct Claim: Decodable {
            let elementIdentifier: String
            let digestId: UInt32
            let disclose: Bool
            let issuerSignedItemBytesHex: String

            enum CodingKeys: String, CodingKey {
                case elementIdentifier = "element_identifier"
                case digestId = "digest_id"
                case disclose
                case issuerSignedItemBytesHex = "issuer_signed_item_bytes_hex"
            }
        }
        struct EcdsaWitnessJSON: Decodable {
            let qxHex: String, qyHex: String, rHex: String, sHex: String, sInvHex: String
            enum CodingKeys: String, CodingKey {
                case qxHex = "qx_hex", qyHex = "qy_hex", rHex = "r_hex", sHex = "s_hex", sInvHex = "s_inv_hex"
            }
        }
        struct MsoBodyJSON: Decodable {
            let deviceXHex: String, deviceYHex: String
            let signedTs: String, validFromTs: String, validUntilTs: String
            enum CodingKeys: String, CodingKey {
                case deviceXHex = "device_x_hex", deviceYHex = "device_y_hex"
                case signedTs = "signed_ts", validFromTs = "valid_from_ts", validUntilTs = "valid_until_ts"
            }
        }
        let claims: [Claim]
        let ecdsaWitness: EcdsaWitnessJSON
        let msoBody: MsoBodyJSON
        enum CodingKeys: String, CodingKey {
            case claims, ecdsaWitness = "ecdsa_witness", msoBody = "mso_body"
        }
    }

    private struct TestVector {
        let claims: [VegaFfiClaim]
        let ecdsaWitness: FfiEcdsaWitness
        let msoBody: FfiMsoBodyWitness
    }

    private func hexToData(_ hex: String) -> Data {
        var bytes = [UInt8]()
        bytes.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            bytes.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return Data(bytes)
    }

    private func loadResource(_ name: String, ext: String) throws -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "zk-cred-vega") else {
            throw XCTSkip("test resource not found: \(name).\(ext)")
        }
        return try Data(contentsOf: url)
    }

    /// Decompresses in its own call frame - mirrors the Kotlin test's own
    /// `loadProverKey`/`loadVerifierKey` split, so the ~110MB decompressed
    /// buffer becomes unreachable as soon as the native handle exists,
    /// rather than staying live alongside the other key's own ~110MB buffer
    /// (that Kotlin doc comment's own real on-device OOM is the reason this
    /// split exists at all - the same risk applies here).
    private func loadProverKey() throws -> VegaProverKey {
        let compressed = try loadResource("vega-mc-p256-v1-prover-key.bin", ext: "zst")
        return try deserializeProverKey(bytes: decompress(compressed))
    }

    private func loadVerifierKey() throws -> VegaVerifierKey {
        let compressed = try loadResource("vega-mc-p256-v1-verifier-key.bin", ext: "zst")
        return try deserializeVerifierKey(bytes: decompress(compressed))
    }

    private func decompress(_ compressed: Data) throws -> Data {
        let frameSize = compressed.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> UInt64 in
            ZSTD_getFrameContentSize(src.baseAddress, src.count)
        }
        let contentSizeUnknown = UInt64.max
        let contentSizeError = UInt64.max - 1
        XCTAssertTrue(frameSize != contentSizeUnknown && frameSize != contentSizeError && frameSize > 100_000_000)

        var output = Data(count: Int(frameSize))
        let written = output.withUnsafeMutableBytes { (dst: UnsafeMutableRawBufferPointer) -> Int in
            compressed.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Int in
                ZSTD_decompress(dst.baseAddress, dst.count, src.baseAddress, src.count)
            }
        }
        XCTAssertEqual(ZSTD_isError(written), 0)
        return output
    }

    private func loadTestVector() throws -> TestVector {
        let json = try loadResource("mdl_4claims_mixed_disclosure", ext: "json")
        let parsed = try JSONDecoder().decode(TestVectorJSON.self, from: json)

        let claims = parsed.claims.map {
            VegaFfiClaim(
                issuerSignedItemBytes: hexToData($0.issuerSignedItemBytesHex),
                disclose: $0.disclose,
                digestId: $0.digestId
            )
        }
        let ecdsaWitness = FfiEcdsaWitness(
            qx: hexToData(parsed.ecdsaWitness.qxHex),
            qy: hexToData(parsed.ecdsaWitness.qyHex),
            r: hexToData(parsed.ecdsaWitness.rHex),
            s: hexToData(parsed.ecdsaWitness.sHex),
            sInv: hexToData(parsed.ecdsaWitness.sInvHex)
        )
        let msoBody = FfiMsoBodyWitness(
            deviceX: hexToData(parsed.msoBody.deviceXHex),
            deviceY: hexToData(parsed.msoBody.deviceYHex),
            signedTs: Data(parsed.msoBody.signedTs.utf8),
            validFromTs: Data(parsed.msoBody.validFromTs.utf8),
            validUntilTs: Data(parsed.msoBody.validUntilTs.utf8)
        )
        return TestVector(claims: claims, ecdsaWitness: ecdsaWitness, msoBody: msoBody)
    }

    /// One entry per claim slot, in the same order as `TestVector.claims`:
    /// the real `issuerSignedItemBytes` for a disclosed slot, empty for an
    /// undisclosed one - the exact shape `verify()` requires as of the r12
    /// circuit (disclosed bytes travel beside the proof, not inside its
    /// public IO).
    private func disclosedBytes(for vector: TestVector) -> [Data] {
        vector.claims.map { $0.disclose ? $0.issuerSignedItemBytes : Data() }
    }

    /// Full round trip against the real crate: `prepProve` -> `prove` ->
    /// `verify`, confirming the proof verifies and that disclosed/undisclosed
    /// claims come back exactly as the test vector declared them.
    func testProveAndVerify_realMdocVector_succeeds() throws {
        let vector = try loadTestVector()

        let proveResult = try { () throws -> FfiProveResult in
            let proverKey = try loadProverKey()
            let prepState = try prepProve(pk: proverKey, claims: vector.claims, ecdsaWitness: vector.ecdsaWitness, msoBody: vector.msoBody)
            return try prove(pk: proverKey, claims: vector.claims, ecdsaWitness: vector.ecdsaWitness, msoBody: vector.msoBody, priorState: prepState)
        }()

        XCTAssertFalse(proveResult.proofBytes.isEmpty, "proof must be non-empty")
        XCTAssertFalse(proveResult.nextState.isEmpty, "nextState must be non-empty")

        let verifyResult = try verify(vk: loadVerifierKey(), proofBytes: proveResult.proofBytes, disclosedBytes: disclosedBytes(for: vector))

        XCTAssertEqual(vector.ecdsaWitness.qx, verifyResult.qx)
        XCTAssertEqual(vector.ecdsaWitness.qy, verifyResult.qy)
        XCTAssertEqual(vector.msoBody.deviceX, verifyResult.deviceX)
        XCTAssertEqual(vector.msoBody.deviceY, verifyResult.deviceY)
        XCTAssertEqual(vector.claims.count, verifyResult.claims.count)

        for (index, claim) in vector.claims.enumerated() {
            let disclosed = verifyResult.claims[index]
            XCTAssertEqual(claim.disclose, disclosed.disclosed, "claim \(index) disclosed flag")
            XCTAssertEqual(claim.digestId, disclosed.digestId, "claim \(index) digestId")
            if claim.disclose {
                XCTAssertFalse(disclosed.plaintext.isEmpty, "claim \(index) should have real plaintext when disclosed")
            } else {
                XCTAssertTrue(disclosed.plaintext.allSatisfy { $0 == 0 }, "claim \(index) plaintext should be all-zero when undisclosed")
            }
        }
    }

    /// Runs `prove` once and returns only its `nextState` bytes - its own
    /// call frame so the large `prepState`/first `FfiProveResult` become
    /// unreachable before the second `prove` call, mirroring the Kotlin
    /// test's identical `firstProveNextState` split (a real on-device OOM
    /// there otherwise).
    private func firstProveNextState(proverKey: VegaProverKey, vector: TestVector) throws -> Data {
        let prepState = try prepProve(pk: proverKey, claims: vector.claims, ecdsaWitness: vector.ecdsaWitness, msoBody: vector.msoBody)
        return try prove(pk: proverKey, claims: vector.claims, ecdsaWitness: vector.ecdsaWitness, msoBody: vector.msoBody, priorState: prepState).nextState
    }

    /// Confirms the native `prepProve`/`prove`/`verify` API itself still
    /// supports state reuse at this low level: a second `prove` call using
    /// the first call's own `nextState` (skipping `prepProve`) still
    /// produces a verifiable proof. This is NOT the path
    /// `VegaProofSystem.generateProof` actually takes in production -
    /// unlike Longfellow, Vega's `generateProof` deliberately never passes
    /// `priorState` through and never returns a reusable `nextState` (see
    /// its own doc comment): reusing state repeats the same digest-blinding
    /// nonce, making two presentations correlatable to each other even when
    /// they disclose different claims. Keeping this test is still useful -
    /// it is the only coverage that the native binding's reuse mechanism
    /// itself behaves as documented - but it must not be read as proof that
    /// wiring `priorState` into `VegaProofSystem` is safe (Copilot review,
    /// PR #182).
    func testProve_reusingPriorState_stillVerifies() throws {
        let vector = try loadTestVector()

        let secondProve = try { () throws -> FfiProveResult in
            let proverKey = try loadProverKey()
            let nextState = try firstProveNextState(proverKey: proverKey, vector: vector)
            return try prove(pk: proverKey, claims: vector.claims, ecdsaWitness: vector.ecdsaWitness, msoBody: vector.msoBody, priorState: nextState)
        }()

        let verifyResult = try verify(vk: loadVerifierKey(), proofBytes: secondProve.proofBytes, disclosedBytes: disclosedBytes(for: vector))
        XCTAssertEqual(vector.ecdsaWitness.qx, verifyResult.qx)
    }
}

#endif // os(iOS)
