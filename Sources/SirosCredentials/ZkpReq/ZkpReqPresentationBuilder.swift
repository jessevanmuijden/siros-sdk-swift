// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Builds the `vp_token` entry of a `zkp_req` response (nym_auth rulebook v0.4): the base64url (no padding) of
/// the definite-length CBOR encoding of a `ZkpPresentation`. The wallet then runs ``ZkpReqResponseValidator`` on
/// what it built and sends nothing that fails it.
///
/// `proof_time` is the PROVER's: the wallet renders it from its own clock with ``ZkpReqProofTime/render(seconds:)``
/// (the same bytes are the circuit's public input); there is no verifier-chosen time and no `iat` binding.
public enum ZkpReqPresentationBuilder {
    public enum Refusal: Error, Sendable, Equatable {
        /// A field breaks a limit of the shape (empty proof, certificate count or size, `proof_time` form).
        case invalid(ZkpReqResponseError)
    }

    public enum ResultValue: Sendable {
        case pseudonym([UInt8])
        case predicateSatisfied
    }

    /// Encodes one presentation. `results` are keyed by the request's `return` handles, in the order given.
    public static func encode(
        systemId: String, proof: [UInt8], issuerKeySet: [[UInt8]], proofTime: String?, results: [(handle: String, value: ResultValue)]
    ) -> String {
        var map = Encoder()
        map.header(major: 5, count: 4 + (proofTime == nil ? 0 : 1))
        map.text("system_id"); map.text(systemId)
        map.text("proof"); map.bytes(proof)
        map.text("issuer_key_set"); map.header(major: 4, count: issuerKeySet.count)
        for key in issuerKeySet { map.bytes(key) }
        if let proofTime {
            map.text("proof_time"); map.header(major: 6, count: 0); map.text(proofTime)
        }
        map.text("results"); map.header(major: 5, count: results.count)
        for (handle, value) in results {
            map.text(handle)
            switch value {
            case .pseudonym(let bytes): map.bytes(bytes)
            case .predicateSatisfied: map.out.append(0xF5)
            }
        }
        return base64url(map.out)
    }

    /// The whole `vp_token` for one credential query, validated against the plan before it is returned.
    public static func vpToken(
        for plan: ZkpReqPlan, presentations: [String]
    ) throws -> String {
        guard let queryId = plan.queryId else { throw Refusal.invalid(.queryIdMissing) }
        let entries = presentations.map { "\"\($0)\"" }.joined(separator: ",")
        let token = "{\(RawJSON.string(queryId).serialized()):[\(entries)]}"
        do { try ZkpReqResponseValidator.validate(plan, vpToken: token) } catch let error as ZkpReqResponseError {
            throw Refusal.invalid(error)
        }
        return token
    }

    private struct Encoder {
        var out: [UInt8] = []

        mutating func header(major: UInt8, count: Int) {
            let n = UInt64(count)
            switch n {
            case 0...23: out.append(major << 5 | UInt8(n))
            case 24...0xFF: out += [major << 5 | 24, UInt8(n)]
            case 0x100...0xFFFF: out += [major << 5 | 25, UInt8(n >> 8), UInt8(n & 0xFF)]
            default:
                out.append(major << 5 | 26)
                for shift in [24, 16, 8, 0] as [UInt64] { out.append(UInt8(truncatingIfNeeded: n >> shift)) }
            }
        }

        mutating func text(_ value: String) { let bytes = Array(value.utf8); header(major: 3, count: bytes.count); out += bytes }
        mutating func bytes(_ value: [UInt8]) { header(major: 2, count: value.count); out += value }
    }

    private static func base64url(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
