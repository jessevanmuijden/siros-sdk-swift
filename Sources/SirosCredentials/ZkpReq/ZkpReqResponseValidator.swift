// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Why a `zkp_req` response was refused. `code` is the stable identifier shared with the conformance vectors
/// (siros-dc-matcher `zkp_req_response`); the first rule broken is reported.
public enum ZkpReqResponseError: String, Error, Sendable, Equatable {
    case responseNotParseable = "response_not_parseable"
    case duplicateMember = "duplicate_member"
    case queryIdMissing = "query_id_missing"
    case presentationsNotArray = "presentations_not_array"
    case presentationsEmpty = "presentations_empty"
    case presentationsMultipleNotAllowed = "presentations_multiple_not_allowed"
    case presentationNotString = "presentation_not_string"
    case presentationNotBase64url = "presentation_not_base64url"
    case cborMalformed = "cbor_malformed"
    case cborIndefiniteLength = "cbor_indefinite_length"
    case cborTrailingBytes = "cbor_trailing_bytes"
    case cborDuplicateKey = "cbor_duplicate_key"
    case presentationNotMap = "presentation_not_map"
    case presentationKeyNotText = "presentation_key_not_text"
    case presentationUnknownMember = "presentation_unknown_member"
    case presentationMemberMissing = "presentation_member_missing"
    case presentationMemberWrongType = "presentation_member_wrong_type"
    case systemIdNotOffered = "system_id_not_offered"
    case proofEmpty = "proof_empty"
    case issuerKeySetEmpty = "issuer_key_set_empty"
    case issuerKeySetTooMany = "issuer_key_set_too_many"
    case issuerKeyNotBytes = "issuer_key_not_bytes"
    case issuerKeyEmpty = "issuer_key_empty"
    case issuerKeyTooLarge = "issuer_key_too_large"
    case proofTimeMissing = "proof_time_missing"
    case proofTimeNotTdate = "proof_time_not_tdate"
    case proofTimeForm = "proof_time_form"
    case resultKeyNotText = "result_key_not_text"
    case resultHandleUnexpected = "result_handle_unexpected"
    case resultHandleMissing = "result_handle_missing"
    case resultFunctionUnknown = "result_function_unknown"
    case resultWrongType = "result_wrong_type"
    case resultNotSatisfied = "result_not_satisfied"
    case pseudonymPrfUnknown = "pseudonym_prf_unknown"
    case pseudonymWrongLength = "pseudonym_wrong_length"

    public var code: String { rawValue }
}

/// One accepted `ZkpPresentation`. The proof and the certificates are opaque here and may be secret-adjacent
/// (a pseudonym): the type redacts its description.
public struct ZkpReqPresentation: Sendable, Equatable, CustomStringConvertible {
    public enum Result: Sendable, Equatable {
        case pseudonym([UInt8])
        case predicate
    }

    public let systemId: String
    public let proof: [UInt8]
    public let issuerKeySet: [[UInt8]]
    public let proofTime: String?
    public let results: [(handle: String, value: Result)]

    public static func == (lhs: ZkpReqPresentation, rhs: ZkpReqPresentation) -> Bool {
        lhs.systemId == rhs.systemId && lhs.proof == rhs.proof && lhs.issuerKeySet == rhs.issuerKeySet && lhs.proofTime == rhs.proofTime
            && lhs.results.count == rhs.results.count && zip(lhs.results, rhs.results).allSatisfy { $0.handle == $1.handle && $0.value == $1.value }
    }

    public var description: String { "ZkpReqPresentation(systemId: \(systemId), redacted)" }
}

/// Checks the SHAPE of a `zkp_req` entry in a `vp_token` and its binding to the request (siros-dc-matcher
/// docs/zkp_req_response.md; the vectors are copied verbatim). It verifies neither the proof nor any
/// certificate. A wallet runs it on the response it built before sending it.
public enum ZkpReqResponseValidator {
    public static let pseudonymBytesSha256 = 32
    public static let pseudonymBytesHashdh = 48
    public static let issuerKeySetMax = 8
    public static let issuerKeyMaxBytes = 4096
    /// The longest `base64url` presentation read (a real proof can be large, but unbounded input is refused).
    public static let maxPresentationCharacters = 256 * 1024

    private static let members = ["system_id", "proof", "issuer_key_set", "proof_time", "results"]
    private static let required = ["system_id", "proof", "issuer_key_set", "results"]

    public static func validate(_ plan: ZkpReqPlan, vpToken: String) throws {
        _ = try parse(plan, vpToken: vpToken)
    }

    public static func parse(_ plan: ZkpReqPlan, vpToken: String) throws -> [ZkpReqPresentation] {
        guard case .object(let token)? = RawJSON.parse(vpToken) else { throw ZkpReqResponseError.responseNotParseable }
        var seen = Set<String>()
        for (key, _) in token where !seen.insert(key).inserted { throw ZkpReqResponseError.duplicateMember }
        guard let queryId = plan.queryId, let entry = token.first(where: { $0.0 == queryId })?.1 else {
            throw ZkpReqResponseError.queryIdMissing
        }
        guard case .array(let presentations) = entry else { throw ZkpReqResponseError.presentationsNotArray }
        guard !presentations.isEmpty else { throw ZkpReqResponseError.presentationsEmpty }
        if presentations.count > 1, !plan.allowsMultiple { throw ZkpReqResponseError.presentationsMultipleNotAllowed }
        return try presentations.map { try check(plan, $0) }
    }

    private static func check(_ plan: ZkpReqPlan, _ element: RawJSON) throws -> ZkpReqPresentation {
        guard case .string(let text) = element else { throw ZkpReqResponseError.presentationNotString }
        guard let bytes = decodeBase64url(text) else { throw ZkpReqResponseError.presentationNotBase64url }
        let item: ZkpReqCbor.Item
        do { item = try ZkpReqCbor.decode(bytes) } catch let failure as ZkpReqCbor.Failure {
            switch failure {
            case .malformed: throw ZkpReqResponseError.cborMalformed
            case .indefinite: throw ZkpReqResponseError.cborIndefiniteLength
            case .trailing: throw ZkpReqResponseError.cborTrailingBytes
            case .duplicateKey: throw ZkpReqResponseError.cborDuplicateKey
            }
        }
        guard case .map(let entries) = item else { throw ZkpReqResponseError.presentationNotMap }
        var named: [(String, ZkpReqCbor.Item)] = []
        for (key, value) in entries {
            guard case .text(let name) = key else { throw ZkpReqResponseError.presentationKeyNotText }
            named.append((name, value))
        }
        if named.contains(where: { !members.contains($0.0) }) { throw ZkpReqResponseError.presentationUnknownMember }
        func find(_ name: String) -> ZkpReqCbor.Item? { named.first { $0.0 == name }?.1 }
        for member in required where find(member) == nil { throw ZkpReqResponseError.presentationMemberMissing }
        guard case .text(let systemId)? = find("system_id"), case .bytes(let proof)? = find("proof"),
              case .array(let keys)? = find("issuer_key_set"), case .map(let results)? = find("results") else {
            throw ZkpReqResponseError.presentationMemberWrongType
        }
        // Fail closed: a request that stated no list offered nothing to match. The presentation carries no
        // proof system, so only `system_id_values` is checkable here.
        guard plan.systemIds?.contains(systemId) == true else { throw ZkpReqResponseError.systemIdNotOffered }
        guard !proof.isEmpty else { throw ZkpReqResponseError.proofEmpty }
        let keySet = try checkIssuerKeySet(keys)
        let proofTime = try checkProofTime(plan, find("proof_time"))
        return ZkpReqPresentation(systemId: systemId, proof: proof, issuerKeySet: keySet, proofTime: proofTime, results: try checkResults(plan, results))
    }

    private static func checkIssuerKeySet(_ keys: [ZkpReqCbor.Item]) throws -> [[UInt8]] {
        guard !keys.isEmpty else { throw ZkpReqResponseError.issuerKeySetEmpty }
        guard keys.count <= issuerKeySetMax else { throw ZkpReqResponseError.issuerKeySetTooMany }
        var out: [[UInt8]] = []
        for key in keys {
            guard case .bytes(let bytes) = key else { throw ZkpReqResponseError.issuerKeyNotBytes }
            guard !bytes.isEmpty else { throw ZkpReqResponseError.issuerKeyEmpty }
            guard bytes.count <= issuerKeyMaxBytes else { throw ZkpReqResponseError.issuerKeyTooLarge }
            out.append(bytes)
        }
        return out
    }

    private static func checkProofTime(_ plan: ZkpReqPlan, _ item: ZkpReqCbor.Item?) throws -> String? {
        guard let item else {
            if plan.sourceFormat == ZkpReqPlanner.sourceMsoMdoc { throw ZkpReqResponseError.proofTimeMissing }
            return nil
        }
        guard case .tag(0, let inner) = item, case .text(let text) = inner else { throw ZkpReqResponseError.proofTimeNotTdate }
        guard (try? ZkpReqProofTime.parse(text)) != nil else { throw ZkpReqResponseError.proofTimeForm }
        return text
    }

    private static func checkResults(_ plan: ZkpReqPlan, _ results: [(ZkpReqCbor.Item, ZkpReqCbor.Item)]) throws -> [(handle: String, value: ZkpReqPresentation.Result)] {
        var named: [(String, ZkpReqCbor.Item)] = []
        for (key, value) in results {
            guard case .text(let handle) = key else { throw ZkpReqResponseError.resultKeyNotText }
            named.append((handle, value))
        }
        let wanted = Set(plan.functions.map(\.handle))
        if named.contains(where: { !wanted.contains($0.0) }) { throw ZkpReqResponseError.resultHandleUnexpected }
        for function in plan.functions where !named.contains(where: { $0.0 == function.handle }) {
            throw ZkpReqResponseError.resultHandleMissing
        }
        var out: [(handle: String, value: ZkpReqPresentation.Result)] = []
        for function in plan.functions {
            guard let value = named.first(where: { $0.0 == function.handle })?.1 else { throw ZkpReqResponseError.resultHandleMissing }
            switch function.functionId {
            case "pseudonym":
                let length: Int
                switch function.params["prf"]?.stringValue {
                case "sha-256": length = pseudonymBytesSha256
                case "hashdh-bls12381g1": length = pseudonymBytesHashdh
                default: throw ZkpReqResponseError.pseudonymPrfUnknown
                }
                guard case .bytes(let bytes) = value else { throw ZkpReqResponseError.resultWrongType }
                guard bytes.count == length else { throw ZkpReqResponseError.pseudonymWrongLength }
                out.append((function.handle, .pseudonym(bytes)))
            case "age_check":
                switch value {
                case .bool(true): out.append((function.handle, .predicate))
                case .bool(false): throw ZkpReqResponseError.resultNotSatisfied // a decline, not a result
                default: throw ZkpReqResponseError.resultWrongType
                }
            default:
                throw ZkpReqResponseError.resultFunctionUnknown
            }
        }
        return out
    }

    /// Strict unpadded base64url: alphabet `A-Z a-z 0-9 - _`, no padding, no whitespace, a canonical final
    /// character. Nil otherwise.
    static func decodeBase64url(_ text: String) -> [UInt8]? {
        let bytes = Array(text.utf8)
        guard bytes.count <= maxPresentationCharacters, bytes.count % 4 != 1 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(bytes.count / 4 * 3 + 2)
        var accumulator: UInt32 = 0, bits: UInt32 = 0
        for byte in bytes {
            let value: UInt32
            switch byte {
            case 0x41...0x5A: value = UInt32(byte - 0x41)
            case 0x61...0x7A: value = UInt32(byte - 0x61 + 26)
            case 0x30...0x39: value = UInt32(byte - 0x30 + 52)
            case 0x2D: value = 62
            case 0x5F: value = 63
            default: return nil
            }
            accumulator = (accumulator << 6) | value
            bits += 6
            if bits >= 8 {
                bits -= 8
                out.append(UInt8(truncatingIfNeeded: accumulator >> bits))
            }
        }
        if bits > 0, accumulator & ((1 << bits) - 1) != 0 { return nil }
        return out
    }
}
