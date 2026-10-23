// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

// The `zkp_req` request side (nym_auth rulebook v0.4, "DCQL profile and presentation syntax"; siros-dc-matcher
// docs/zkp_req_request.md): the planner judges STRUCTURE, `ZkpReqUnsatisfiable` the rulebook's rules that need
// only the request. Which configurations a proof system supports is its registry entry's say, not decided here.

/// One function call of `_req`, normalised: `functionId` is `fn_id`, `handle` is `return`, `params` the
/// original parameters (known ones were type-checked, every other one is untouched).
public struct ZkpReqPlannedFunction: Sendable, Equatable {
    public let functionId: String
    public let handle: String
    public let params: [String: JSONValue]

    public init(functionId: String, handle: String, params: [String: JSONValue]) {
        self.functionId = functionId
        self.handle = handle
        self.params = params
    }
}

/// A normalised `zkp_req` credential query.
public struct ZkpReqPlan: Sendable, Equatable {
    public let functions: [ZkpReqPlannedFunction]
    /// `client_metadata.vp_formats_supported.zkp_req.proof_system_values`, when stated.
    public let proofSystems: [String]?
    /// `system_id_values`, when stated.
    public let systemIds: [String]?
    /// `meta.source_format`.
    public let sourceFormat: String
    public let metaDoctype: String?
    public let metaSchemaId: String?
    /// The credential query exactly as parsed (unknown members survive).
    public let raw: JSONValue

    public init(
        functions: [ZkpReqPlannedFunction], proofSystems: [String]?, systemIds: [String]?, sourceFormat: String,
        metaDoctype: String?, metaSchemaId: String?, raw: JSONValue
    ) {
        self.functions = functions
        self.proofSystems = proofSystems
        self.systemIds = systemIds
        self.sourceFormat = sourceFormat
        self.metaDoctype = metaDoctype
        self.metaSchemaId = metaSchemaId
        self.raw = raw
    }

    /// The `id` of the credential query (the `vp_token` key of its response).
    public var queryId: String? { raw.objectValue?["id"]?.stringValue }
    /// DCQL: `multiple` omitted means false.
    public var allowsMultiple: Bool { raw.objectValue?["multiple"]?.boolValue == true }
}

/// A structurally invalid request. The `code` is the stable identifier shared with the conformance vectors.
public enum ZkpReqInvalidRequest: String, Error, Sendable, Equatable {
    case queryNotParseable = "query_not_parseable"
    case reqMissingOrEmpty = "req_missing_or_empty"
    case itemMissingFunctionId = "item_missing_function_id"
    case itemMissingHandle = "item_missing_handle"
    case paramWrongType = "param_wrong_type"
    case paramInvalidFullDate = "param_invalid_full_date"
    case duplicateHandle = "duplicate_handle"
    case claimsPresent = "claims_present"
    case claimSetsPresent = "claim_sets_present"
    case reqSetsPresent = "req_sets_present"
    case invalidMeta = "invalid_meta"
    case invalidClientMetadata = "invalid_client_metadata"

    public var code: String { rawValue }
}

public enum ZkpReqPlanner {
    public static let sourceMsoMdoc = "mso_mdoc"
    public static let sourceBbsCd = "bbs_cd"

    private enum ParamType { case string, fullDate, integer }

    /// The function table; where a new rulebook function is added. Every declared parameter is optional here.
    private static let functions: [String: [String: ParamType]] = [
        "pseudonym": ["config": .string, "ver": .integer, "prf": .string, "verifier_context": .string],
        "age_check": ["ge": .fullDate, "le": .fullDate],
    ]

    /// Parses and normalises one Credential Query (an element of `dcql_query.credentials`) and, optionally,
    /// the request's `client_metadata`.
    public static func plan(credentialQuery: String, clientMetadata: String? = nil) throws -> ZkpReqPlan {
        guard let raw = try? StrictJSON.parse(credentialQuery), let query = raw.objectValue else {
            throw ZkpReqInvalidRequest.queryNotParseable
        }
        // DCQL's own claim machinery has no meaning for this format.
        if query["claims"] != nil { throw ZkpReqInvalidRequest.claimsPresent }
        if query["claim_sets"] != nil { throw ZkpReqInvalidRequest.claimSetsPresent }
        if query["_req_sets"] != nil { throw ZkpReqInvalidRequest.reqSetsPresent }
        let meta = try readMeta(query["meta"])
        guard let req = query["_req"] else { throw ZkpReqInvalidRequest.reqMissingOrEmpty }
        let planned = try readItems(req)
        let filter = try clientMetadata.map(readFilter) ?? (nil, nil)
        return ZkpReqPlan(
            functions: planned, proofSystems: filter.0, systemIds: filter.1, sourceFormat: meta.sourceFormat,
            metaDoctype: meta.doctype, metaSchemaId: meta.schemaId, raw: raw)
    }

    private static func readMeta(_ value: JSONValue?) throws -> (sourceFormat: String, doctype: String?, schemaId: String?) {
        guard let meta = value?.objectValue, let source = meta["source_format"]?.stringValue else { throw ZkpReqInvalidRequest.invalidMeta }
        func text(_ key: String) throws -> String? {
            guard let value = meta[key] else { return nil }
            guard let string = value.stringValue else { throw ZkpReqInvalidRequest.invalidMeta }
            return string
        }
        let doctype = try text("doctype_value"), schema = try text("schema_id_value")
        if let vct = meta["vct_values"] {
            guard let list = vct.arrayValue, list.allSatisfy({ $0.stringValue != nil }) else { throw ZkpReqInvalidRequest.invalidMeta }
        }
        return (source, doctype, schema)
    }

    private static func readItems(_ req: JSONValue) throws -> [ZkpReqPlannedFunction] {
        guard let items = req.arrayValue, !items.isEmpty else { throw ZkpReqInvalidRequest.reqMissingOrEmpty }
        var seen = Set<String>()
        var out: [ZkpReqPlannedFunction] = []
        for item in items {
            guard let functionId = item.objectValue?["fn_id"]?.stringValue else { throw ZkpReqInvalidRequest.itemMissingFunctionId }
            guard let handle = item.objectValue?["return"]?.stringValue else { throw ZkpReqInvalidRequest.itemMissingHandle }
            guard seen.insert(handle).inserted else { throw ZkpReqInvalidRequest.duplicateHandle }
            out.append(ZkpReqPlannedFunction(functionId: functionId, handle: handle, params: try readParams(functionId, item.objectValue?["params"])))
        }
        return out
    }

    private static func readParams(_ functionId: String, _ value: JSONValue?) throws -> [String: JSONValue] {
        var params: [String: JSONValue] = [:]
        if let value {
            guard let object = value.objectValue else { throw ZkpReqInvalidRequest.paramWrongType }
            params = object
        }
        guard let spec = functions[functionId] else { return params }
        for (name, type) in spec {
            guard let value = params[name] else { continue }
            switch type {
            case .integer:
                guard isInteger(value) else { throw ZkpReqInvalidRequest.paramWrongType }
            case .string, .fullDate:
                guard let text = value.stringValue else { throw ZkpReqInvalidRequest.paramWrongType }
                if type == .fullDate, !isFullDate(text) { throw ZkpReqInvalidRequest.paramInvalidFullDate }
            }
        }
        return params
    }

    /// A JSON number with no fraction or exponent that fits a 64-bit integer (signed or unsigned).
    static func isInteger(_ value: JSONValue) -> Bool {
        switch value {
        case .int: return true
        case .decimal(let text):
            guard !text.contains("."), !text.contains("e"), !text.contains("E") else { return false }
            return Int64(text) != nil || UInt64(text) != nil
        default: return false
        }
    }

    /// RFC 3339 section 5.6 `full-date`: `YYYY-MM-DD` with a real calendar day. Syntax and calendar only.
    static func isFullDate(_ text: String) -> Bool {
        let parts = text.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0].utf8.count == 4, parts[1].utf8.count == 2, parts[2].utf8.count == 2,
              parts.allSatisfy({ $0.utf8.allSatisfy { $0 >= 0x30 && $0 <= 0x39 } }),
              let year = Int(parts[0]), let month = Int(parts[1]), let day = Int(parts[2]) else { return false }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
        let days: Int
        switch month {
        case 1, 3, 5, 7, 8, 10, 12: days = 31
        case 4, 6, 9, 11: days = 30
        case 2: days = leap ? 29 : 28
        default: return false
        }
        return (1...days).contains(day)
    }

    private static func readFilter(_ text: String) throws -> ([String]?, [String]?) {
        guard let metadata = (try? StrictJSON.parse(text))?.objectValue else { throw ZkpReqInvalidRequest.invalidClientMetadata }
        guard let formats = try object(metadata["vp_formats_supported"]) else { return (nil, nil) }
        guard let entry = try object(formats["zkp_req"]) else { return (nil, nil) }
        return (try stringList(entry["proof_system_values"]), try stringList(entry["system_id_values"]))
    }

    /// nil when the member is absent; a wrong type is an invalid `client_metadata`.
    private static func object(_ value: JSONValue?) throws -> [String: JSONValue]? {
        guard let value else { return nil }
        guard let object = value.objectValue else { throw ZkpReqInvalidRequest.invalidClientMetadata }
        return object
    }

    private static func stringList(_ value: JSONValue?) throws -> [String]? {
        guard let value else { return nil }
        guard let list = value.arrayValue else { throw ZkpReqInvalidRequest.invalidClientMetadata }
        let strings = list.compactMap(\.stringValue)
        guard strings.count == list.count else { throw ZkpReqInvalidRequest.invalidClientMetadata }
        return strings
    }
}

/// Why a well-formed request is unsatisfiable by the rulebook's own rules (decided from the request alone).
public enum ZkpReqUnsatisfiable: String, Error, Sendable, Equatable {
    case sourceFormatUnsupported = "source_format_unsupported"
    case metaTypeValueInvalid = "meta_type_value_invalid"
    case holderBindingWaived = "holder_binding_waived"
    case functionUnknown = "function_unknown"
    case pseudonymRepeated = "pseudonym_repeated"
    case ageCheckRepeated = "age_check_repeated"
    case pseudonymConfigMissing = "pseudonym_config_missing"
    case pseudonymConfigUnknown = "pseudonym_config_unknown"
    case pseudonymVerMissing = "pseudonym_ver_missing"
    case pseudonymVerUnsupported = "pseudonym_ver_unsupported"
    case pseudonymPrfMissing = "pseudonym_prf_missing"
    case pseudonymPrfUnsupported = "pseudonym_prf_unsupported"
    case verifierContextInvalid = "verifier_context_invalid"
    case ageCheckNoBound = "age_check_no_bound"
    case ageCheckInverted = "age_check_inverted"
    case ageCheckSpanTooShort = "age_check_span_too_short"

    public var code: String { rawValue }

    /// The pseudonym configurations the rulebook defines, with whether `bbs_cd` defines them.
    private static let configs: [String: Bool] = [
        "known-offender-matching-ssc": true, "known-offender-matching-psc": false,
        "account-recovery-ssc": false, "user-managed-pseudonym-xsite-ssc": false,
    ]
    public static let pseudonymVersion: UInt64 = 1
    public static let minimumAgeSpanDays: Int64 = 365

    /// The first rule a plan breaks, or nil. A plan that passes is not thereby served: the selected system's
    /// registry entry still decides which configurations and parameters it supports.
    public static func check(_ plan: ZkpReqPlan) -> ZkpReqUnsatisfiable? {
        let bbs: Bool
        switch plan.sourceFormat {
        case ZkpReqPlanner.sourceMsoMdoc: bbs = false
        case ZkpReqPlanner.sourceBbsCd: bbs = true
        default: return .sourceFormatUnsupported
        }
        let typeOk = bbs ? (plan.metaSchemaId != nil && plan.metaDoctype == nil) : (plan.metaDoctype != nil && plan.metaSchemaId == nil)
        let hasVct = plan.raw.objectValue?["meta"]?.objectValue?["vct_values"] != nil
        if !typeOk || hasVct { return .metaTypeValueInvalid }
        if plan.raw.objectValue?["require_cryptographic_holder_binding"]?.boolValue == false { return .holderBindingWaived }
        var pseudonyms = 0, ages = 0
        for function in plan.functions {
            switch function.functionId {
            case "pseudonym":
                pseudonyms += 1
                if pseudonyms > 1 { return .pseudonymRepeated }
                if let rule = pseudonymRule(function.params, bbs: bbs) { return rule }
            case "age_check":
                ages += 1
                if ages > 1 { return .ageCheckRepeated }
                if let rule = ageRule(function.params) { return rule }
            default:
                return .functionUnknown
            }
        }
        return nil
    }

    private static func pseudonymRule(_ params: [String: JSONValue], bbs: Bool) -> ZkpReqUnsatisfiable? {
        guard let config = params["config"]?.stringValue else { return .pseudonymConfigMissing }
        guard let bbsOk = configs[config] else { return .pseudonymConfigUnknown }
        guard let ver = params["ver"] else { return .pseudonymVerMissing }
        var one = false
        if case .int(1) = ver { one = true }
        guard one else { return .pseudonymVerUnsupported }
        guard let prf = params["prf"]?.stringValue else { return .pseudonymPrfMissing }
        let prfOk = bbs ? (prf == "hashdh-bls12381g1" && bbsOk) : prf == "sha-256"
        guard prfOk else { return .pseudonymPrfUnsupported }
        let wantsContext = config == "account-recovery-ssc"
        if let context = params["verifier_context"]?.stringValue {
            return wantsContext && (1...64).contains(context.utf8.count) ? nil : .verifierContextInvalid
        }
        return wantsContext ? .verifierContextInvalid : nil
    }

    private static func ageRule(_ params: [String: JSONValue]) -> ZkpReqUnsatisfiable? {
        let ge = params["ge"]?.stringValue, le = params["le"]?.stringValue
        switch (ge, le) {
        case (nil, nil): return .ageCheckNoBound
        case (let ge?, let le?):
            guard let from = dayNumber(ge), let to = dayNumber(le) else { return .ageCheckNoBound }
            if to < from { return .ageCheckInverted }
            if to - from + 1 < minimumAgeSpanDays { return .ageCheckSpanTooShort }
            return nil
        default: return nil
        }
    }

    /// Days since 1970-01-01 of a validated `full-date`.
    private static func dayNumber(_ date: String) -> Int64? {
        let parts = date.split(separator: "-").compactMap { Int64($0) }
        guard parts.count == 3 else { return nil }
        return ZkpReqProofTime.days(fromCivil: parts[0], parts[1], parts[2])
    }
}
