// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Builds the consent model from validated transaction data and the
/// attestation's type metadata (TS12 v1.0.1 sections 3.3.1 to 3.3.3).
///
/// Fails closed: a parameter without a localised name, or a missing required
/// UI label, ends processing ("the Wallet Unit SHALL cease processing the
/// transaction and inform the User", section 3.3.1).
struct TransactionConsentModelBuilder: Sendable {
    let source: any TransactionMetadataSource
    let fetchTimeout: TimeInterval
    let maxResourceBytes: Int
    let note: MetadataAuthenticationNote
    /// One builder serves one validation: every referenced document is fetched once
    /// (several entries naming the same `claims_uri` or `ui_labels_uri` share the download), and
    /// all fetching together shares one deadline of one and a half times the per-fetch timeout, so the time
    /// the user waits before the prompt does not grow with the number of entries.
    private let startedAt = Date()
    private let cache = FetchedResources()
    private var totalBudget: TimeInterval { fetchTimeout * 1.5 }

    /// Maximum string lengths from section 3.3.3.
    static let maxLengths = ["affirmative_action_label": 30, "denial_action_label": 30,
                             "transaction_title": 50, "security_hint": 250]

    func build(
        validated: ValidatedTransactionData,
        request: TransactionDataRequest,
        verifier: String,
        credentialName: String,
        requestSigned: Bool?,
        locale: String,
        attributes: [TransactionConsentAttributes] = []
    ) async throws -> TransactionConsentRequest {
        var entries: [TransactionConsentEntry] = []
        for entry in validated.entries {
            guard let queryId = entry.credentialIds.first,
                  let typeEntry = entry.typeMetadata[queryId]?.objectValue,
                  let credential = request.credentials.first(where: { $0.queryId == queryId }) else {
                throw TransactionDataError(.metadataUnavailable, detail: "no display metadata for the transaction type")
            }
            let pinPrefix = "transaction_data_types['\(entry.type)']."
            let claims = try await resource(
                inline: typeEntry["claims"], uri: typeEntry["claims_uri"], name: "claims",
                pin: credential.integrityClaims[pinPrefix + "claims_uri#integrity"]
            )
            let labels = try await resource(
                inline: typeEntry["ui_labels"], uri: typeEntry["ui_labels_uri"], name: "ui_labels",
                pin: credential.integrityClaims[pinPrefix + "ui_labels_uri#integrity"]
            )
            // Embedded claims/labels are authenticated only through the type
            // metadata itself; with no `vct#integrity` they are not authenticated.
            if credential.integrityClaims["vct#integrity"] == nil { note.noteUnpinned() }
            let fields = try fields(payload: entry.payload, type: entry.type, claims: claims, locale: locale)
            let ui = try uiLabels(labels, locale: locale)
            for text in [ui["transaction_title"], ui["security_hint"], ui["denial_action_label"], ui["affirmative_action_label"]] {
                try TextSafety.require(text, maxLength: 250, what: "a label")
            }
            let typeName = TransactionDataBuiltIns.displayName(forType: entry.type)
            try TextSafety.require(typeName, maxLength: 200, what: "the transaction type name")
            entries.append(TransactionConsentEntry(
                title: ui["transaction_title"],
                typeName: typeName,
                fields: fields,
                affirmativeLabel: try requireLabel(ui["affirmative_action_label"]),
                denialLabel: ui["denial_action_label"],
                securityHint: ui["security_hint"]
            ))
        }
        return TransactionConsentRequest(
            verifier: verifier, credentialName: credentialName, entries: entries,
            requestSigned: requestSigned, locale: locale, attributes: attributes
        )
    }

    private func requireLabel(_ label: String?) throws -> String {
        guard let label, !label.isEmpty else {
            throw TransactionDataError(.metadataUnavailable, detail: "affirmative_action_label is not available")
        }
        return label
    }

    // MARK: Referenced documents

    /// An embedded document or one referenced by URI (never both).
    private func resource(inline: JSONValue?, uri: JSONValue?, name: String, pin: String?) async throws -> JSONValue {
        switch (inline, uri) {
        case (.some, .some):
            throw TransactionDataError(.metadataUnavailable, detail: "\(name) given both inline and by URI")
        case (.none, .none):
            throw TransactionDataError(.metadataUnavailable, detail: "\(name) not provided")
        case (.some(let value), .none):
            return value
        case (.none, .some(let uriValue)):
            guard let uri = uriValue.stringValue, !uri.isEmpty else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(name) URI is not a string")
            }
            let source = self.source
            let limit = maxResourceBytes
            let remaining = totalBudget - Date().timeIntervalSince(startedAt)
            let data: Data?
            if let cached = cache.get(uri) {
                data = cached
            } else if remaining <= 0 {
                data = nil
            } else {
                data = await withDeadline(min(fetchTimeout, remaining), fallback: nil) { await source.fetchResource(uri: uri, maxBytes: limit) }
                if let data { cache.set(uri, data) }
            }
            guard let data, data.count <= maxResourceBytes else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(name) URI could not be fetched")
            }
            if pin == nil { note.noteUnpinned() }
            if let pin, !Integrity.matches(data, pin) {
                throw TransactionDataError(.metadataUnavailable, detail: "\(name) content does not match its #integrity")
            }
            guard let parsed = try? StrictJSON.parse(data) else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(name) content is not JSON")
            }
            return parsed
        }
    }

    // MARK: Fields

    private struct ClaimMeta {
        let path: [String?]
        let level: Int
        let labels: [(lang: String, text: String)]
        let order: Int
    }

    private func claimMetadata(_ claims: JSONValue) throws -> [ClaimMeta] {
        guard let list = claims.arrayValue else {
            throw TransactionDataError(.metadataUnavailable, detail: "claims is not an array")
        }
        return try list.enumerated().map { index, item in
            guard let object = item.objectValue, let rawPath = object["path"]?.arrayValue else {
                throw TransactionDataError(.metadataUnavailable, detail: "claim metadata without a path")
            }
            let path: [String?] = try rawPath.map {
                switch $0 {
                case .string(let s): return s
                case .null: return nil
                default: throw TransactionDataError(.metadataUnavailable, detail: "claim path element is not a string or null")
                }
            }
            var level = 3 // TS12 3.3.1: the default when none is set
            if let v = object["visualisation"] {
                guard case .int(let n) = v, (1...4).contains(n) else {
                    throw TransactionDataError(.metadataUnavailable, detail: "visualisation is not an integer from 1 to 4")
                }
                level = Int(n)
            }
            let labels: [(String, String)] = (object["display"]?.arrayValue ?? []).compactMap { d in
                guard let lang = d["lang"]?.stringValue ?? d["locale"]?.stringValue, let label = d["label"]?.stringValue,
                      !label.isEmpty else { return nil }
                return (lang, label)
            }
            return ClaimMeta(path: path, level: level, labels: labels, order: index)
        }
    }

    private func fields(payload: JSONValue, type: String, claims: JSONValue, locale: String) throws -> [TransactionConsentField] {
        let metadata = try claimMetadata(claims)
        var result: [(order: Int, field: TransactionConsentField)] = []
        for (path, value) in try leaves(of: payload) {
            let full: [String?] = ["payload"] + path
            guard let meta = metadata.first(where: { $0.path == full }) else {
                throw TransactionDataError(.metadataUnavailable, detail: "no claim metadata for a payload parameter")
            }
            guard let label = LocaleMatcher.pick(meta.labels, preferred: locale) else {
                // Level 4 may be left out of the display, so its name is not required.
                let isFloor = TransactionDataBuiltIns.displayFloorPaths(forType: type).contains { $0.map(Optional.some) == path }
                if meta.level == 4 && !isFloor { continue }
                throw TransactionDataError(.metadataUnavailable, detail: "no localised name for a payload parameter")
            }
            // What the user approves is never shown below level 2 for a built-in
            // type, whatever the (possibly unauthenticated) metadata says.
            let floor = TransactionDataBuiltIns.displayFloorPaths(forType: type).contains { $0.map(Optional.some) == path }
            let level = floor ? min(meta.level, 2) : meta.level
            try TextSafety.require(label, maxLength: 100, what: "a parameter name")
            try TextSafety.require(value, maxLength: 1000, what: "a parameter value")
            result.append((meta.order, TransactionConsentField(label: label, value: value, level: level, path: path)))
        }
        return result.sorted { ($0.field.level, $0.order) < ($1.field.level, $1.order) }.map(\.field)
    }

    /// Every leaf of the payload with its path (`nil` for an array element)
    /// and its value as text. Object keys are visited in sorted order so the
    /// result is deterministic; display order comes from the claim metadata.
    private func leaves(of value: JSONValue, path: [String?] = []) throws -> [([String?], String)] {
        switch value {
        case .object(let members):
            return try members.keys.sorted().flatMap { try leaves(of: members[$0]!, path: path + [$0]) }
        case .array(let items):
            return try items.flatMap { try leaves(of: $0, path: path + [nil]) }
        default:
            return [(path, try text(of: value))]
        }
    }

    private func text(of value: JSONValue) throws -> String {
        switch value {
        case .string(let s): return s
        case .bool(let b): return b ? "true" : "false"
        case .null: return "null"
        case .int(let i): return String(i)
        case .decimal(let text):
            // The number exactly as the verifier wrote it. Exponent notation is
            // not shown: it would not read as what was sent.
            guard !text.lowercased().contains("e") else {
                throw TransactionDataError(.invalidEntry, detail: "a number cannot be displayed exactly")
            }
            return text
        case .double:
            // Only a lossy source (never a parsed payload) yields a double.
            throw TransactionDataError(.invalidEntry, detail: "a number cannot be displayed exactly")
        default: throw TransactionDataError(.invalidEntry, detail: "unexpected container value")
        }
    }

    // MARK: UI labels

    private func uiLabels(_ catalogue: JSONValue, locale: String) throws -> [String: String] {
        guard let object = catalogue.objectValue else {
            throw TransactionDataError(.metadataUnavailable, detail: "ui_labels is not an object")
        }
        var result: [String: String] = [:]
        for (key, maxLength) in Self.maxLengths {
            guard let variants = object[key] else { continue }
            guard let list = variants.arrayValue else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(key) is not an array")
            }
            let options: [(String, String)] = list.compactMap { v in
                guard let lang = v["lang"]?.stringValue, let value = v["value"]?.stringValue else { return nil }
                return (lang, value)
            }
            guard let chosen = LocaleMatcher.pick(options, preferred: locale) else { continue }
            guard chosen.unicodeScalars.count <= maxLength else {
                throw TransactionDataError(.metadataUnavailable, detail: "\(key) exceeds \(maxLength) characters")
            }
            result[key] = chosen
        }
        return result
    }
}

/// Picks the best localised string for a preferred BCP 47 tag: exact match,
/// then same primary language, then English, then the first offered.
enum LocaleMatcher {
    static func pick(_ options: [(lang: String, text: String)], preferred: String) -> String? {
        guard !options.isEmpty else { return nil }
        func norm(_ s: String) -> String { s.lowercased().replacingOccurrences(of: "_", with: "-") }
        func primary(_ s: String) -> String { String(norm(s).split(separator: "-").first ?? "") }
        let want = norm(preferred)
        if let exact = options.first(where: { norm($0.lang) == want }) { return exact.text }
        if let same = options.first(where: { primary($0.lang) == primary(want) }) { return same.text }
        if let english = options.first(where: { primary($0.lang) == "en" }) { return english.text }
        return options[0].text
    }
}

/// Text shown to the user comes from a verifier or an issuer-controlled
/// document, so it is refused (never silently altered or cut) when it could
/// misrepresent what is on screen: control and newline characters, format
/// characters (bidirectional overrides and isolates, zero-width characters,
/// joiners, byte-order marks), line and paragraph separators, private-use and
/// unassigned code points, and over-long strings.
enum TextSafety {
    static func isSafe(_ text: String, maxLength: Int) -> Bool {
        guard text.unicodeScalars.count <= maxLength else { return false }
        for scalar in text.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .unassigned, .surrogate: return false
            default: break
            }
        }
        return true
    }

    /// `text` with every scalar `isSafe` would refuse (controls, newlines, bidirectional and other
    /// format characters, private-use and unassigned code points) replaced by U+FFFD, so
    /// verifier-supplied text can be shown or logged without spoofing the line it sits on.
    static func neutralized(_ text: String) -> String {
        var out = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            switch scalar.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .unassigned, .surrogate:
                out.append("\u{FFFD}")
            default:
                out.append(scalar)
            }
        }
        return String(out)
    }

    static func require(_ text: String?, maxLength: Int, what: String) throws {
        guard let text else { return }
        guard isSafe(text, maxLength: maxLength) else {
            throw TransactionDataError(.invalidEntry, detail: "\(what) cannot be displayed safely")
        }
    }
}


/// The documents one validation has already fetched, by URI.
final class FetchedResources: @unchecked Sendable {
    private let lock = NSLock()
    private var documents: [String: Data] = [:]
    func get(_ uri: String) -> Data? { lock.lock(); defer { lock.unlock() }; return documents[uri] }
    func set(_ uri: String, _ data: Data) { lock.lock(); documents[uri] = data; lock.unlock() }
}
