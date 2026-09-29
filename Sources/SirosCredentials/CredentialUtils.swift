// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CoreFoundation)
// For CFGetTypeID/CFBooleanGetTypeID in formatClaimValue. Available through
// Foundation on Apple platforms, but on Linux swift-corelibs-foundation needs
// the module imported explicitly.
import CoreFoundation
#endif
@preconcurrency import SwiftCBOR
#if canImport(os)
import os
private let logger = Logger(subsystem: "org.siros.sdk", category: "CredentialUtils")
#endif

/// A user-facing claim extracted from a credential payload.
public struct DisplayClaim: Sendable, Equatable {
    public let key: String
    public let label: String
    public let value: String
    public let description: String?
    public let mandatory: Bool
    /// VCTM SVG template placeholder ID this claim fills, if any.
    public let svgId: String?
    /// A `data:image/...;base64,...` URI when this claim is a byte-string
    /// that decoded to a displayable image (e.g. an mdoc portrait) - kept
    /// separate from `value` so a generic claims list still shows the
    /// concise `"<N bytes>"` placeholder instead of an enormous base64
    /// string; only `SvgTemplateRenderer` substitutes this into a card.
    public let imageDataUri: String?
    /// True when this claim is a byte-string that could not be turned into
    /// a displayable image (e.g. JPEG 2000 - see `CredentialUtils.formatCborValue`).
    /// `SvgTemplateRenderer` renders such a claim as `-` rather than the raw
    /// `"<N bytes>"` placeholder, which would be more confusing in an image slot.
    public let isUndecodableBytes: Bool

    public init(
        key: String,
        label: String,
        value: String,
        description: String? = nil,
        mandatory: Bool = false,
        svgId: String? = nil,
        imageDataUri: String? = nil,
        isUndecodableBytes: Bool = false
    ) {
        self.key = key
        self.label = label
        self.value = value
        self.description = description
        self.mandatory = mandatory
        self.svgId = svgId
        self.imageDataUri = imageDataUri
        self.isUndecodableBytes = isUndecodableBytes
    }
}

/// One claim whose value changed between two versions of the same credential.
public struct AttributeChange: Sendable, Equatable {
    public let key: String
    public let label: String
    public let oldValue: String
    public let newValue: String

    public init(key: String, label: String, oldValue: String, newValue: String) {
        self.key = key
        self.label = label
        self.oldValue = oldValue
        self.newValue = newValue
    }
}

/// The result of ``CredentialUtils/computeAttributeDiff(before:after:)``.
/// `hasChanges` is false (the fully-silent-renewal case per plan §4.4) only
/// when all three lists are empty.
public struct CredentialAttributeDiff: Sendable, Equatable {
    public let changed: [AttributeChange]
    public let added: [DisplayClaim]
    public let removed: [DisplayClaim]

    public init(changed: [AttributeChange], added: [DisplayClaim], removed: [DisplayClaim]) {
        self.changed = changed
        self.added = added
        self.removed = removed
    }

    public var hasChanges: Bool { !changed.isEmpty || !added.isEmpty || !removed.isEmpty }
}

/// The individually-decoded parts of a raw SD-JWT VC string, for display.
///
/// Each field is the decoded JSON text (not yet pretty-printed - callers
/// typically feed these straight into ``CredentialUtils/prettyPrintJson(_:)``
/// or an equivalent renderer).
public struct SdJwtParts: Sendable, Equatable {
    public let header: String?
    public let payload: String?
    /// Each disclosure is a JSON array (`[salt, name, value]` or `[salt, value]`)
    /// per the SD-JWT spec - one raw JSON string per disclosure, not one opaque blob.
    public let disclosures: [String]

    public init(header: String?, payload: String?, disclosures: [String]) {
        self.header = header
        self.payload = payload
        self.disclosures = disclosures
    }
}

public enum CredentialUtils {

    private static let jwtSkipKeys: Set<String> = [
        "iss", "sub", "aud", "exp", "nbf", "iat", "jti",
        "_sd", "_sd_alg", "cnf", "vct", "status", "client_status", "type",
    ]

    /// Parse the payload of a JWT (or the JWT part of an SD-JWT).
    public static func parseJwtPayload(_ raw: String) -> [String: Any]? {
        let jwtPart = raw.split(separator: "~", maxSplits: 1).first.map(String.init) ?? raw
        let parts = jwtPart.split(separator: ".")
        guard parts.count >= 2 else { return nil }

        guard let data = base64UrlDecode(String(parts[1])) else {
            #if canImport(os)
            logger.warning("Failed to base64url-decode JWT payload")
            #endif
            return nil
        }

        do {
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return nil
            }
            return json
        } catch {
            #if canImport(os)
            logger.warning("Failed to parse JWT payload: \(error.localizedDescription)")
            #endif
            return nil
        }
    }

    /// Split a raw SD-JWT VC (`<jwt>~<disclosure>~<disclosure>~...`) into its
    /// individually-decoded parts, for display purposes (e.g. a "Raw" debug
    /// tab) - each disclosure is a separate JSON array per the SD-JWT spec, not
    /// part of one opaque blob.
    public static func parseSdJwtParts(_ raw: String) -> SdJwtParts {
        let segments = raw.split(separator: "~", omittingEmptySubsequences: false).map(String.init)
        let jwtSegments = segments.first?.split(separator: ".").map(String.init) ?? []
        let header = jwtSegments.first.flatMap { decodeJsonSegmentText($0) }
        let payload = jwtSegments.count > 1 ? decodeJsonSegmentText(jwtSegments[1]) : nil
        let disclosures = segments.dropFirst()
            .filter { !$0.isEmpty }
            .compactMap { decodeJsonSegmentText($0) }
        return SdJwtParts(header: header, payload: payload, disclosures: disclosures)
    }

    /// Pretty-print a JSON string with 2-space indentation. Returns the input
    /// unchanged if it doesn't parse as JSON - callers can feed arbitrary
    /// claim values through this safely.
    public static func prettyPrintJson(_ text: String) -> String {
        guard let data = text.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let pretty = try? JSONSerialization.data(
                withJSONObject: obj,
                options: [.prettyPrinted, .sortedKeys]
              ),
              let prettyString = String(data: pretty, encoding: .utf8) else {
            return text
        }
        return prettyString
    }

    /// Pretty-print an XML/SVG document with simple per-element indentation.
    ///
    /// This is not a validating parser - it's a light tokenizer good enough to
    /// make a VCTM SVG rendering template (or any other XML blob) readable in
    /// a "Raw"/debug view, mirroring what ``prettyPrintJson(_:)`` does for
    /// JSON. Self-closing tags (`<foo/>`), the XML declaration, and comments
    /// are handled; malformed input degrades to returning the original text
    /// unchanged rather than throwing.
    public static func prettyPrintXml(_ xml: String) -> String {
        var result = ""
        var depth = 0
        var index = xml.startIndex
        while index < xml.endIndex {
            guard let tagStart = xml[index...].firstIndex(of: "<") else {
                let remainder = xml[index...].trimmingCharacters(in: .whitespacesAndNewlines)
                if !remainder.isEmpty { result += remainder }
                break
            }
            let text = xml[index..<tagStart].trimmingCharacters(in: .whitespacesAndNewlines)
            guard let tagEnd = xml[tagStart...].firstIndex(of: ">") else {
                return xml
            }
            let tag = xml[tagStart...tagEnd]
            if !text.isEmpty {
                result += String(repeating: "  ", count: depth) + text + "\n"
            }
            let isClosing = tag.hasPrefix("</")
            let isSelfClosing = tag.hasSuffix("/>") || tag.hasPrefix("<?") || tag.hasPrefix("<!--")
            if isClosing { depth = max(0, depth - 1) }
            result += String(repeating: "  ", count: depth) + tag + "\n"
            if !isClosing && !isSelfClosing { depth += 1 }
            index = xml.index(after: tagEnd)
        }
        return result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Extract user-facing claims from a stored credential.
    ///
    /// VCTM claim paths can be arbitrarily nested (e.g. a diploma's ELM schema
    /// nests everything under `credentialSubject`) - each claim is resolved by
    /// walking its own full path, not just matched by its first segment
    /// against a top-level key.
    public static func extractClaims(_ credential: StoredCredential) -> [DisplayClaim] {
        if credential.format == "mso_mdoc" { return extractMdocClaims(credential) }
        guard let payload = parseJwtPayload(credential.raw) else { return [] }
        let vctmClaims = credential.metadata?.claims ?? []

        let vctmResolved: [DisplayClaim] = vctmClaims.compactMap { claim in
            guard !claim.path.isEmpty, let value = resolveClaimPath(payload, claim.path) else { return nil }
            return DisplayClaim(
                key: claim.path.joined(separator: "."),
                label: claim.label ?? formatClaimKey(claim.path.last ?? ""),
                value: formatClaimValue(value),
                description: claim.description,
                mandatory: claim.mandatory,
                svgId: claim.svgId
            )
        }

        // Top-level keys already resolved (as an ancestor) via a VCTM path
        // shouldn't ALSO be dumped raw - e.g. once "credentialSubject.foo" is
        // resolved, don't separately dump the whole "credentialSubject" blob.
        let coveredTopLevelKeys = Set(vctmClaims.compactMap { $0.path.first })
        let uncovered = payload.keys.sorted().compactMap { key -> DisplayClaim? in
            guard !jwtSkipKeys.contains(key), !coveredTopLevelKeys.contains(key) else { return nil }
            return DisplayClaim(
                key: key,
                label: formatClaimKey(key),
                value: formatClaimValue(payload[key])
            )
        }

        return vctmResolved + uncovered
    }

    /// Walk a VCTM claim path (e.g. `["credentialSubject", "hasClaim", "awardedBy"]`)
    /// through nested JSON to the leaf value it selects. Returns nil if any
    /// segment is missing - the claim just isn't present in this credential.
    private static func resolveClaimPath(_ root: [String: Any], _ path: [String]) -> Any? {
        var current: Any = root
        for segment in path {
            guard let dict = current as? [String: Any], let next = dict[segment] else { return nil }
            current = next
        }
        return current
    }

    /// The credential type the credential itself declares: `vct` for an SD-JWT
    /// VC, `docType` for an mdoc. Nil when it declares none, or cannot be read.
    ///
    /// This is what the holder actually received, as opposed to the credential
    /// configuration ID, which is what the issuer advertised. The two are
    /// checked against each other at issuance, because everything else in the
    /// issuance path — entitlement, type metadata, WSCD selection — keys off
    /// the advertised type, so an issuer that advertises one type and issues
    /// another would have every one of those decisions made about the wrong
    /// credential.
    /// The `vct` a credential declares, read from the credential itself and
    /// only then from its metadata.
    ///
    /// `metadata` is a rendering artefact: it is absent until an issuance flow
    /// has an offer to build it from, and the hydration pass that repopulates
    /// it skips any credential whose metadata is already real. Anything that
    /// decides what a credential *is* must therefore read the credential, or
    /// it will disagree with the issuer about a credential that is perfectly
    /// valid. An mdoc has no `vct` and falls through to the metadata, which is
    /// where a doctype-shaped question belongs instead — see ``declaredType``.
    public static func vctOf(_ credential: StoredCredential) -> String? {
        (parseJwtPayload(credential.raw)?["vct"] as? String) ?? credential.metadata?.vct
    }

    public static func declaredType(format: String, raw: String) -> String? {
        if format == "mso_mdoc" {
            return parseMdocDocument(raw)?.docType
        }
        return parseJwtPayload(raw)?["vct"] as? String
    }

    /// mdoc analogue of ``extractClaims(_:)``: parse a stored mdoc credential's
    /// REAL disclosed namespace/element values (via `MdocCbor`, not
    /// `parseJwtPayload` which assumes a JWT-shaped `raw`) into `DisplayClaim`s,
    /// using MDDL claim metadata (`credential.metadata.claims`, populated by
    /// ``buildMdocMetadata(offer:mddlSchema:)``) for labels/descriptions when available.
    ///
    /// Claim keys/paths use the `["namespace", "elementIdentifier"]` shape,
    /// consistent with how ``buildMdocMetadata(offer:mddlSchema:)`` populates `ClaimMeta.path`.
    /// Decode and parse a stored mdoc credential's raw base64url CBOR into its
    /// `DocumentMdoc` shape (unwrapping the `DeviceResponse`-style envelope
    /// per wallet-frontend#191). Returns nil if the raw string isn't
    /// valid base64url or doesn't parse as an mdoc document.
    public static func parseMdocDocument(_ rawCredential: String) -> DocumentMdoc? {
        guard let bytes = base64UrlDecode(rawCredential) else { return nil }
        do {
            return try MdocCbor.parseStoredCredential([UInt8](bytes))
        } catch {
            #if canImport(os)
            logger.warning("Failed to parse mdoc credential: \(error.localizedDescription)")
            #endif
            return nil
        }
    }

    /// Extract an mdoc credential's data elements as display claims.
    ///
    /// A byte-string data element (e.g. an ISO 18013-5/23220 `portrait`) is
    /// only turned into a displayable image (`DisplayClaim.imageDataUri`,
    /// consumed by `SvgTemplateRenderer` for `svg_templates` cards) when it
    /// is JPEG or PNG. **Issuers must not issue JPEG 2000 portraits if they
    /// want them to render in an SVG card** - this SDK deliberately does not
    /// decode JPEG 2000 (see issue #176 "Decision: JPEG 2000"); a JPEG
    /// 2000 (or any other non-JPEG/PNG) byte string instead renders as `-`
    /// in that card slot (`DisplayClaim.isUndecodableBytes`). An issuer
    /// wanting SVG-card portraits from a JPEG-2000-native pipeline (e.g.
    /// ISO 18013-5's default, or `facetec-api`'s FaceTec capture) must
    /// transcode to JPEG or PNG server-side before issuance.
    public static func extractMdocClaims(_ credential: StoredCredential) -> [DisplayClaim] {
        guard let document = parseMdocDocument(credential.raw) else { return [] }

        var claimMetaByPath: [String: ClaimMeta] = [:]
        for claim in credential.metadata?.claims ?? [] {
            claimMetaByPath[claim.path.joined(separator: "/")] = claim
        }

        return document.issuerSigned.nameSpaces.flatMap { namespace, items in
            items.map { entry -> DisplayClaim in
                let elementId = entry.item.elementIdentifier
                let meta = claimMetaByPath["\(namespace)/\(elementId)"]
                let cborValue = entry.item.elementValue
                var imageUri: String?
                var isUndecodableBytes = false
                if case .byteString(let bytes) = cborValue {
                    imageUri = imageDataUri(bytes)
                    isUndecodableBytes = imageUri == nil
                }
                return DisplayClaim(
                    key: "\(namespace).\(elementId)",
                    label: meta?.label ?? formatClaimKey(elementId),
                    value: formatCborValue(cborValue),
                    description: meta?.description,
                    mandatory: meta?.mandatory ?? false,
                    svgId: meta?.svgId,
                    imageDataUri: imageUri,
                    isUndecodableBytes: isUndecodableBytes
                )
            }
        }
    }

    /// Build `CredentialMetadata` for an mdoc credential from its MDDL schema -
    /// the mdoc analogue of ``buildMetadata(offer:vctm:rawCredential:)``.
    /// Populates `CredentialMetadata.doctype` (unused for SD-JWT credentials)
    /// instead of `CredentialMetadata.vct`.
    public static func buildMdocMetadata(offer: CredentialOffer, mddlSchema: MddlSchema? = nil) -> CredentialMetadata {
        let locale = Locale.current.identifier.replacingOccurrences(of: "_", with: "-")
        let display = mddlSchema?.display.flatMap { displays in
            displays.first(where: { $0.locale == locale })
                ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                ?? displays.first
        }

        let claims: [ClaimMeta]? = mddlSchema?.claims?.flatMap { namespace, elements in
            elements.map { elementId, meta -> ClaimMeta in
                let claimDisplay = meta.display.flatMap { displays in
                    displays.first(where: { $0.locale == locale })
                        ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                        ?? displays.first
                }
                return ClaimMeta(
                    path: [namespace, elementId],
                    label: claimDisplay?.name,
                    mandatory: meta.mandatory,
                    svgId: meta.svgId
                )
            }
        }

        let svgTemplates: [SvgTemplateInfo]? = display?.rendering?.svgTemplates?.map { template in
            SvgTemplateInfo(
                uri: template.uri,
                colorScheme: template.properties?.colorScheme,
                contrast: template.properties?.contrast,
                orientation: template.properties?.orientation
            )
        }

        return CredentialMetadata(
            name: display?.name ?? offer.credentialName,
            description: display?.description ?? offer.credentialDescription,
            issuer: IssuerInfo(name: offer.issuerName, url: offer.credentialIssuerIdentifier),
            doctype: mddlSchema?.doctype,
            backgroundColor: display?.backgroundColor ?? offer.backgroundColor,
            textColor: display?.textColor ?? offer.textColor,
            logo: display?.logo.map { LogoInfo(uri: $0.uri, altText: $0.altText) }
                ?? offer.logoUri.map { LogoInfo(uri: $0) },
            claims: claims,
            svgTemplates: svgTemplates
        )
    }

    /// Format a decoded CBOR element value for display. A byte string always
    /// stays the concise `"<N bytes>"` placeholder here, even when it sniffs
    /// as a displayable image - `DisplayClaim.imageDataUri` (see
    /// `extractMdocClaims`) is the only place the actual
    /// `data:image/...;base64,...` URI is surfaced, so a generic claims list
    /// never has to render an enormous base64 string for a portrait; only
    /// `SvgTemplateRenderer` substitutes the image URI into a rendering card.
    ///
    /// Integrators targeting `svg_templates` cards for mdoc portraits must
    /// issue the underlying byte string as JPEG or PNG - see `imageDataUri`
    /// below for exactly which magic bytes are recognized. JPEG 2000 (the
    /// ISO 18013-5/23220 default) is deliberately NOT decoded by this SDK
    /// (see issue #176 "Decision: JPEG 2000"); an issuer whose portraits are
    /// JPEG 2000 must transcode to JPEG or PNG server-side (e.g.
    /// `facetec-api`'s `issuer.format: mdoc` pipeline does this) before a
    /// wallet using this SDK can render that portrait in an SVG card - it
    /// will otherwise always render as `-` in that slot (`DisplayClaim.isUndecodableBytes`).
    private static func formatCborValue(_ value: CBOR) -> String {
        switch value {
        case .utf8String(let s): return s
        case .byteString(let b): return "<\(b.count) bytes>"
        case .unsignedInt(let n): return String(n)
        case .negativeInt(let n): return String(-1 - Int64(n))
        case .boolean(let b): return b ? "true" : "false"
        case .double(let d): return String(d)
        case .float(let f): return String(f)
        default: return String(describing: value)
        }
    }

    /// Sniffs `bytes` for a JPEG or PNG magic number and, if found, returns a
    /// `data:image/...;base64,...` URI. Returns nil for anything else
    /// (including JPEG 2000, deliberately not decoded - see `formatCborValue`),
    /// so callers fall back to their own non-image placeholder.
    private static func imageDataUri(_ bytes: [UInt8]) -> String? {
        let mimeType: String
        if bytes.count >= 3, bytes[0] == 0xFF, bytes[1] == 0xD8, bytes[2] == 0xFF {
            mimeType = "image/jpeg"
        } else if bytes.count >= 4, bytes[0] == 0x89, bytes[1] == 0x50, bytes[2] == 0x4E, bytes[3] == 0x47 {
            mimeType = "image/png"
        } else {
            return nil
        }
        // Defensive copy: some CBOR decoders can hand back a slice/view into
        // a larger shared buffer rather than a standalone array.
        let base64 = Data(bytes).base64EncodedString()
        return "data:\(mimeType);base64,\(base64)"
    }

    /// Build credential metadata from an offer, optional VCTM, and raw credential.
    public static func buildMetadata(
        offer: CredentialOffer,
        vctm: Vctm? = nil,
        rawCredential: String? = nil
    ) -> CredentialMetadata {
        let locale = Locale.current.identifier.replacingOccurrences(of: "_", with: "-")
        let vctmDisplay = vctm?.display.flatMap { displays in
            displays.first(where: { $0.locale == locale })
                ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                ?? displays.first
        }

        let simple = vctmDisplay?.rendering?.simple

        let payload = rawCredential.flatMap { parseJwtPayload($0) }
        let vct = payload?["vct"] as? String

        let claims: [ClaimMeta]? = vctm?.claims?.map { claim in
            let claimDisplay = claim.display.flatMap { displays in
                displays.first(where: { $0.locale == locale })
                    ?? displays.first(where: { $0.locale.hasPrefix(String(locale.prefix(2))) })
                    ?? displays.first
            }
            return ClaimMeta(
                path: claim.path.compactMap { $0 },
                label: claimDisplay?.label,
                description: claimDisplay?.description,
                sd: claim.sd,
                mandatory: claim.mandatory ?? false,
                svgId: claim.svgId
            )
        }

        let svgTemplates: [SvgTemplateInfo]? = vctmDisplay?.rendering?.svgTemplates?.map { template in
            SvgTemplateInfo(
                uri: template.uri,
                colorScheme: template.properties?.colorScheme,
                contrast: template.properties?.contrast,
                orientation: template.properties?.orientation
            )
        }

        return CredentialMetadata(
            name: vctmDisplay?.name ?? offer.credentialName,
            description: vctmDisplay?.description ?? offer.credentialDescription,
            issuer: IssuerInfo(
                name: offer.issuerName,
                url: offer.credentialIssuerIdentifier
            ),
            vct: vct,
            backgroundColor: simple?.backgroundColor ?? offer.backgroundColor,
            textColor: simple?.textColor ?? offer.textColor,
            logo: simple?.logo.map { LogoInfo(uri: $0.uri, altText: $0.altText) }
                ?? offer.logoUri.map { LogoInfo(uri: $0) },
            claims: claims,
            svgTemplates: svgTemplates
        )
    }

    /// Format a snake_case or kebab-case key as a human-readable label.
    public static func formatClaimKey(_ key: String) -> String {
        key.split(omittingEmptySubsequences: true, whereSeparator: { $0 == "_" || $0 == "-" })
            .map { $0.prefix(1).uppercased() + $0.dropFirst() }
            .joined(separator: " ")
    }

    // MARK: - Private

    private static func decodeJsonSegmentText(_ base64url: String) -> String? {
        guard let data = base64UrlDecode(base64url),
              let obj = try? JSONSerialization.jsonObject(with: data),
              let reencoded = try? JSONSerialization.data(withJSONObject: obj),
              let text = String(data: reencoded, encoding: .utf8) else {
            return nil
        }
        return text
    }

    /// Module-internal rather than private: SharedDcqlMatcher formats claim
    /// values for DCQL `values` comparison, and a second formatter would mean
    /// the same claim rendering differently to the matcher than to the user.
    static func formatClaimValue(_ value: Any?) -> String {
        switch value {
        case let s as String: return s
        // Booleans first, and by CFTypeID rather than by cast. `JSONSerialization`
        // bridges a JSON boolean to `__NSCFBoolean`, which *is* an `NSNumber`, so
        // an `as NSNumber` case reached first renders `true` as "1". A plain
        // `as? Bool` test is no better in the other direction: it succeeds for the
        // number 1, rendering it "true" - verified, not assumed. Only the type
        // identity separates them.
        //
        // This is not cosmetic. DCQL compares a requested `values` entry against
        // this string, so `age_over_18: true` matching "1" fails and the
        // credential is not offered.
        case let n as NSNumber where CFGetTypeID(n) == CFBooleanGetTypeID():
            return n.boolValue ? "true" : "false"
        case let n as NSNumber: return n.stringValue
        case let b as Bool: return b ? "true" : "false"
        default: return String(describing: value ?? "")
        }
    }

    /// Decode a base64url (no padding) string, restoring the `=` padding
    /// `Data(base64Encoded:)` requires - a bare `-`/`_` substitution without
    /// restoring padding silently returns nil for any input whose length
    /// isn't already a multiple of 4.
    public static func base64UrlDecode(_ string: String) -> Data? {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }

    /// Group stored credentials into display-ready families, mirroring
    /// wallet-frontend's `CredentialsContextProvider.fetchVcData`: only the
    /// `instanceId == 0` credential of a batch (see `StoredCredential.batchId`)
    /// is returned as a visible entry, with every sibling copy's usage count
    /// attached as `CredentialWithInstances.instances` - the UI derives its
    /// "remaining copies" badge from `instances.count { $0.sigCount == 0 }`.
    ///
    /// Every issuance response - batch of one or of many - shares one
    /// `batchId`, so grouping is uniform: no separate "standalone" case,
    /// matching wallet-frontend exactly.
    public static func groupForDisplay(
        credentials: [StoredCredential],
        presentationHistory: [PresentationRecord]
    ) -> [CredentialWithInstances] {
        func sigCount(for credentialId: Int64) -> Int {
            presentationHistory.filter { $0.credentialIds.contains(credentialId) }.count
        }

        var byBatch: [Int64: [StoredCredential]] = [:]
        for credential in credentials {
            byBatch[credential.batchId, default: []].append(credential)
        }

        let results: [CredentialWithInstances] = byBatch.values.compactMap { members in
            guard let visible = members.first(where: { $0.instanceId == 0 }) else { return nil }
            let instances = members
                .sorted(by: { $0.instanceId < $1.instanceId })
                .map { CredentialInstance(instanceId: $0.instanceId, sigCount: sigCount(for: $0.id)) }
            return CredentialWithInstances(credential: visible, instances: instances)
        }

        return results.sorted(by: { ($0.credential.issuedAt ?? 0) > ($1.credential.issuedAt ?? 0) })
    }

    /// True for `"mso_mdoc_zk"` - a real ZKP predicate-proof format now exists
    /// (`LongfellowZkProofSystem`, wired into `SirosWallet.handleDCAPIRequest`
    /// and the engine's `sign_presentation` ZK branch), unlike every other
    /// format this SDK supports, which discloses via salted-hash element
    /// digests (mdoc's MSO, SD-JWT's `_sd` array).
    ///
    /// Note this checks a *requested/presented* format, not necessarily
    /// `StoredCredential.format` - a ZK presentation is a presentation-time
    /// transform of an ordinarily-stored `"mso_mdoc"` credential (see
    /// `CredentialMatcher.matchesFormat`'s doc comment), so the stored
    /// instance's own format is never `"mso_mdoc_zk"`. Callers that know
    /// which *query* format matched a given instance for the presentation in
    /// progress should pass that via ``eligibleInstances(instances:policy:presentationHistory:availableKeyIds:isZkPresentation:)``'s
    /// `isZkPresentation` parameter rather than relying on that function's
    /// default fallback of checking `StoredCredential.format` directly
    /// (which - for exactly the reason above - never returns true).
    ///
    /// Public (Kotlin keeps it private) only because a public function's
    /// default argument can't reference a less-visible symbol in Swift, and
    /// so the wallet's own "which matched queries are ZK" derivation shares
    /// this one string comparison instead of repeating it.
    public static func isZkpFormat(_ format: String) -> Bool {
        format.caseInsensitiveCompare("mso_mdoc_zk") == .orderedSame
    }

    /// Instances from `instances` (all copies of one batch - see
    /// `StoredCredential.batchId`) that are still allowed to be used for a
    /// NEW presentation under `policy`, given what `presentationHistory`
    /// shows has already been presented. Mirrors ``groupForDisplay(credentials:presentationHistory:)``'s
    /// own `sigCount` usage-counting exactly, so "eligible" and the
    /// "remaining copies" ribbon never disagree.
    ///
    /// ``CredentialConsumptionPolicy/neverConsume`` (the default - today's
    /// actual behavior) skips the usage check, but every policy still
    /// requires the instance's bound signing key to actually exist in
    /// `availableKeyIds` - a real, recurring bug found via live testing: a
    /// software key only ever lives in the WSCD's process memory plus
    /// whatever was last folded into the persisted container, so a lost
    /// sync (or, per privatedata-spec#1/siros-wscd-manager#68, a concurrent-
    /// write merge conflict on the legacy, non-namespaced `S.keypairs`
    /// field) can silently strand a credential with no usable key. Without
    /// this check, `neverConsume` made every such credential report
    /// "available" forever, right up until a live presentation attempt
    /// failed deep inside key selection with no user-facing signal at all.
    /// See `hasAvailableKey` for how a nil `StoredCredential.kid` is handled.
    ///
    /// Otherwise, an instance is eligible only if it hasn't already been
    /// presented (`sigCount == 0`) - each instance is bound to its own device
    /// key specifically so a verifier can't correlate repeated presentations
    /// by a reused key/signature; reusing an already-presented instance would
    /// throw that guarantee away.
    ///
    /// - Parameter isZkPresentation: Whether presenting `instances`' given
    ///   member THIS time will be a ZK proof rather than a raw disclosure -
    ///   defaults to checking `StoredCredential.format` via `isZkpFormat`
    ///   (which, per that function's own doc comment, is never true, since
    ///   ZK-ness lives in the matched DCQL query's format, not the stored
    ///   credential's). Callers that know the matched query format for each
    ///   candidate (e.g. `SirosWallet.handleDCAPIRequest`) should pass a real
    ///   resolver so ``CredentialConsumptionPolicy/consumeNonZkp`` actually
    ///   distinguishes ZK presentations (never consumed) from raw ones
    ///   (consumed).
    public static func eligibleInstances(
        instances: [StoredCredential],
        policy: CredentialConsumptionPolicy,
        presentationHistory: [PresentationRecord],
        availableKeyIds: Set<String>,
        isZkPresentation: (StoredCredential) -> Bool = { isZkpFormat($0.format) }
    ) -> [StoredCredential] {
        // A single pass building this set, rather than rescanning all of
        // presentationHistory per instance (O(instances x history) before),
        // matters once either grows - this can run on every UI update.
        var usedCredentialIds: Set<Int64> = []
        for record in presentationHistory {
            usedCredentialIds.formUnion(record.credentialIds)
        }
        return instances.filter { instance in
            let keyAvailable = hasAvailableKey(instance.kid, availableKeyIds)
            let consumptionEligible: Bool
            if policy == .neverConsume {
                consumptionEligible = true
            } else {
                let consumes = policy == .consumeAll || !isZkPresentation(instance)
                consumptionEligible = !consumes || !usedCredentialIds.contains(instance.id)
            }
            return keyAvailable && consumptionEligible
        }
    }

    /// Whether `kid` (a `StoredCredential.kid`) can actually be used to sign,
    /// given the signer's current `availableKeyIds` - the single rule behind
    /// `eligibleInstances`' key gate, so nothing else in the SDK gets to
    /// disagree about whether a credential is really usable.
    ///
    /// A nil `kid` can't be matched against a specific entry, but every
    /// credential issued through the current per-credential-key architecture
    /// gets a kid at storage time - a real `StoredCredential` with a nil kid
    /// reaching here is a sign its binding was silently lost (e.g. a
    /// concurrent-flow race), not a legitimate legacy case. The best check
    /// still possible without a specific kid to match is whether the signer
    /// holds *any* key at all; with zero keys, a nil-kid credential is
    /// certain to fail to sign exactly like a known-but-missing kid would.
    private static func hasAvailableKey(_ kid: String?, _ availableKeyIds: Set<String>) -> Bool {
        if let kid { return availableKeyIds.contains(kid) }
        return !availableKeyIds.isEmpty
    }

    /// Below this many eligible (unused) instances remaining, the UI should
    /// offer to renew/re-issue the credential rather than let it silently run
    /// out. Not user-configurable in this pass - just the stated default.
    public static let renewThreshold = 0

    /// True when `instances`' eligible (unused) count under `policy`/
    /// `presentationHistory`/`availableKeyIds` has dropped to or below
    /// `threshold` - the proactive-renewal trigger (plan §4.3). Note
    /// `CredentialConsumptionPolicy.neverConsume` makes `eligibleInstances`
    /// return every instance whose key still exists, so this only ever fires
    /// under a consuming policy or once keys go missing.
    public static func isBelowRenewThreshold(
        instances: [StoredCredential],
        policy: CredentialConsumptionPolicy,
        presentationHistory: [PresentationRecord],
        availableKeyIds: Set<String>,
        threshold: Int = renewThreshold
    ) -> Bool {
        eligibleInstances(
            instances: instances,
            policy: policy,
            presentationHistory: presentationHistory,
            availableKeyIds: availableKeyIds
        ).count <= threshold
    }

    /// Compares two versions of the same credential's claims (by `key`, not
    /// list position - VCTM claim ordering isn't guaranteed stable across a
    /// renewal) and reports what changed, matching Kotlin's
    /// `CredentialUtils.computeAttributeDiff` exactly.
    public static func computeAttributeDiff(before: [DisplayClaim], after: [DisplayClaim]) -> CredentialAttributeDiff {
        // `extractClaims` can produce duplicate `DisplayClaim.key` values
        // (e.g. duplicated VCTM paths) - `Dictionary(uniqueKeysWithValues:)`
        // traps at runtime on a duplicate key, so a renewal could crash the
        // app while diffing claims. `uniquingKeysWith` (keeping the first
        // occurrence, deterministically) tolerates that instead of crashing.
        let beforeByKey = Dictionary(before.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
        let afterByKey = Dictionary(after.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
        let changed: [AttributeChange] = afterByKey.keys.filter { beforeByKey[$0] != nil }.compactMap { key in
            guard let old = beforeByKey[key], let new = afterByKey[key], old.value != new.value else { return nil }
            return AttributeChange(key: key, label: new.label, oldValue: old.value, newValue: new.value)
        }
        let added = afterByKey.keys.filter { beforeByKey[$0] == nil }.map { afterByKey[$0]! }
        let removed = beforeByKey.keys.filter { afterByKey[$0] == nil }.map { beforeByKey[$0]! }
        return CredentialAttributeDiff(changed: changed, added: added, removed: removed)
    }

    /// Group stored credentials into one ``CredentialFamily`` per
    /// `StoredCredential.batchId`, for callers (mdoc proximity consent) that
    /// need every instance's full `StoredCredential` - not just its usage
    /// count, as ``groupForDisplay(credentials:presentationHistory:)``'s
    /// `CredentialInstance` carries - because a proximity session signs with
    /// whichever approved instance it picks.
    ///
    /// Uses the same convention as `groupForDisplay`: a batch is only
    /// representable if it has an `instanceId == 0` member; a batch missing
    /// one is skipped rather than falling back to an arbitrary member, so
    /// the two grouping functions never disagree about which batches are
    /// representable.
    public static func groupIntoFamilies(_ credentials: [StoredCredential]) -> [CredentialFamily] {
        var byBatch: [Int64: [StoredCredential]] = [:]
        for credential in credentials {
            byBatch[credential.batchId, default: []].append(credential)
        }
        return byBatch.values.compactMap { members in
            guard let representative = members.first(where: { $0.instanceId == 0 }) else { return nil }
            return CredentialFamily(representative: representative, instances: members)
        }
    }
}

/// Governs whether a successful presentation exhausts the specific credential
/// instance it used, so that instance can never be presented again.
///
/// Defaults to ``neverConsume`` - today's actual behavior - so introducing
/// this setting doesn't silently change existing wallets' behavior.
public enum CredentialConsumptionPolicy: String, Sendable, CaseIterable {
    /// Every successful presentation exhausts the instance it used, regardless of format.
    case consumeAll

    /// A raw disclosure exhausts the instance; a ZK proof of it does not, since
    /// the verifier learns nothing that links two proofs. Which of the two a
    /// presentation is comes from the matched query's format - see the
    /// `isZkPresentation` parameter of `CredentialUtils.eligibleInstances`.
    case consumeNonZkp

    /// Instances are never exhausted - a presentation may reuse any matching instance.
    case neverConsume
}

/// One member of a batch-issued credential family, alongside its usage count.
public struct CredentialInstance: Sendable, Equatable {
    public let instanceId: Int
    public let sigCount: Int

    public init(instanceId: Int, sigCount: Int) {
        self.instanceId = instanceId
        self.sigCount = sigCount
    }
}

/// A visible credential card plus every instance in its batch (see `CredentialUtils.groupForDisplay`).
public struct CredentialWithInstances: Sendable, Equatable {
    public let credential: StoredCredential
    public let instances: [CredentialInstance]

    public init(credential: StoredCredential, instances: [CredentialInstance]) {
        self.credential = credential
        self.instances = instances
    }
}

/// One credential "type" as the user should see it: every `StoredCredential`
/// instance sharing a `StoredCredential.batchId` is the SAME credential from
/// a batch issuance (see `CredentialUtils.groupForDisplay`'s doc comment for
/// why - each instance is bound to its own device key purely for
/// unlinkability, not a distinct credential the user chose to hold multiple
/// of). A proximity consent prompt must offer one choice per family, never
/// one per raw instance, or a 5-instance batch reads as "you have 5 driver's
/// licenses." See `CredentialUtils.groupIntoFamilies`.
public struct CredentialFamily: Sendable, Equatable {
    /// The instance shown to the user for display (matches
    /// `CredentialUtils.groupForDisplay`'s convention of the `instanceId == 0` member).
    public let representative: StoredCredential
    /// Every instance in this batch - the proximity session picks one of these to actually sign with once the family is approved.
    public let instances: [StoredCredential]

    public init(representative: StoredCredential, instances: [StoredCredential]) {
        self.representative = representative
        self.instances = instances
    }
}
