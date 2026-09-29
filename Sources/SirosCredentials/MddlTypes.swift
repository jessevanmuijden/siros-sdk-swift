// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// MDDL (mso_mdoc) schema type: the mdoc analogue of `Vctm`, mirroring
/// `sirosfoundation/vc`'s `pkg/mdoc/schema.go` `MDDLSchema` field-for-field.
/// Drives mdoc issuance server-side and, here, gives the wallet a uniform way
/// to get display labels/claim metadata for mdoc credentials regardless of
/// format - the same role VCTM plays for SD-JWT.
public struct MddlSchema: Codable, Sendable, Equatable {
    public let format: String
    public let doctype: String
    public let display: [MddlDisplay]?
    public let claims: [String: [String: MddlClaimMeta]]?

    /// Minimum key-storage assurance tier a WSCD plugin must meet before the
    /// wallet generates issuance keys for this credential type - the mdoc
    /// analogue of `Vctm.requiredKeyStorage`; see its doc comment for the
    /// ISO 18045 vocabulary and `nil` semantics.
    public let requiredKeyStorage: String?

    public init(
        format: String,
        doctype: String,
        display: [MddlDisplay]? = nil,
        claims: [String: [String: MddlClaimMeta]]? = nil,
        requiredKeyStorage: String? = nil
    ) {
        self.format = format
        self.doctype = doctype
        self.display = display
        self.claims = claims
        self.requiredKeyStorage = requiredKeyStorage
    }

    enum CodingKeys: String, CodingKey {
        case format, doctype, display, claims
        case requiredKeyStorage = "attestation_los"
    }
}

/// Localized display info for an MDDL schema, mirroring `MDDLSchema.Display`.
public struct MddlDisplay: Codable, Sendable, Equatable {
    public let locale: String
    public let name: String
    public let description: String?
    public let logo: MddlLogo?
    public let backgroundColor: String?
    public let textColor: String?
    /// SVG rendering info, mirroring `DisplayProperties.Rendering`.
    public let rendering: MddlRendering?

    public init(
        locale: String,
        name: String,
        description: String? = nil,
        logo: MddlLogo? = nil,
        backgroundColor: String? = nil,
        textColor: String? = nil,
        rendering: MddlRendering? = nil
    ) {
        self.locale = locale
        self.name = name
        self.description = description
        self.logo = logo
        self.backgroundColor = backgroundColor
        self.textColor = textColor
        self.rendering = rendering
    }

    enum CodingKeys: String, CodingKey {
        case locale, name, description, logo, rendering
        case backgroundColor = "background_color"
        case textColor = "text_color"
    }
}

public struct MddlLogo: Codable, Sendable, Equatable {
    public let uri: String?
    public let altText: String?

    public init(uri: String? = nil, altText: String? = nil) {
        self.uri = uri
        self.altText = altText
    }

    enum CodingKeys: String, CodingKey {
        case uri
        case altText = "alt_text"
    }
}

/// SVG-based rendering information for an MDDL display entry, mirroring
/// `mdoc.Rendering` (`pkg/mdoc/schema.go`). mdoc has no "simple" rendering
/// sub-object to mirror VCTM's `VctmRendering.simple` - logo/colors already
/// live directly on `MddlDisplay`.
public struct MddlRendering: Codable, Sendable, Equatable {
    public let svgTemplates: [MddlSvgTemplate]?

    public init(svgTemplates: [MddlSvgTemplate]? = nil) {
        self.svgTemplates = svgTemplates
    }

    enum CodingKeys: String, CodingKey {
        case svgTemplates = "svg_templates"
    }
}

public struct MddlSvgTemplate: Codable, Sendable, Equatable {
    public let uri: String
    public let properties: MddlSvgProperties?

    public init(uri: String, properties: MddlSvgProperties? = nil) {
        self.uri = uri
        self.properties = properties
    }
}

public struct MddlSvgProperties: Codable, Sendable, Equatable {
    public let orientation: String?
    public let colorScheme: String?
    public let contrast: String?

    public init(orientation: String? = nil, colorScheme: String? = nil, contrast: String? = nil) {
        self.orientation = orientation
        self.colorScheme = colorScheme
        self.contrast = contrast
    }

    enum CodingKeys: String, CodingKey {
        case orientation, contrast
        case colorScheme = "color_scheme"
    }
}

/// Metadata for a single mdoc data element within a namespace, mirroring
/// `ClaimMetadata` in `pkg/mdoc/schema.go`. `elements` describes nested
/// item/field shape for container (`array`/`map`) claims like
/// `driving_privileges`.
public struct MddlClaimMeta: Codable, Sendable, Equatable {
    public let display: [MddlClaimDisplay]?
    public let mandatory: Bool
    public let valueType: String?
    public let elements: [String: MddlClaimMeta]?
    /// SVG template placeholder ID this claim fills, if any.
    public let svgId: String?

    public init(
        display: [MddlClaimDisplay]? = nil,
        mandatory: Bool = false,
        valueType: String? = nil,
        elements: [String: MddlClaimMeta]? = nil,
        svgId: String? = nil
    ) {
        self.display = display
        self.mandatory = mandatory
        self.valueType = valueType
        self.elements = elements
        self.svgId = svgId
    }

    enum CodingKeys: String, CodingKey {
        case display, mandatory, elements
        case valueType = "value_type"
        case svgId = "svg_id"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        display = try container.decodeIfPresent([MddlClaimDisplay].self, forKey: .display)
        mandatory = try container.decodeIfPresent(Bool.self, forKey: .mandatory) ?? false
        valueType = try container.decodeIfPresent(String.self, forKey: .valueType)
        elements = try container.decodeIfPresent([String: MddlClaimMeta].self, forKey: .elements)
        svgId = try container.decodeIfPresent(String.self, forKey: .svgId)
    }
}

public struct MddlClaimDisplay: Codable, Sendable, Equatable {
    public let locale: String
    public let name: String

    public init(locale: String, name: String) {
        self.locale = locale
        self.name = name
    }
}
