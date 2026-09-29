// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Substitutes VCTM claim values into an SVG rendering template.
///
/// VCTM's `rendering.svg_templates` (section 6) points at an SVG image; claims
/// with a `svg_id` are meant to fill placeholders inside it. In practice (e.g.
/// the dc4eu/vc image set used by real EUDI-style issuers) this is plain
/// Mustache-style text substitution - `{{claimSvgId}}` tokens inside `<text>`
/// elements - not DOM/id-attribute editing, so this is pure string
/// replacement, platform-agnostic and unit-testable without any UI framework.
public enum SvgTemplateRenderer {

    private static let unmatchedToken = try! NSRegularExpression(pattern: "\\{\\{[^}]*\\}\\}")

    /// Replace every `{{claim.svgId}}` token in `svgTemplate` with that claim's
    /// resolved, XML-escaped value. Any token left over (a claim the VCTM
    /// defines but that isn't present in this particular credential) is
    /// blanked rather than shown to the user literally.
    ///
    /// A claim carrying `imageDataUri` (a byte-string that decoded to a
    /// displayable image - see `CredentialUtils.extractMdocClaims`)
    /// substitutes that URI rather than its concise `value` placeholder.
    /// A claim marked `isUndecodableBytes` (a byte string present but not
    /// recognized as an image, e.g. JPEG 2000) renders as `-` instead -
    /// showing a byte count where an image was expected would be more
    /// confusing than an explicit "not shown" marker. Note these two fields
    /// are read directly rather than inferred from `value`'s text: a
    /// legitimate text claim could otherwise coincidentally equal
    /// `formatCborValue`'s placeholder shape (e.g. a claim literally valued
    /// `"<12 bytes>"`) and be misclassified.
    public static func substitute(_ svgTemplate: String, claims: [DisplayClaim]) -> String {
        var result = svgTemplate
        for claim in claims {
            guard let id = claim.svgId else { continue }
            let value: String
            if let imageDataUri = claim.imageDataUri {
                value = imageDataUri
            } else if claim.isUndecodableBytes {
                value = "-"
            } else {
                value = claim.value
            }
            result = result.replacingOccurrences(of: "{{\(id)}}", with: escapeXml(value))
        }
        let range = NSRange(result.startIndex..., in: result)
        result = unmatchedToken.stringByReplacingMatches(in: result, range: range, withTemplate: "")
        return result
    }

    /// Escape characters that are special in XML text content/attributes.
    public static func escapeXml(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }
}
