// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(ImageIO)
import Foundation
import CoreGraphics
import ImageIO
import SwiftDraw

/// Deny-by-default gate in front of SwiftDraw. SwiftDraw 0.29.0 trapped or
/// recursed without bound on five different inputs we found by testing
/// (self-referencing pattern/mask, nested `<svg>`, huge dimensions in
/// attributes and in `style`, WOFF fonts reached through `@font-face` with
/// `url (` / `u/**/rl(` spellings), so a denylist cannot be trusted: the
/// document is accepted only if every element, attribute and value is on the
/// lists below, and anything not understood is refused (never repaired).
///
/// Supported: `svg` (root only), `g`, `defs`, `title`, `desc`, `path`, `rect`,
/// `circle`, `ellipse`, `line`, `polyline`, `polygon`, `linearGradient`,
/// `radialGradient`, `stop`, `clipPath`; geometry, paint (colour, `none`,
/// `currentColor`, `url(#id)`), stroke, opacity, transform, `clip-path` and
/// gradient attributes with validated grammar; `#fragment` hrefs on gradients.
/// Not supported: `style` attributes and `<style>`, text/fonts, `use`,
/// `image`, `pattern`, `mask`, `filter`, `marker`, `switch`, `symbol`,
/// animation, scripts, `foreignObject`, links, DOCTYPE/entities, namespaced
/// elements or attributes (other than the SVG/xlink declarations).
enum SvgActiveContentGuard {
    static let allowedElements: Set<String> = [
        "svg", "g", "defs", "title", "desc", "path", "rect", "circle", "ellipse", "line", "polyline",
        "polygon", "linearGradient", "radialGradient", "stop", "clipPath",
    ]

    /// Bounds on document complexity (the byte cap alone allows ~25k elements).
    static let maxElements = 5000
    static let maxDepth = 64

    /// Largest magnitude accepted for any number. SwiftDraw traps (Float to
    /// Int) on values like `1e30` in sizes, before any check of ours could run.
    static let maxSvgNumber = 1_000_000.0

    // MARK: Value grammar (every pattern is anchored; nothing outside it passes)

    private static func re(_ pattern: String) -> NSRegularExpression {
        // swiftlint:disable:next force_try
        try! NSRegularExpression(pattern: pattern)
    }
    private static let numberPattern = "[+-]?(?:\\d+\\.?\\d*|\\.\\d+)(?:[eE][+-]?\\d+)?"
    private static let lengthPattern = re("^(" + numberPattern + ")(px|pt|pc|mm|cm|in|em|ex|%)?$")
    private static let numberRe = re("^" + numberPattern + "$")
    private static let idPattern = "[A-Za-z_][A-Za-z0-9_.:-]{0,63}"
    private static let idRe = re("^" + idPattern + "$")
    private static let fragmentRe = re("^#" + idPattern + "$")
    private static let hexColorRe = re("^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")
    private static let rgbRe = re("^rgba?\\(\\s*[0-9.%]+(?:\\s*,\\s*[0-9.%]+){2,3}\\s*\\)$")
    private static let namedColorRe = re("^[A-Za-z]{3,20}$")
    private static let paintUrlRe = re("^url\\(#" + idPattern + "\\)$")
    private static let pathDataRe = re("^[MmZzLlHhVvCcSsQqTtAa0-9eE+\\-.,\\s]{1,100000}$")
    private static let transformRe = re(
        "^\\s*(?:(?:matrix|translate|scale|rotate|skewX|skewY)\\s*\\([0-9eE+\\-.,\\s]{0,200}\\)\\s*,?\\s*){1,16}$")
    private static let aspectRe = re("^(?:none|x(?:Min|Mid|Max)Y(?:Min|Mid|Max))(?: (?:meet|slice))?$")

    private static func matches(_ r: NSRegularExpression, _ v: String) -> Bool {
        r.firstMatch(in: v, range: NSRange(v.startIndex..., in: v)) != nil
    }

    private static func isNumber(_ v: String) -> Bool {
        guard matches(numberRe, v), let d = Double(v), d.isFinite else { return false }
        return abs(d) <= maxSvgNumber
    }

    /// A number-list separated by spaces and/or commas.
    private static func isNumberList(_ v: String, max count: Int = 10_000) -> Bool {
        let parts = v.split(whereSeparator: { " ,\t\r\n".contains($0) })
        return !parts.isEmpty && parts.count <= count && parts.allSatisfy { isNumber(String($0)) }
    }

    private static func isLengthList(_ v: String) -> Bool {
        let parts = v.split(whereSeparator: { " ,\t\r\n".contains($0) })
        return !parts.isEmpty && parts.count <= 64 && parts.allSatisfy { lengthProblem(String($0)) == nil }
    }

    private static func isOpacity(_ v: String) -> Bool {
        let t = v.trimmingCharacters(in: .whitespaces)
        if t.hasSuffix("%") { return isNumber(String(t.dropLast())) }
        return isNumber(t)
    }

    static func isColor(_ v: String) -> Bool {
        let t = v.trimmingCharacters(in: .whitespaces)
        return ["none", "currentColor"].contains(t) || matches(hexColorRe, t) || matches(rgbRe, t) || matches(namedColorRe, t)
    }

    /// `none`, a colour, `url(#id)`, or `url(#id) <colour>`: no whitespace inside
    /// `url(`, no comments, no external or data: URLs.
    static func isPaint(_ v: String) -> Bool {
        let t = v.trimmingCharacters(in: .whitespaces)
        if isColor(t) { return true }
        if matches(paintUrlRe, t) { return true }
        guard t.hasPrefix("url("), let close = t.firstIndex(of: ")") else { return false }
        let url = String(t[...close])
        let rest = t[t.index(after: close)...].trimmingCharacters(in: .whitespaces)
        return matches(paintUrlRe, url) && isColor(rest)
    }

    private static func isEnum(_ v: String, _ values: [String]) -> Bool { values.contains(v.trimmingCharacters(in: .whitespaces)) }

    /// A CSS/SVG length: number, optional unit, magnitude within `maxSvgNumber`.
    static func lengthProblem(_ raw: String) -> LogoRejection? {
        let v = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let m = lengthPattern.firstMatch(in: v, range: NSRange(v.startIndex..., in: v)),
              let r = Range(m.range(at: 1), in: v), let d = Double(v[r]), d.isFinite
        else { return .invalidSvg }
        return abs(d) > maxSvgNumber ? .dimensionsTooLarge : nil
    }

    /// Validators for the attributes that may appear on any allowed element.
    private static let attributeValidators: [String: (String) -> Bool] = [
        "id": { matches(idRe, $0) },
        "x": { lengthProblem($0) == nil }, "y": { lengthProblem($0) == nil },
        "width": { lengthProblem($0) == nil }, "height": { lengthProblem($0) == nil },
        "cx": { lengthProblem($0) == nil }, "cy": { lengthProblem($0) == nil }, "r": { lengthProblem($0) == nil },
        "rx": { lengthProblem($0) == nil }, "ry": { lengthProblem($0) == nil },
        "x1": { lengthProblem($0) == nil }, "y1": { lengthProblem($0) == nil },
        "x2": { lengthProblem($0) == nil }, "y2": { lengthProblem($0) == nil },
        "fx": { lengthProblem($0) == nil }, "fy": { lengthProblem($0) == nil }, "fr": { lengthProblem($0) == nil },
        "offset": { lengthProblem($0) == nil },
        "points": { isNumberList($0) },
        "d": { matches(pathDataRe, $0) },
        "transform": { matches(transformRe, $0) }, "gradientTransform": { matches(transformRe, $0) },
        "viewBox": { isNumberList($0, max: 4) && $0.split(whereSeparator: { " ,\t\r\n".contains($0) }).count == 4 },
        "preserveAspectRatio": { matches(aspectRe, $0) },
        "version": { isEnum($0, ["1.0", "1.1", "2.0"]) },
        "fill": isPaint, "stroke": isPaint,
        "stop-color": isColor, "color": isColor,
        "stroke-width": { lengthProblem($0) == nil },
        "stroke-linecap": { isEnum($0, ["butt", "round", "square"]) },
        "stroke-linejoin": { isEnum($0, ["miter", "round", "bevel"]) },
        "stroke-miterlimit": isNumber,
        "stroke-dasharray": { $0.trimmingCharacters(in: .whitespaces) == "none" || isLengthList($0) },
        "stroke-dashoffset": { lengthProblem($0) == nil },
        "fill-rule": { isEnum($0, ["nonzero", "evenodd"]) }, "clip-rule": { isEnum($0, ["nonzero", "evenodd"]) },
        "opacity": isOpacity, "fill-opacity": isOpacity, "stroke-opacity": isOpacity, "stop-opacity": isOpacity,
        "clip-path": { $0.trimmingCharacters(in: .whitespaces) == "none" || matches(paintUrlRe, $0.trimmingCharacters(in: .whitespaces)) },
        "display": { isEnum($0, ["inline", "none"]) },
        "gradientUnits": { isEnum($0, ["userSpaceOnUse", "objectBoundingBox"]) },
        "clipPathUnits": { isEnum($0, ["userSpaceOnUse", "objectBoundingBox"]) },
        "spreadMethod": { isEnum($0, ["pad", "reflect", "repeat"]) },
    ]

    /// nil when the SVG may be rasterized, otherwise why not.
    static func check(_ data: Data) -> LogoRejection? {
        // DOCTYPE/ENTITY: refused up front (also catches declarations the
        // parser would not report). A false positive inside a comment is fine.
        let text = String(decoding: data, as: UTF8.self).lowercased()
        if text.contains("<!doctype") || text.contains("<!entity") { return .activeContent }

        let delegate = Delegate()
        let parser = XMLParser(data: data)
        parser.delegate = delegate
        parser.shouldResolveExternalEntities = false
        parser.shouldProcessNamespaces = false
        parser.shouldReportNamespacePrefixes = false
        let ok = parser.parse()
        if let refusal = delegate.refusal { return refusal }
        if !ok || !delegate.sawSvgRoot { return .invalidSvg }
        return nil
    }

    /// nil when one element's attributes are all allowed with valid values.
    static func attributeProblem(element: String, _ attrs: [String: String], isRoot: Bool) -> LogoRejection? {
        for (key, value) in attrs {
            switch key {
            case "xmlns":
                guard isRoot, value == "http://www.w3.org/2000/svg" else { return .activeContent }
            case "xmlns:xlink":
                guard isRoot, value == "http://www.w3.org/1999/xlink" else { return .activeContent }
            case "href", "xlink:href":
                // Same-document gradient inheritance only.
                guard ["linearGradient", "radialGradient"].contains(element),
                      matches(fragmentRe, value) else { return .activeContent }
            case "width", "height", "viewBox":
                if isRoot && key != "viewBox" { if let bad = lengthProblem(value) { return bad } }
                guard attributeValidators[key]?(value) == true else { return .invalidSvg }
                if key == "viewBox", let bad = viewBoxProblem(value) { return bad }
            default:
                guard let validate = attributeValidators[key], validate(value) else { return .activeContent }
            }
        }
        return nil
    }

    /// viewBox: four finite numbers, positive size.
    static func viewBoxProblem(_ raw: String) -> LogoRejection? {
        let nums = raw.split(whereSeparator: { " ,\t\r\n".contains($0) }).compactMap { Double($0) }
        guard nums.count == 4, nums.allSatisfy({ $0.isFinite }) else { return .invalidSvg }
        if nums.contains(where: { abs($0) > maxSvgNumber }) { return .dimensionsTooLarge }
        return nums[2] <= 0 || nums[3] <= 0 ? .invalidSvg : nil
    }

    private final class Delegate: NSObject, XMLParserDelegate {
        var refusal: LogoRejection?
        var sawSvgRoot = false
        private var elementCount = 0
        private var depth = 0
        private var stack: [String] = []

        private func refuse(_ parser: XMLParser, _ r: LogoRejection) {
            if refusal == nil { refusal = r }
            parser.abortParsing()
        }

        func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                    qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
            let isRoot = !sawSvgRoot
            if isRoot {
                if elementName != "svg" { return refuse(parser, .invalidSvg) }
                sawSvgRoot = true
            } else if elementName == "svg" {
                // SwiftDraw 0.29.0 processes nested <svg> children twice per
                // level: 20 levels (735 bytes) took 55 s to parse (verified).
                return refuse(parser, .activeContent)
            }
            guard SvgActiveContentGuard.allowedElements.contains(elementName) else { return refuse(parser, .activeContent) }
            elementCount += 1
            depth += 1
            if elementCount > SvgActiveContentGuard.maxElements || depth > SvgActiveContentGuard.maxDepth {
                return refuse(parser, .tooLarge)
            }
            if let bad = SvgActiveContentGuard.attributeProblem(element: elementName, attributeDict, isRoot: isRoot) {
                return refuse(parser, bad)
            }
            stack.append(elementName)
        }

        func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
            depth -= 1
            _ = stack.popLast()
        }

        /// Text is inert only inside title/desc; anywhere else only whitespace is allowed.
        func parser(_ parser: XMLParser, foundCharacters string: String) {
            if let top = stack.last, ["title", "desc"].contains(top) { return }
            if !string.allSatisfy({ $0.isWhitespace }) { refuse(parser, .activeContent) }
        }

        func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
            if let top = stack.last, ["title", "desc"].contains(top) { return }
            refuse(parser, .activeContent)
        }

        // Any entity/notation declaration is a DOCTYPE with content.
        func parser(_ parser: XMLParser, foundInternalEntityDeclarationWithName name: String, value: String?) {
            refuse(parser, .activeContent)
        }
        func parser(_ parser: XMLParser, foundExternalEntityDeclarationWithName name: String, publicID: String?, systemID: String?) {
            refuse(parser, .activeContent)
        }
        func parser(_ parser: XMLParser, foundUnparsedEntityDeclarationWithName name: String, publicID: String?,
                    systemID: String?, notationName: String?) {
            refuse(parser, .activeContent)
        }
    }
}

/// Renders an SVG that already passed `SvgActiveContentGuard` to PNG bytes
/// with SwiftDraw (no script engine, no network, no file access); the output
/// is pixels, so no vector content survives.
enum SvgLogoRasterizer {
    static func rasterize(_ data: Data) -> Data? {
        guard let svg = SVG(data: data) else { return nil }
        let w = Double(svg.size.width), h = Double(svg.size.height)
        guard w.isFinite, h.isFinite, w > 0, h > 0 else { return nil }
        let edge = Double(LogoSanitizer.svgRenderEdge)
        let scale = edge / max(w, h)
        let pw = min(LogoSanitizer.svgRenderEdge, max(1, Int(w * scale)))
        let ph = min(LogoSanitizer.svgRenderEdge, max(1, Int(h * scale)))
        guard let space = CGColorSpace(name: CGColorSpace.sRGB),
              let ctx = CGContext(
                  data: nil, width: pw, height: ph, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
              )
        else { return nil }
        // SwiftDraw draws in a top-left origin space.
        ctx.translateBy(x: 0, y: CGFloat(ph))
        ctx.scaleBy(x: 1, y: -1)
        ctx.draw(svg, in: CGRect(x: 0, y: 0, width: pw, height: ph))
        guard let image = ctx.makeImage() else { return nil }
        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, "public.png" as CFString, 1, nil) else { return nil }
        CGImageDestinationAddImage(dest, image, nil)
        return CGImageDestinationFinalize(dest) ? out as Data : nil
    }
}
#endif
