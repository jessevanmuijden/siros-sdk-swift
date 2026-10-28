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
/// `radialGradient`, `stop`; geometry, paint (colour, `none`,
/// `currentColor`, `url(#id)` on shapes only), stroke, opacity, transform and
/// gradient attributes with validated grammar; `#fragment` hrefs on gradients.
/// Not supported: `style` attributes and `<style>`, text/fonts, `use`,
/// `image`, `pattern`, `mask`, `filter`, `marker`, `switch`, `symbol`,
/// animation, scripts, `foreignObject`, links, DOCTYPE/entities, namespaced
/// elements or attributes (other than the SVG/xlink declarations).
enum SvgActiveContentGuard {
    static let allowedElements: Set<String> = [
        "svg", "g", "defs", "title", "desc", "path", "rect", "circle", "ellipse", "line", "polyline",
        "polygon", "linearGradient", "radialGradient", "stop",
    ]

    /// Bounds on document complexity (the byte cap alone allows ~25k elements).
    static let maxElements = 5000
    /// Flat caps instead of per-use accounting: at most this many gradients and stops in a document
    /// (gradient reuse by many shapes is then bounded by the element cap times 64 stops).
    static let maxGradients = 8
    static let maxStops = 64
    /// Shapes that may carry a `url(#id)` fill/stroke; everything else (g, svg, defs, ...) may not,
    /// so no paint reference is ever inherited and none needs accounting.
    static let paintTargets: Set<String> = ["path", "rect", "circle", "ellipse", "line", "polyline", "polygon"]
    static let maxDepth = 64

    /// Largest magnitude accepted for any number. SwiftDraw traps (Float to
    /// Int) on values like `1e30` in sizes, before any check of ours could run.
    static let maxSvgNumber = 1_000_000.0

    // MARK: Value grammar (every pattern is anchored; nothing outside it passes)

    private static func re(_ pattern: String) -> NSRegularExpression {
        // swiftlint:disable:next force_try
        try! NSRegularExpression(pattern: pattern)
    }
    // Possessive quantifiers and a fractional run that exists only after the point: no two
    // adjacent variable-length digit runs, so a 300 KB run of digits is rejected in linear time.
    private static let numberPattern = "[+-]?+(?:\\d++(?:\\.\\d*+)?+|\\.\\d++)(?:[eE][+-]?+\\d++)?+"
    private static let lengthPattern = re("^(" + numberPattern + ")(px|pt|pc|mm|cm|in|em|ex|%)?$")
    private static let numberRe = re("^" + numberPattern + "$")
    private static let idPattern = "[A-Za-z_][A-Za-z0-9_.:-]{0,63}"
    private static let idRe = re("^" + idPattern + "$")
    private static let fragmentRe = re("^#" + idPattern + "$")
    // 3- and 6-digit only: SwiftDraw 0.29.0 mis-parses 4- and 8-digit alpha hex (verified: #ff000080 renders opaque navy). Use rgba().
    private static let hexColorRe = re("^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")
    private static let rgbRe = re("^rgba?\\(\\s*[0-9.%]+(?:\\s*,\\s*[0-9.%]+){2,3}\\s*\\)$")
    private static let namedColorRe = re("^[A-Za-z]{3,20}$")
    private static let paintUrlRe = re("^url\\(#" + idPattern + "\\)$")
    private static let transformFnRe = re("\\G\\s*(matrix|translate|scale|rotate|skewX|skewY)\\s*\\(([^()]*)\\)\\s*,?")

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

    /// See `SvgPathData`.
    static func isValidPathData(_ d: String) -> Bool { SvgPathData.isValid(d, maxNumber: maxSvgNumber) }

    /// Transform list with exact argument counts per function.
    static func isValidTransform(_ t: String) -> Bool {
        let ns = t as NSString
        var pos = 0
        var count = 0
        while pos < ns.length {
            guard let m = transformFnRe.firstMatch(in: t, options: [.anchored], range: NSRange(location: pos, length: ns.length - pos)),
                  m.range.location == pos else {
                return ns.substring(from: pos).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && count > 0
            }
            let fn = ns.substring(with: m.range(at: 1))
            let args = ns.substring(with: m.range(at: 2)).split(whereSeparator: { " ,\t\r\n".contains($0) }).map(String.init)
            guard args.allSatisfy(isNumber) else { return false }
            let ok: Bool
            switch fn {
            case "matrix": ok = args.count == 6
            case "translate", "scale": ok = args.count == 1 || args.count == 2
            case "rotate": ok = args.count == 1 || args.count == 3
            default: ok = args.count == 1 // skewX, skewY
            }
            guard ok else { return false }
            count += 1
            guard count <= 16 else { return false }
            pos = m.range.location + m.range.length
        }
        return count > 0
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

    /// Stop offsets: a number, or a percentage (SwiftDraw resolves these; verified).
    static func isOffset(_ v: String) -> Bool { isOpacity(v) }

    /// Geometry lengths: a length without a percentage (SwiftDraw 0.29.0 does not resolve percentages on shapes).
    static func isGeometryLength(_ v: String) -> Bool {
        lengthProblem(v) == nil && !v.trimmingCharacters(in: .whitespacesAndNewlines).hasSuffix("%")
    }

    /// A bare number or `px`: other units would be silently ignored by SwiftDraw's stroke-width parsing.
    static func isUnitlessLength(_ v: String) -> Bool {
        let t = v.trimmingCharacters(in: .whitespacesAndNewlines)
        let number = t.hasSuffix("px") ? String(t.dropLast(2)) : t
        return isNumber(number)
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
        "x": isGeometryLength, "y": isGeometryLength,
        "width": isGeometryLength, "height": isGeometryLength,
        "cx": isGeometryLength, "cy": isGeometryLength, "r": isGeometryLength,
        "rx": isGeometryLength, "ry": isGeometryLength,
        "x1": isGeometryLength, "y1": isGeometryLength,
        "x2": isGeometryLength, "y2": isGeometryLength,
        "fx": isGeometryLength, "fy": isGeometryLength, "fr": isGeometryLength,
        "offset": isOffset,
        "points": { isNumberList($0) && $0.split(whereSeparator: { " ,\t\r\n".contains($0) }).count % 2 == 0 },
        "d": { isValidPathData($0) },
        "transform": { isValidTransform($0) }, "gradientTransform": { isValidTransform($0) },
        "viewBox": { isNumberList($0, max: 4) && $0.split(whereSeparator: { " ,\t\r\n".contains($0) }).count == 4 },
        "version": { isEnum($0, ["1.0", "1.1", "2.0"]) },
        "fill": isPaint, "stroke": isPaint,
        "stop-color": isColor, "color": isColor,
        "stroke-width": isUnitlessLength, // SwiftDraw parses stroke-width as a bare float: units would be ignored
        "stroke-linecap": { isEnum($0, ["butt", "round", "square"]) },
        "stroke-linejoin": { isEnum($0, ["miter", "round", "bevel"]) },
        "fill-rule": { isEnum($0, ["nonzero", "evenodd"]) },
        "opacity": isOpacity, "fill-opacity": isOpacity, "stroke-opacity": isOpacity, "stop-opacity": isOpacity,
        "gradientUnits": { isEnum($0, ["userSpaceOnUse", "objectBoundingBox"]) },
        "spreadMethod": { isEnum($0, ["pad"]) }, // reflect/repeat render as pad in SwiftDraw 0.29.0
    ]

    /// nil when the SVG may be rasterized, otherwise why not.
    static func check(_ data: Data) -> LogoRejection? {
        // DOCTYPE/ENTITY: refused up front (also catches declarations the
        // parser would not report). A false positive inside a comment is fine.
        // UTF-8 only: UTF-16 (or any NUL-bearing) input would hide a DOCTYPE from this scan, so it is refused.
        guard !data.contains(0), let decoded = String(data: data, encoding: .utf8) else { return .invalidSvg }
        let text = decoded.lowercased()
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
            case "href":
                // SwiftDraw 0.29.0 reads only xlink:href, so a plain href would silently not
                // inherit (verified); refused rather than rewritten.
                return .activeContent
            case "xlink:href":
                // SwiftDraw 0.29.0 copies only the referenced gradient's immediate stops, not its
                // coordinates, units, transform or further links, so inheritance would render wrongly.
                return .activeContent
            case "width", "height", "viewBox":
                if isRoot && key != "viewBox" {
                    if let bad = lengthProblem(value) { return bad }
                    if !isGeometryLength(value) { return .invalidSvg } // no percentage viewport
                }
                guard attributeValidators[key]?(value) == true else { return .invalidSvg }
                if key == "viewBox", let bad = viewBoxProblem(value) { return bad }
            default:
                guard let validate = attributeValidators[key], validate(value) else { return .activeContent }
            }
        }
        if isRoot, let bad = aspectProblem(attrs) { return bad }
        return nil
    }

    /// SwiftDraw 0.29.0 ignores `preserveAspectRatio` and scales the axes independently, so a viewport whose
    /// aspect differs from the viewBox's would be rendered stretched: refused (compared on unitless/px numbers).
    static func aspectProblem(_ attrs: [String: String]) -> LogoRejection? {
        guard let vb = attrs["viewBox"], let ws = attrs["width"], let hs = attrs["height"] else { return nil }
        let box = vb.split(whereSeparator: { " ,\t\r\n".contains($0) }).compactMap { Double($0) }
        func number(_ v: String) -> Double? {
            let t = v.trimmingCharacters(in: .whitespacesAndNewlines)
            return Double(t.hasSuffix("px") ? String(t.dropLast(2)) : t) // other units: not comparable
        }
        guard box.count == 4, let w = number(ws), let h = number(hs), w > 0, h > 0, box[3] > 0 else { return .invalidSvg }
        let viewport = w / h, boxAspect = box[2] / box[3]
        return abs(viewport - boxAspect) / boxAspect > 0.01 ? .invalidSvg : nil
    }

    /// Geometry units one element adds to the document total: path segments, polygon/polyline point
    /// pairs, one for any other shape; nil for non-geometry elements.
    static func geometryUnits(element: String, _ attrs: [String: String]) -> (units: Int, curves: Int)? {
        switch element {
        case "path":
            guard let d = attrs["d"] else { return (1, 0) }
            guard let c = SvgPathData.analyze(d, maxNumber: maxSvgNumber) else { return (1, 0) }
            return (c.segments, c.curves)
        case "polygon", "polyline":
            let n = (attrs["points"] ?? "").split(whereSeparator: { " ,\t\r\n".contains($0) }).count
            return (max(1, n / 2), 0)
        case "rect", "circle", "ellipse", "line": return (1, 0)
        default: return nil
        }
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
        /// Geometry units in the whole document: path segments, polygon/polyline points, one per other shape.
        private var geometry = 0
        private var curves = 0
        private var ids = Set<String>()
        private var gradients = 0
        private var stops = 0
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
            // Duplicate ids make SwiftDraw and our accounting disagree about which element a reference means.
            if let id = attributeDict["id"], !ids.insert(id).inserted { return refuse(parser, .activeContent) }
            switch elementName {
            case "linearGradient", "radialGradient":
                gradients += 1
                if gradients > SvgActiveContentGuard.maxGradients { return refuse(parser, .tooLarge) }
            case "stop":
                stops += 1
                if stops > SvgActiveContentGuard.maxStops { return refuse(parser, .tooLarge) }
            default: break
            }
            // Paint references only on leaf shapes: a `fill="url(#g)"` on a group or the root would be inherited
            // by every descendant and would multiply the gradient work. Any value mentioning url is refused
            // there, whatever the spelling or whitespace.
            if !SvgActiveContentGuard.paintTargets.contains(elementName) {
                for key in ["fill", "stroke"] where attributeDict[key]?.lowercased().contains("url") == true {
                    return refuse(parser, .activeContent)
                }
            }
            if let g = SvgActiveContentGuard.geometryUnits(element: elementName, attributeDict) {
                geometry += g.units
                curves += g.curves
                if geometry > SvgPathData.maxDocumentSegments || curves > SvgPathData.maxDocumentCurves { return refuse(parser, .tooLarge) }
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
