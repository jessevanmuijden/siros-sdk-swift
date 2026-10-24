// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

#if canImport(ImageIO)
import Foundation
import CoreGraphics
import ImageIO
import SwiftDraw

/// Refuses (never repairs) an SVG that contains anything but static shapes,
/// text and gradients. Mirrors siros-sdk-kotlin's `SvgActiveContentGuard`.
/// `<image>` is refused outright, embedded `data:` rasters included. Uses
/// Foundation's XMLParser, so malformed XML is itself a refusal. This is a
/// gate in front of the rasterizer, not a sanitizer: nothing is rewritten.
enum SvgActiveContentGuard {
    static let forbiddenElements: Set<String> = [
        "script", "foreignobject", "use", "iframe", "object", "embed", "a",
        "image", "audio", "video", "animate", "set", "animatetransform", "animatemotion",
        "animatecolor", "handler", "listener", "feimage", "cursor", "font-face-uri",
        // SwiftDraw 0.29.0 recurses without cycle detection through a pattern
        // or mask that references itself (stack overflow, verified); neither
        // can be proven acyclic here, so both are refused. clipPath, marker,
        // filter and gradient href cycles were tried and are safe in 0.29.0.
        "pattern", "mask",
    ]

    /// A `url(...)` that points anywhere but a same-document `#fragment`.
    private static let externalUrl = try! NSRegularExpression( // swiftlint:disable:this force_try
        pattern: "url\\(\\s*(?!\\s*['\"]?\\s*#)", options: [.caseInsensitive])
    private static let cssImport = try! NSRegularExpression( // swiftlint:disable:this force_try
        pattern: "@import", options: [.caseInsensitive])

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

    private static func localName(_ qualified: String) -> String {
        (qualified.split(separator: ":").last.map(String.init) ?? qualified).lowercased()
    }

    /// Largest magnitude accepted for width/height/viewBox numbers. SwiftDraw
    /// 0.29.0 traps (Float to Int) on values like `1e30`, before any size
    /// check of ours could run, so everything is validated first.
    /// Bounds on document complexity (the byte cap alone allows ~25k elements).
    static let maxElements = 5000
    static let maxDepth = 64

    static let maxSvgNumber = 1_000_000.0

    private static let lengthPattern = try! NSRegularExpression( // swiftlint:disable:this force_try
        pattern: "^[+-]?(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?(px|pt|pc|mm|cm|in|em|ex|%)?$")

    /// A CSS/SVG length: number, optional unit, magnitude within `maxSvgNumber`.
    static func lengthProblem(_ raw: String) -> LogoRejection? {
        let v = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let r = NSRange(v.startIndex..., in: v)
        guard let m = lengthPattern.firstMatch(in: v, range: r) else { return .invalidSvg }
        // Number = everything before the unit (group 3), so "em"/"ex" are not mistaken for an exponent.
        let unitStart = m.range(at: 3).location == NSNotFound ? r.length : m.range(at: 3).location
        let digits = (v as NSString).substring(to: unitStart)
        guard let d = Double(digits), d.isFinite else { return .invalidSvg }
        return abs(d) > maxSvgNumber ? .dimensionsTooLarge : nil
    }

    /// nil when width/height/viewBox of an `<svg>` element are safe to hand to SwiftDraw.
    /// SwiftDraw gives an inline `style="width:..."` precedence over the
    /// attribute and traps on the same huge values (verified on 0.29.0), so
    /// width/height declared in a `style` attribute get the same check.
    /// (Other CSS routes were tried and are safe: width/height on shapes,
    /// stroke-width, font-size, transform, `<style>` rules.)
    static func dimensionProblem(_ attrs: [String: String]) -> LogoRejection? {
        for (key, raw) in attrs {
            switch localName(key) {
            case "width", "height":
                if let bad = lengthProblem(raw) { return bad }
            case "style":
                for decl in raw.split(separator: ";") {
                    guard let colon = decl.firstIndex(of: ":") else { continue }
                    let prop = decl[..<colon].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    let value = String(decl[decl.index(after: colon)...])
                    if ["width", "height"].contains(prop), let bad = lengthProblem(value) { return bad }
                }
            case "viewbox":
                let parts = raw.split(whereSeparator: { " ,\t\r\n".contains($0) })
                guard parts.count == 4 else { return .invalidSvg }
                var nums: [Double] = []
                for p in parts {
                    let t = String(p)
                    guard lengthPattern.firstMatch(in: t, range: NSRange(t.startIndex..., in: t)) != nil,
                          !t.hasSuffix("%"), let d = Double(t), d.isFinite else { return .invalidSvg }
                    if abs(d) > maxSvgNumber { return .dimensionsTooLarge }
                    nums.append(d)
                }
                if nums[2] <= 0 || nums[3] <= 0 { return .invalidSvg }
            default: break
            }
        }
        return nil
    }

    static func cssIsUnsafe(_ css: String) -> Bool {
        let r = NSRange(css.startIndex..., in: css)
        return externalUrl.firstMatch(in: css, range: r) != nil || cssImport.firstMatch(in: css, range: r) != nil
    }

    private final class Delegate: NSObject, XMLParserDelegate {
        var refusal: LogoRejection?
        var sawSvgRoot = false
        private var inStyle = false
        private var elementCount = 0
        private var depth = 0
        private var style = ""

        private func refuse(_ parser: XMLParser, _ r: LogoRejection) {
            if refusal == nil { refusal = r }
            parser.abortParsing()
        }

        func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?,
                    qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
            let name = localName(elementName)
            if !sawSvgRoot {
                if name != "svg" { return refuse(parser, .invalidSvg) }
                sawSvgRoot = true
            } else if name == "svg" {
                // SwiftDraw 0.29.0 processes nested <svg> children twice per
                // level: 20 levels (735 bytes) took 55 s to parse (verified).
                return refuse(parser, .activeContent)
            }
            elementCount += 1
            depth += 1
            if elementCount > SvgActiveContentGuard.maxElements || depth > SvgActiveContentGuard.maxDepth {
                return refuse(parser, .tooLarge)
            }
            if forbiddenElements.contains(name) { return refuse(parser, .activeContent) }
            if name == "svg", let bad = SvgActiveContentGuard.dimensionProblem(attributeDict) {
                return refuse(parser, bad)
            }
            inStyle = name == "style"
            style = ""
            for (key, value) in attributeDict {
                let attr = localName(key)
                if attr.hasPrefix("on") { return refuse(parser, .activeContent) }
                if value.range(of: "javascript:", options: .caseInsensitive) != nil { return refuse(parser, .activeContent) }
                if cssIsUnsafe(value) { return refuse(parser, .activeContent) }
                if attr == "href" || attr == "src",
                   !value.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("#") {
                    return refuse(parser, .activeContent)
                }
            }
        }

        func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
            depth -= 1
            if inStyle, cssIsUnsafe(style) { return refuse(parser, .activeContent) }
            inStyle = false
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            if inStyle { style += string }
        }

        func parser(_ parser: XMLParser, foundCDATA CDATABlock: Data) {
            if inStyle { style += String(decoding: CDATABlock, as: UTF8.self) }
        }

        // Any entity/notation/element declaration is a DOCTYPE with content.
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
