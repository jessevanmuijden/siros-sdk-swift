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

    static func cssIsUnsafe(_ css: String) -> Bool {
        let r = NSRange(css.startIndex..., in: css)
        return externalUrl.firstMatch(in: css, range: r) != nil || cssImport.firstMatch(in: css, range: r) != nil
    }

    private final class Delegate: NSObject, XMLParserDelegate {
        var refusal: LogoRejection?
        var sawSvgRoot = false
        private var inStyle = false
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
            }
            if forbiddenElements.contains(name) { return refuse(parser, .activeContent) }
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
