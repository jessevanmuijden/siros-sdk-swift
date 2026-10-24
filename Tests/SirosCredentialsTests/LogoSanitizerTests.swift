// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import XCTest
@testable import SirosCredentials
#if canImport(ImageIO)
import ImageIO
import CoreGraphics
#endif

final class LogoSanitizerTests: XCTestCase {
    private func uri(_ type: String, _ bytes: Data) -> String {
        "data:\(type);base64,\(bytes.base64EncodedString())"
    }

    private func rejection(_ s: String, file: StaticString = #filePath, line: UInt = #line) -> LogoRejection? {
        if case .failure(let r) = LogoSanitizer.sanitize(s) { return r }
        XCTFail("expected rejection for \(s.prefix(60))", file: file, line: line)
        return nil
    }

    // MARK: - Platform-independent (no image decode needed)

    func testHttpsPassesThroughAsRemote() {
        guard case .success(.remote(let url)) = LogoSanitizer.sanitize("https://example.org/logo.png") else {
            return XCTFail("expected remote")
        }
        XCTAssertEqual(url.absoluteString, "https://example.org/logo.png")
    }

    func testNonHttpsSchemesRejected() {
        for s in ["http://example.org/l.png", "javascript:alert(1)", "file:///etc/passwd", "ftp://x/y", "//example.org/l.png", "logo.png"] {
            XCTAssertEqual(rejection(s), .unsupportedScheme, s)
        }
        XCTAssertEqual(rejection(""), .empty)
        XCTAssertEqual(rejection("   "), .empty)
    }

    func testHttpsWithCredentialsOrNoHostRejected() {
        XCTAssertEqual(rejection("https://user:pw@example.org/l.png"), .invalidRemoteUrl)
        XCTAssertEqual(rejection("https:///l.png"), .invalidRemoteUrl)
    }

    func testSvgDataUriRejectedEvenWhenBenign() {
        let svg = Data("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>".utf8)
        XCTAssertEqual(rejection(uri("image/svg+xml", svg)), .svgNotSupported)
        XCTAssertEqual(rejection("data:image/svg+xml;utf8,<svg onload='alert(1)'/>"), .svgNotSupported)
        XCTAssertEqual(rejection("data:image/svg+xml,%3Csvg%3E"), .svgNotSupported)
        XCTAssertEqual(rejection("DATA:IMAGE/SVG+XML;BASE64,PHN2Zy8+"), .svgNotSupported)
        if case .failure(.svgNotSupported) = LogoSanitizer.sanitize(imageData: svg, declaredMediaType: "image/svg+xml") {} else {
            XCTFail("sanitize(imageData:) must reject SVG")
        }
    }

    func testWrongMediaTypeRejected() {
        for t in ["text/html", "application/javascript", "image/bmp", "image/x-icon", "application/octet-stream", "text/plain"] {
            XCTAssertEqual(rejection(uri(t, Data([1, 2, 3]))), .unsupportedMediaType, t)
        }
    }

    func testMalformedDataUrisRejected() {
        XCTAssertEqual(rejection("data:image/png;base64"), .malformedDataUri)              // no comma
        XCTAssertEqual(rejection("data:image/png,AAAA"), .malformedDataUri)                // not base64
        XCTAssertEqual(rejection("data:,AAAA"), .malformedDataUri)                         // no type
        XCTAssertEqual(rejection("data:image/png;charset=latin1;base64,AAAA"), .malformedDataUri) // other charset
        XCTAssertEqual(rejection("data:image/png;foo=bar;base64,AAAA"), .malformedDataUri) // extra params
    }

    func testBadBase64Rejected() {
        XCTAssertEqual(rejection("data:image/png;base64,@@@@"), .invalidBase64)
        XCTAssertEqual(rejection("data:image/png;base64,iVBO Rw0K"), .invalidBase64) // whitespace
        XCTAssertEqual(rejection("data:image/png;base64,"), .invalidBase64)
    }

    func testOversizedPayloadRejected() {
        let big = Data(repeating: 0x41, count: LogoSanitizer.maxDecodedBytes + 1)
        XCTAssertEqual(rejection(uri("image/png", big)), .tooLarge)
        // Far past the cap: refused before base64 decoding is attempted.
        XCTAssertEqual(rejection("data:image/png;base64," + String(repeating: "A", count: 4_000_000)), .tooLarge)
    }

    func testGarbageBytesRejectedAsUndecodable() {
        let r = rejection(uri("image/png", Data("not an image at all".utf8)))
        #if canImport(ImageIO)
        XCTAssertEqual(r, .undecodable)
        #else
        XCTAssertEqual(r, .platformUnsupported)
        #endif
    }

    #if !canImport(ImageIO)
    /// Linux: no ImageIO, so every data: logo is refused (fail closed).
    func testLinuxDataLogoFailsClosed() {
        // 1x1 PNG
        let png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGNgYGD4DwABBAEAfbLI3wAAAABJRU5ErkJggg=="
        XCTAssertEqual(rejection("data:image/png;base64," + png), .platformUnsupported)
    }
    #endif
}

#if canImport(ImageIO)
/// Decode/re-encode behaviour, needs ImageIO (Apple platforms).
final class LogoSanitizerImageTests: XCTestCase {
    private static let marker = "EVIL_PAYLOAD_MARKER_7f3a"

    /// Noise, so that a truncated file really loses pixel data.
    private func makeImage(width: Int, height: Int) -> CGImage {
        let ctx = CGContext(
            data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
            space: CGColorSpace(name: CGColorSpace.sRGB)!,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        )!
        let px = ctx.data!.bindMemory(to: UInt8.self, capacity: height * ctx.bytesPerRow)
        var g = SystemRandomNumberGenerator()
        for i in 0..<(height * ctx.bytesPerRow) { px[i] = UInt8.random(in: 0...255, using: &g) }
        return ctx.makeImage()!
    }

    private func encode(_ image: CGImage, uti: String, properties: [CFString: Any]? = nil) -> Data {
        let out = NSMutableData()
        let dest = CGImageDestinationCreateWithData(out, uti as CFString, 1, nil)!
        CGImageDestinationAddImage(dest, image, properties as CFDictionary?)
        XCTAssertTrue(CGImageDestinationFinalize(dest))
        return out as Data
    }

    private func uri(_ type: String, _ bytes: Data) -> String { "data:\(type);base64,\(bytes.base64EncodedString())" }

    private func assertCleanPng(_ logo: DisplayLogo, width: Int, height: Int, file: StaticString = #filePath, line: UInt = #line) {
        guard case .image(let data) = logo else { return XCTFail("expected image", file: file, line: line) }
        XCTAssertEqual(Array(data.prefix(8)), [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], file: file, line: line)
        let src = CGImageSourceCreateWithData(data as CFData, nil)!
        XCTAssertEqual(CGImageSourceGetType(src) as String?, "public.png", file: file, line: line)
        let p = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as! [CFString: Any]
        XCTAssertEqual(p[kCGImagePropertyPixelWidth] as? Int, width, file: file, line: line)
        XCTAssertEqual(p[kCGImagePropertyPixelHeight] as? Int, height, file: file, line: line)
        XCTAssertNil(data.range(of: Data(Self.marker.utf8)), "marker leaked", file: file, line: line)
    }

    func testValidPngDataUri() {
        let png = encode(makeImage(width: 32, height: 16), uti: "public.png")
        guard case .success(let logo) = LogoSanitizer.sanitize(uri("image/png", png)) else { return XCTFail() }
        assertCleanPng(logo, width: 32, height: 16)
    }

    func testValidJpegDataUriIsReencodedAsPng() {
        let jpg = encode(makeImage(width: 40, height: 40), uti: "public.jpeg")
        guard case .success(let logo) = LogoSanitizer.sanitize(uri("image/jpeg", jpg)) else { return XCTFail() }
        assertCleanPng(logo, width: 40, height: 40)
    }

    func testValidGifDataUri() {
        let gif = encode(makeImage(width: 8, height: 8), uti: "com.compuserve.gif")
        guard case .success(let logo) = LogoSanitizer.sanitize(uri("image/gif", gif)) else { return XCTFail() }
        assertCleanPng(logo, width: 8, height: 8)
    }

    func testMediaTypeCaseInsensitive() {
        let png = encode(makeImage(width: 4, height: 4), uti: "public.png")
        guard case .success = LogoSanitizer.sanitize("DATA:IMAGE/PNG;BASE64," + png.base64EncodedString()) else { return XCTFail() }
    }

    func testCharsetParameterAccepted() {
        let png = encode(makeImage(width: 4, height: 4), uti: "public.png")
        guard case .success = LogoSanitizer.sanitize("data:image/png;charset=utf-8;base64," + png.base64EncodedString()) else { return XCTFail() }
    }

    func testTruncatedImageRejected() {
        let png = encode(makeImage(width: 64, height: 64), uti: "public.png")
        let cut = png.prefix(png.count / 2)
        if case .failure(.undecodable) = LogoSanitizer.sanitize(uri("image/png", Data(cut))) {} else {
            XCTFail("truncated PNG must be refused")
        }
        let jpg = encode(makeImage(width: 64, height: 64), uti: "public.jpeg")
        if case .failure(.undecodable) = LogoSanitizer.sanitize(uri("image/jpeg", Data(jpg.prefix(jpg.count / 2)))) {} else {
            XCTFail("truncated JPEG must be refused")
        }
    }

    func testExifOrientationBakedIntoPixels() {
        let jpg = encode(makeImage(width: 40, height: 20), uti: "public.jpeg", properties: [kCGImagePropertyOrientation: 6])
        guard case .success(let logo) = LogoSanitizer.sanitize(uri("image/jpeg", jpg)) else { return XCTFail() }
        assertCleanPng(logo, width: 20, height: 40) // rotated, not sideways
    }

    /// A decoy end marker inside metadata must not make a truncated file look complete.
    func testPngDecoyIendInMetadataDoesNotHideTruncation() {
        let png = [UInt8](encode(makeImage(width: 64, height: 64), uti: "public.png"))
        let iend: [UInt8] = [0, 0, 0, 0, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]
        // Ancillary chunk "prVt" whose data contains an IEND-looking sequence (CRC not checked by the guard).
        let dataLen = iend.count
        let chunk: [UInt8] = [0, 0, 0, UInt8(dataLen)] + Array("prVt".utf8) + iend + [0, 0, 0, 0]
        let withDecoy = Array(png[0..<33]) + chunk + Array(png[33...])
        XCTAssertTrue(LogoSanitizer.hasEndMarker(Data(withDecoy), mediaType: "image/png"))
        let truncated = Data(withDecoy.prefix(33 + chunk.count + (png.count - 33) / 2))
        XCTAssertFalse(LogoSanitizer.hasEndMarker(truncated, mediaType: "image/png"))
        XCTAssertFalse(LogoSanitizer.hasEndMarker(Data(withDecoy.dropLast(1)), mediaType: "image/png"))
        if case .failure = LogoSanitizer.sanitize(uri("image/png", truncated)) {} else { XCTFail("truncated PNG accepted") }
    }

    /// An EXIF thumbnail's EOI must not make a truncated main image look complete.
    func testJpegThumbnailEoiDoesNotHideTruncation() {
        let jpg = [UInt8](encode(makeImage(width: 64, height: 64), uti: "public.jpeg"))
        // APP1 segment (length covers itself) holding an embedded mini-JPEG with its own SOI/EOI.
        let payload: [UInt8] = [0xFF, 0xD8, 0x41, 0x42, 0xFF, 0xD9]
        let seg: [UInt8] = [0xFF, 0xE1, 0, UInt8(2 + payload.count)] + payload
        let withThumb = Array(jpg[0..<2]) + seg + Array(jpg[2...])
        XCTAssertTrue(LogoSanitizer.hasEndMarker(Data(withThumb), mediaType: "image/jpeg"))
        XCTAssertFalse(LogoSanitizer.hasEndMarker(Data(withThumb.prefix(2 + seg.count + (jpg.count - 2) / 2)), mediaType: "image/jpeg"))
        // Trailing bytes after a complete image are still fine.
        XCTAssertTrue(LogoSanitizer.hasEndMarker(Data(withThumb + [1, 2, 3]), mediaType: "image/jpeg"))
    }

    /// Legal fill bytes before a restart marker inside the scan must not end it early.
    func testJpegFillByteBeforeRestartMarkerAccepted() {
        // SOI, SOS (len 3 header-ish, content irrelevant to the walker), scan with FF FF D0 then more data, EOI.
        let sos: [UInt8] = [0xFF, 0xDA, 0x00, 0x03, 0x00]
        let scan: [UInt8] = [0x11, 0x22, 0xFF, 0xFF, 0xD0, 0x33, 0xFF, 0x00, 0x44]
        let ok: [UInt8] = [0xFF, 0xD8] + sos + scan + [0xFF, 0xD9]
        XCTAssertTrue(LogoSanitizer.hasEndMarker(Data(ok), mediaType: "image/jpeg"))
        // Truncated after the padded restart: still refused.
        XCTAssertFalse(LogoSanitizer.hasEndMarker(Data([0xFF, 0xD8] + sos + scan), mediaType: "image/jpeg"))
        // Fill bytes before the final EOI are fine too.
        XCTAssertTrue(LogoSanitizer.hasEndMarker(Data([0xFF, 0xD8] + sos + scan + [0xFF, 0xFF, 0xD9]), mediaType: "image/jpeg"))
    }

    func testDeclaredTypeMustMatchContent() {
        let png = encode(makeImage(width: 4, height: 4), uti: "public.png")
        if case .failure(.undecodable) = LogoSanitizer.sanitize(uri("image/jpeg", png)) {} else {
            XCTFail("PNG labelled JPEG must be refused")
        }
    }

    func testPolyglotTrailingPayloadDropped() {
        var png = encode(makeImage(width: 16, height: 16), uti: "public.png")
        let trailer = Data("<script>\(Self.marker)</script>".utf8)
        png.append(trailer)
        XCTAssertNotNil(png.range(of: Data(Self.marker.utf8)), "fixture must contain the marker")
        guard case .success(let logo) = LogoSanitizer.sanitize(uri("image/png", png)) else { return XCTFail("decodable polyglot should be cleaned, not refused") }
        assertCleanPng(logo, width: 16, height: 16)
    }

    func testJpegMetadataAndTrailerDropped() {
        let props: [CFString: Any] = [
            kCGImagePropertyExifDictionary: [kCGImagePropertyExifUserComment: Self.marker],
            kCGImagePropertyIPTCDictionary: [kCGImagePropertyIPTCCaptionAbstract: Self.marker],
        ]
        var jpg = encode(makeImage(width: 16, height: 16), uti: "public.jpeg", properties: props)
        jpg.append(Data(Self.marker.utf8))
        XCTAssertNotNil(jpg.range(of: Data(Self.marker.utf8)))
        guard case .success(let logo) = LogoSanitizer.sanitize(uri("image/jpeg", jpg)) else { return XCTFail() }
        assertCleanPng(logo, width: 16, height: 16)
    }

    func testPngTextChunkDropped() {
        let props: [CFString: Any] = [kCGImagePropertyPNGDictionary: [kCGImagePropertyPNGDescription: Self.marker]]
        let png = encode(makeImage(width: 16, height: 16), uti: "public.png", properties: props)
        XCTAssertNotNil(png.range(of: Data(Self.marker.utf8)), "fixture must carry the text chunk")
        guard case .success(let logo) = LogoSanitizer.sanitize(uri("image/png", png)) else { return XCTFail() }
        assertCleanPng(logo, width: 16, height: 16)
    }

    func testOversizedDimensionsRejected() {
        let png = encode(makeImage(width: LogoSanitizer.maxDimension + 1, height: 1), uti: "public.png")
        XCTAssertLessThan(png.count, LogoSanitizer.maxDecodedBytes)
        if case .failure(.dimensionsTooLarge) = LogoSanitizer.sanitize(uri("image/png", png)) {} else {
            XCTFail("over-wide image must be refused")
        }
    }

    func testSanitizeImageDataForFetchedRemoteLogo() {
        let png = encode(makeImage(width: 8, height: 8), uti: "public.png")
        guard case .success(let logo) = LogoSanitizer.sanitize(imageData: png, declaredMediaType: "image/png") else { return XCTFail() }
        assertCleanPng(logo, width: 8, height: 8)
    }
}
#endif

final class LogoCacheTests: XCTestCase {
    func testResultIsCachedByUriIncludingRejections() async {
        let cache = LogoCache(capacity: 8)
        let good = "https://example.org/a.png"
        let bad = "javascript:alert(1)"
        let first = await cache.resolve(good)
        let again = await cache.resolve(good)
        XCTAssertEqual(first, again)
        XCTAssertNotNil(first)
        let r1 = await cache.resolve(bad)
        let r2 = await cache.resolve(bad)
        XCTAssertNil(r1)
        XCTAssertNil(r2)
        let count = await cache.sanitizeCount
        XCTAssertEqual(count, 2, "each distinct URI sanitized once")
    }

    func testCacheIsBounded() async {
        let cache = LogoCache(capacity: 2)
        for i in 0..<5 { _ = await cache.resolve("https://example.org/\(i).png") }
        _ = await cache.resolve("https://example.org/0.png") // evicted, sanitized again
        let count = await cache.sanitizeCount
        XCTAssertEqual(count, 6)
    }
}
