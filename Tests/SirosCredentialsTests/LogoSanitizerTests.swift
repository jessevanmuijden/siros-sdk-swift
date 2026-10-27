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

    func testEffectiveTimeoutValidatesAndClamps() {
        for bad in [TimeInterval.nan, .infinity, -.infinity, 0, -1, -0.0001, -.greatestFiniteMagnitude] {
            XCTAssertNil(LogoSanitizer.effectiveTimeout(bad), "\(bad)")
        }
        XCTAssertEqual(LogoSanitizer.effectiveTimeout(0.5), 0.5)
        XCTAssertEqual(LogoSanitizer.effectiveTimeout(1e300), LogoSanitizer.maxFetchTimeout)
        XCTAssertEqual(LogoSanitizer.effectiveTimeout(.greatestFiniteMagnitude), LogoSanitizer.maxFetchTimeout)
        XCTAssertEqual(LogoSanitizer.effectiveTimeout(LogoSanitizer.maxFetchTimeout), LogoSanitizer.maxFetchTimeout)
    }

    func testFetchRejectsUnusableTimeoutBeforeAnyRequest() async {
        let url = URL(string: "https://example.org/a.svg")!
        for bad in [TimeInterval.nan, .infinity, -1, 0] {
            if case .failure(.invalidTimeout) = await LogoSanitizer.fetchAndSanitize(url, timeout: bad) {} else { XCTFail("\(bad)") }
        }
    }

    // MARK: Path data grammar (pure Foundation, runs everywhere)

    private func validPath(_ d: String) -> Bool { SvgPathData.isValid(d, maxNumber: 1_000_000) }

    func testPathDataGrammarAcceptsOrdinaryPaths() {
        for d in ["M0 0 L8 0 L8 8 Z", "M0,0 4,0 4,4 8,8", "m1 1 h4 v4 z m2 2 l1 1", "M0 0 C1 1 2 2 3 3 S4 4 5 5 Q1 1 2 2 T3 3",
                  "M0 0 A4 4 0 0 1 4 4", "M0 0 a1 1 0 00.5.5", "M-1.5e2 .5 L+3 -.25z", "M0 0Z", "M0 0 Z M1 1 L2 2",
                  "M0 0 L1 1 2 2 3 3", " M0 0 z ", "M0 0 L1 1,2 2", "M0 0 z\n m1 1"] {
            XCTAssertTrue(validPath(d), d)
        }
    }

    /// Each of these makes SwiftDraw 0.29.0 loop without consuming input or trap; none may pass.
    func testPathDataGrammarRefusesEveryNonAdvancingOrTrappingForm() {
        let bad = [
            "M0 0Z0", "M0 0 L4 0 L4 4 Z 5", "M0 0 z,1", "M0 0Z,", "M0 0 z ,", "M0 0 Z , L1 1", "M0 0Z,L1 1", "M0 0Z.5", "M0 0Z-1", "M0 0Ze1",
            "M0 0 ß", "M0 0Zſ1 2 3 4", "M0 0 ı", "M0 0 \u{212A}", "M0 0 İ", "M0 0 ǆ", "M0 0 Ｌ1 1", "M０ 0", "M0 0 L1 1\u{00A0}",
            "M0 0 L1 1\u{2003}2 2", "M0 0 L1 1\u{0}", "M0 0 é", "💥",
            "", " ", "L0 0", "Z", "M0", "M0 0 L1", "M0 0 H", "M0 0 C1 1 2 2 3", "M0 0 A4 4 0 0 1 4", "M0 0 A4 4 0 2 1 4 4",
            "M0 0 L1 1 e", "M0 0 L1e 1", "M0 0 L1e+ 1", "M0 0 L1 1 x", "M0 0 L1e30 1", "M0 0 L--1 1", "M0 0 L1..2 1", "M0 0 <", "M0 0 L1 1 2",
            "M0 0 L1 1 X", "M0 0 R1 1", "M0 0 L 1 1 -", "M0 0 L1 1 +", "M0 0 .", "M0 0 L. 1", "M0 0 L1 1 e5",
        ]
        for d in bad { XCTAssertFalse(validPath(d), d.debugDescription) }
    }

    /// SwiftDraw scans back to the last move for every Z: 99,000 compact Zs did not finish in 25 s on a release
    /// build. Complexity is capped per path and per document (validator and guard level, nothing reaches SwiftDraw).
    func testPathComplexityIsBounded() {
        XCTAssertFalse(validPath("M0 0" + String(repeating: "Z", count: 99_000)))
        XCTAssertFalse(validPath("M0 0 " + String(repeating: "Z ", count: SvgPathData.maxSegments + 1)))
        XCTAssertFalse(validPath("M0 0 " + String(repeating: "L1 1 ", count: SvgPathData.maxSegments + 1)), "implicit repeats count too")
        XCTAssertFalse(validPath(String(repeating: "M0 0 ", count: SvgPathData.maxSubpaths + 1)))
        XCTAssertTrue(validPath("M0 0 " + String(repeating: "L1 1 ", count: 1000) + String(repeating: "Z", count: 100)))
        XCTAssertTrue(validPath(String(repeating: "M0 0 L1 1 Z ", count: 300)))
        let counts = SvgPathData.analyze("M0 0 L1 1 2 2 Z m1 1 z", maxNumber: 1e6)
        XCTAssertEqual(counts?.segments, 6) // M L L Z m z
        XCTAssertEqual(counts?.subpaths, 2)
    }

    /// Deterministic bounded property test: whatever the grammar accepts is ASCII-only, starts with
    /// M/m, uses only command letters, never has a comma after Z/z, and every Z/z is followed by
    /// whitespace/end/letter. (The matching "renders under SwiftDraw within a timeout" fuzz is a scratch
    /// harness on the Mac mini; this keeps the invariants honest everywhere.)
    func testPathDataGrammarInvariantsOnGeneratedPaths() {
        let noise = ["ß", "ſ", "ı", "\u{212A}", "İ", "ǆ", "e", "-", "+", ",", ".", " ", "Z", "z", "e1", "1e2", "-.5", "1.", "0 0 1", "x", "5 5 5"]
        let letters = Array("MmLlHhVvCcSsQqTtAaZz")
        let counts: [Character: Int] = ["M": 2, "L": 2, "T": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4, "A": 7, "Z": 0]
        let numbers = ["0", "1", "2", "5", "12", "3.5", "-4", ".5", "1e2", "+3", "-.25"]
        var accepted = 0
        for idx in 0..<6000 {
            var x = UInt64(idx) &* 6364136223846793005 &+ 1442695040888963407
            func next(_ n: Int) -> Int { x = x &* 6364136223846793005 &+ 1442695040888963407; return Int((x >> 33) % UInt64(n)) }
            var d = next(4) == 0 ? "" : "M0 0 "
            for _ in 0..<(1 + next(5)) {
                let l = letters[next(letters.count)]
                d += String(l)
                let n = counts[Character(l.uppercased())] ?? 0
                for _ in 0..<(n * (1 + next(2))) { d += numbers[next(numbers.count)] + [" ", ",", " ", ""][next(4)] }
                if next(4) == 0 { d += noise[next(noise.count)] } // mutate: this is where the bad inputs come from
                if next(3) == 0 { d += " " }
            }
            guard validPath(d) else { continue }
            accepted += 1
            let b = Array(d.utf8)
            XCTAssertTrue(b.allSatisfy { $0 < 0x80 }, d)
            let first = b.first { $0 != 0x20 && $0 != 0x09 && $0 != 0x0A && $0 != 0x0D }
            XCTAssertTrue(first == 0x4D || first == 0x6D, d)
            let allowedLetters = Set("MmLlHhVvCcSsQqTtAaZz".utf8)
            for (i, c) in b.enumerated() {
                let isLetter = (c | 0x20) >= 0x61 && (c | 0x20) <= 0x7A
                if isLetter && c != 0x65 && c != 0x45 { XCTAssertTrue(allowedLetters.contains(c), d) } // e/E only inside numbers
                if c == 0x5A || c == 0x7A {
                    var j = i + 1
                    while j < b.count, b[j] == 0x20 || b[j] == 0x09 || b[j] == 0x0A || b[j] == 0x0D { j += 1 }
                    XCTAssertTrue(j == b.count || ((b[j] | 0x20) >= 0x61 && (b[j] | 0x20) <= 0x7A), "Z must be followed by a command or the end: \(d)")
                }
            }
        }
        XCTAssertGreaterThan(accepted, 100, "the generator must actually produce accepted paths (accepted \(accepted))")
    }

    func testPercentEncodedSvgRefused() {
        // Base64 only, like every other data: logo (and like Kotlin).
        XCTAssertEqual(rejection("data:image/svg+xml;utf8,<svg onload='alert(1)'/>"), .malformedDataUri)
        XCTAssertEqual(rejection("data:image/svg+xml,%3Csvg%3E"), .malformedDataUri)
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
    func testLinuxSvgFailsClosed() {
        let svg = Data("<svg xmlns='http://www.w3.org/2000/svg' width='4' height='4'/>".utf8)
        XCTAssertEqual(rejection(uri("image/svg+xml", svg)), .platformUnsupported)
    }
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

    // MARK: - SVG

    private func svg(_ body: String, attrs: String = "width=\"64\" height=\"32\" viewBox=\"0 0 64 32\"") -> String {
        "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" \(attrs)>\(body)</svg>"
    }

    private func svgUri(_ s: String) -> String { uri("image/svg+xml", Data(s.utf8)) }

    private func svgRejection(_ s: String, file: StaticString = #filePath, line: UInt = #line) -> LogoRejection? {
        if case .failure(let r) = LogoSanitizer.sanitize(svgUri(s)) { return r }
        XCTFail("expected rejection", file: file, line: line)
        return nil
    }

    private func pixel(_ data: Data, x: Int, y: Int) -> [UInt8] {
        let src = CGImageSourceCreateWithData(data as CFData, nil)!
        let img = CGImageSourceCreateImageAtIndex(src, 0, nil)!
        let ctx = CGContext(data: nil, width: img.width, height: img.height, bitsPerComponent: 8, bytesPerRow: 0,
                            space: CGColorSpace(name: CGColorSpace.sRGB)!,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        ctx.draw(img, in: CGRect(x: 0, y: 0, width: img.width, height: img.height))
        let p = ctx.data!.bindMemory(to: UInt8.self, capacity: img.height * ctx.bytesPerRow)
        // Bitmap memory is top-row-first.
        let off = y * ctx.bytesPerRow + x * 4
        return [p[off], p[off + 1], p[off + 2], p[off + 3]]
    }

    func testCleanSvgRasterizedToPng() {
        guard case .success(let logo) = LogoSanitizer.sanitize(svgUri(svg("<rect width=\"64\" height=\"32\" fill=\"#ff0000\"/>"))),
              case .image(let data) = logo else { return XCTFail() }
        let src = CGImageSourceCreateWithData(data as CFData, nil)!
        XCTAssertEqual(CGImageSourceGetType(src) as String?, "public.png")
        let p = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as! [CFString: Any]
        XCTAssertEqual(p[kCGImagePropertyPixelWidth] as? Int, LogoSanitizer.svgRenderEdge)
        XCTAssertEqual(p[kCGImagePropertyPixelHeight] as? Int, LogoSanitizer.svgRenderEdge / 2)
        let px = pixel(data, x: 10, y: 10)
        XCTAssertEqual(px[0], 255); XCTAssertEqual(px[1], 0); XCTAssertEqual(px[3], 255)
    }

    func testSvgOrientationIsUpright() {
        // Red square in the bottom-right corner only.
        let s = svg("<rect x=\"32\" y=\"16\" width=\"32\" height=\"16\" fill=\"#ff0000\"/>")
        guard case .success(.image(let data)) = LogoSanitizer.sanitize(svgUri(s)) else { return XCTFail() }
        let w = LogoSanitizer.svgRenderEdge, h = LogoSanitizer.svgRenderEdge / 2
        XCTAssertEqual(pixel(data, x: w - 10, y: h - 10)[3], 255, "bottom-right drawn")
        XCTAssertEqual(pixel(data, x: 10, y: 10)[3], 0, "top-left transparent")
    }

    func testSvgWithoutViewBoxKeepsArtwork() {
        let s = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"1024\" height=\"1024\"><rect x=\"768\" y=\"768\" width=\"200\" height=\"200\" fill=\"#ff0000\"/></svg>"
        guard case .success(.image(let data)) = LogoSanitizer.sanitize(svgUri(s)) else { return XCTFail() }
        let e = LogoSanitizer.svgRenderEdge
        XCTAssertEqual(pixel(data, x: Int(Double(e) * 0.8), y: Int(Double(e) * 0.8))[0], 255)
    }

    func testHugeViewBoxIsScaledToBoundedBitmap() {
        let s = svg("<rect width=\"1\" height=\"1\"/>", attrs: "width=\"1000000\" height=\"1000000\" viewBox=\"0 0 1000000 1000000\"")
        guard case .success(.image(let data)) = LogoSanitizer.sanitize(svgUri(s)) else { return XCTFail() }
        let src = CGImageSourceCreateWithData(data as CFData, nil)!
        let p = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as! [CFString: Any]
        XCTAssertLessThanOrEqual(p[kCGImagePropertyPixelWidth] as! Int, LogoSanitizer.maxDimension)
        XCTAssertLessThanOrEqual(p[kCGImagePropertyPixelHeight] as! Int, LogoSanitizer.maxDimension)
        // Extreme aspect ratio still yields a valid >=1px bitmap.
        let thin = svg("<rect width=\"1\" height=\"1\"/>", attrs: "width=\"100000\" height=\"1\" viewBox=\"0 0 100000 1\"")
        guard case .success = LogoSanitizer.sanitize(svgUri(thin)) else { return XCTFail() }
    }

    func testSvgActiveContentRefused() {
        let evil: [String: String] = [
            "script": svg("<script>alert(1)</script><rect width=\"1\" height=\"1\"/>"),
            "scriptNs": svg("<svg:script xmlns:svg=\"http://www.w3.org/2000/svg\">alert(1)</svg:script>"),
            "foreignObject": svg("<foreignObject><div xmlns=\"http://www.w3.org/1999/xhtml\">x</div></foreignObject>"),
            "use": svg("<defs><rect id=\"a\" width=\"1\" height=\"1\"/></defs><use href=\"#a\"/>"),
            "a": svg("<a href=\"#x\"><rect width=\"1\" height=\"1\"/></a>"),
            "imageDataPayload": svg("<image width=\"8\" height=\"8\" href=\"data:image/png;base64,iVBORw0KGgo=\"/>"),
            "imageExternal": svg("<image href=\"https://evil.example/x.png\" width=\"8\" height=\"8\"/>"),
            "animate": svg("<rect width=\"1\" height=\"1\"><animate attributeName=\"x\" from=\"0\" to=\"9\" dur=\"1s\"/></rect>"),
            "set": svg("<rect width=\"1\" height=\"1\"><set attributeName=\"onclick\" to=\"alert(1)\"/></rect>"),
            "iframe": svg("<iframe src=\"https://evil.example\"/>"),
            "onload": svg("<rect width=\"1\" height=\"1\"/>", attrs: "width=\"4\" height=\"4\" onload=\"alert(1)\""),
            "onclick": svg("<rect width=\"1\" height=\"1\" onclick=\"alert(1)\"/>"),
            "javascriptHref": svg("<rect width=\"1\" height=\"1\" fill=\"javascript:alert(1)\"/>"),
            "externalHrefOnGradient": svg("<linearGradient id=\"g\" xlink:href=\"https://evil.example/g.svg#x\"/>"),
            "externalUrlFill": svg("<rect width=\"1\" height=\"1\" fill=\"url(https://evil.example/p.svg#a)\"/>"),
            "styleImport": svg("<style>@import url(https://evil.example/a.css);</style>"),
            "styleExternalUrl": svg("<style>rect{fill:url(https://evil.example/x)}</style>"),
            "styleAttrExternalUrl": svg("<rect width=\"1\" height=\"1\" style=\"fill:url('http://evil.example/x')\"/>"),
            "doctypeEntity": "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY x \"boom\">]>" + svg("<text>&x;</text>"),
            "doctypeBare": "<!DOCTYPE svg>" + svg(""),
            "entityBomb": "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY a \"aaaaaaaaaa\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">]>" + svg("<text>&c;</text>"),
        ]
        for (name, s) in evil {
            XCTAssertEqual(svgRejection(s), .activeContent, name)
        }
    }

    // (4) SwiftDraw 0.29.0 overflows the stack on self-referencing pattern/mask; refused before it runs.
    func testSelfReferencingPatternAndMaskRefused() {
        let pattern = svg("<defs><pattern id=\"p\" width=\"4\" height=\"4\" patternUnits=\"userSpaceOnUse\"><rect width=\"4\" height=\"4\" fill=\"url(#p)\"/></pattern></defs><rect width=\"8\" height=\"8\" fill=\"url(#p)\"/>")
        let mask = svg("<defs><mask id=\"m\"><rect width=\"8\" height=\"8\" fill=\"white\" mask=\"url(#m)\"/></mask></defs><rect width=\"8\" height=\"8\" mask=\"url(#m)\"/>")
        XCTAssertEqual(svgRejection(pattern), .activeContent)
        XCTAssertEqual(svgRejection(mask), .activeContent)
    }

    // (5) SwiftDraw 0.29.0 traps (Float to Int) on these; refused before SVG(data:).
    func testHugeOrNonFiniteDimensionsRefusedBeforeSwiftDraw() {
        let bad = [
            "width=\"1e30\" height=\"1\"", "width=\"1\" height=\"1e30\"",
            "width=\"99999999999999999999\" height=\"1\"", "width=\"1e20mm\" height=\"1\"",
            "viewBox=\"0 0 1e30 1\"", "viewBox=\"0 0 1 1e30\" width=\"4\" height=\"4\"",
            "width=\"1e400\" height=\"1\"", "width=\"inf\" height=\"1\"", "width=\"nan\" height=\"1\"",
            "width=\"4\" height=\"4\" viewBox=\"0 0 0 4\"", "width=\"4\" height=\"4\" viewBox=\"0 0 4\"",
        ]
        for attrs in bad {
            let s = svg("<rect width=\"1\" height=\"1\"/>", attrs: attrs)
            XCTAssertNotNil(svgRejection(s), attrs) // reaching SwiftDraw with these would crash the process
        }
        // Nested <svg> reaches the same conversion.
        XCTAssertNotNil(svgRejection(svg("<svg width=\"1e30\" height=\"1e30\"><rect width=\"1\" height=\"1\"/></svg>")))
        // Ordinary units and exponents still render.
        for attrs in ["width=\"64px\" height=\"32px\"", "width=\"1e2\" height=\"50\"", "width=\"2em\" height=\"1em\"",
                      "width=\"2.5in\" height=\"1in\""] {
            guard case .success = LogoSanitizer.sanitize(svgUri(svg("<rect width=\"1\" height=\"1\"/>", attrs: attrs))) else {
                return XCTFail(attrs)
            }
        }
    }

    // SwiftDraw 0.29.0 re-processes nested <svg> children at every level (exponential: 20 levels = 55 s).
    func testNestedSvgElementsRefused() {
        var s = ""
        for _ in 0..<20 { s += "<svg width=\"8\" height=\"8\">" }
        s += "<rect width=\"1\" height=\"1\"/>"
        for _ in 0..<20 { s += "</svg>" }
        let t0 = Date()
        XCTAssertEqual(svgRejection(svg(s)), .activeContent)
        XCTAssertLessThan(Date().timeIntervalSince(t0), 2)
        XCTAssertEqual(svgRejection(svg("<svg width=\"8\" height=\"8\"/>")), .activeContent) // even one
    }

    func testElementCountAndDepthCapped() {
        let many = svg(String(repeating: "<rect width=\"1\" height=\"1\"/>", count: SvgActiveContentGuard.maxElements + 1))
        XCTAssertLessThan(many.utf8.count, LogoSanitizer.maxDecodedBytes)
        XCTAssertEqual(svgRejection(many), .tooLarge)
        let deep = svg(String(repeating: "<g>", count: SvgActiveContentGuard.maxDepth + 1) + String(repeating: "</g>", count: SvgActiveContentGuard.maxDepth + 1))
        XCTAssertEqual(svgRejection(deep), .tooLarge)
        let ok = svg(String(repeating: "<rect width=\"1\" height=\"1\"/>", count: 500))
        guard case .success = LogoSanitizer.sanitize(svgUri(ok)) else { return XCTFail("a few hundred shapes are fine") }
    }

    // MARK: Allowlist guard (deny by default), tested on the guard itself so failures are assertions.

    private static let ns = "xmlns=\"http://www.w3.org/2000/svg\""

    private func guardCheck(_ svgText: String) -> LogoRejection? { SvgActiveContentGuard.check(Data(svgText.utf8)) }

    func testStyleAttributeAndElementAreNeverAllowed() {
        // SwiftDraw prefers style="width:1e30" over the attribute and traps on it.
        for style in ["width:1e30;height:8;", "fill:red", "", "font-family:x"] {
            XCTAssertEqual(guardCheck(svg("<rect width=\"1\" height=\"1\"/>", attrs: "width=\"8\" height=\"8\" style=\"\(style)\"")), .activeContent, style)
            XCTAssertEqual(guardCheck(svg("<rect width=\"1\" height=\"1\" style=\"\(style)\"/>")), .activeContent, style)
        }
        XCTAssertEqual(guardCheck(svg("<style>rect{fill:red}</style>")), .activeContent)
        XCTAssertEqual(guardCheck(svg("<rect class=\"a\" width=\"1\" height=\"1\"/>")), .activeContent)
    }

    /// The fifth SwiftDraw crash class: @font-face -> WOFF decoder, reachable through
    /// `url (` and `u/**/rl(` spellings that a regex denylist missed.
    func testFontFaceWoffRoutesRefusedInEveryUrlSpelling() {
        var woff = Data("wOFF".utf8) + Data([0, 1, 0, 0, 0, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 44])
        woff.append(Data(count: 44 - woff.count))
        let b64 = woff.base64EncodedString()
        for url in ["url(data:font/woff;base64,\(b64))", "url (data:font/woff;base64,\(b64))",
                    "u/**/rl(data:font/woff;base64,\(b64))", "URL(data:font/woff;base64,\(b64))",
                    "url(\"data:font/woff;base64,\(b64)\")", "url(https://evil.example/f.woff)"] {
            let doc = svg("<style>@font-face{font-family:x;src:\(url)}</style><text style=\"font-family:x\">A</text>")
            XCTAssertEqual(guardCheck(doc), .activeContent, url)
            XCTAssertEqual(svgRejection(doc), .activeContent, url) // end to end: refused, never reaches SwiftDraw
        }
        // The same spellings in paint attributes.
        for fill in ["url (#g)", "u/**/rl(#g)", "url( #g)", "url(#g )", "url('#g')", "url(data:image/png;base64,AAAA)",
                     "url(https://evil.example/p.svg#a)", "url(#g) /*c*/"] {
            XCTAssertEqual(guardCheck(svg("<defs><linearGradient id=\"g\"/></defs><rect width=\"1\" height=\"1\" fill=\"\(fill)\"/>")),
                           .activeContent, fill)
        }
        XCTAssertNil(guardCheck(svg("<defs><linearGradient id=\"g\"/></defs><rect width=\"1\" height=\"1\" fill=\"url(#g) #fff\"/>")))
    }

    func testCommentsInsideValuesAndTextOutsideTitleRefused() {
        XCTAssertEqual(guardCheck(svg("<rect width=\"1\" height=\"1\" fill=\"/*x*/red\"/>")), .activeContent)
        XCTAssertEqual(guardCheck(svg("<rect width=\"1\" height=\"1\" transform=\"scale(1)/**/\"/>")), .activeContent)
        XCTAssertEqual(guardCheck(svg("<g>hello</g>")), .activeContent)
        XCTAssertEqual(guardCheck(svg("<g><![CDATA[x]]></g>")), .activeContent)
        XCTAssertEqual(guardCheck(svg("<text>A</text>")), .activeContent)
        XCTAssertNil(guardCheck(svg("<title>Acme</title><desc>logo</desc><!-- generator: x --><rect width=\"1\" height=\"1\"/>")))
    }

    func testNotAllowlistedElementsAttributesAndNamespacesRefused() {
        for el in ["text", "tspan", "use", "image", "pattern", "mask", "filter", "marker", "symbol", "switch", "style", "script",
                   "foreignObject", "a", "animate", "set", "font", "font-face", "view", "metadata", "sodipodi:namedview"] {
            XCTAssertEqual(guardCheck(svg("<\(el)/>")), .activeContent, el)
        }
        for attr in ["onload=\"x\"", "xml:space=\"preserve\"", "xlink:href=\"#a\"", "href=\"#a\"", "inkscape:label=\"x\"",
                     "font-size=\"12\"", "mask=\"url(#m)\"", "filter=\"url(#f)\"", "marker-end=\"url(#m)\"", "enable-background=\"new\""] {
            XCTAssertEqual(guardCheck(svg("<rect width=\"1\" height=\"1\" \(attr)/>")), .activeContent, attr)
        }
        XCTAssertEqual(guardCheck("<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:evil=\"http://evil.example\" width=\"1\" height=\"1\"/>"), .activeContent)
        XCTAssertEqual(guardCheck("<svg xmlns=\"http://evil.example/svg\" width=\"1\" height=\"1\"/>"), .activeContent)
    }

    func testAttributeValueGrammarRejectsMalformedValues() {
        for (attr, value) in [("fill", "javascript:alert(1)"), ("fill", "red;x"), ("stroke-width", "1e30"), ("opacity", "abc"),
                              ("d", "M0 0 evil(1)"), ("transform", "scale(1) evil(2)"), ("points", "1,2,x"),
                              ("stroke-linecap", "inherit"), ("clip-path", "url(https://x/y)"), ("display", "block"),
                              ("id", "1bad id"), ("stroke-dasharray", "1,2,evil")] {
            XCTAssertEqual(guardCheck(svg("<path \(attr)=\"\(value)\"/>")), .activeContent, "\(attr)=\(value)")
        }
    }

    // Positive: typical simple logos still pass, and render.
    func testRealisticLogosPassTheAllowlistAndRender() {
        let logos = [
            "<svg \(Self.ns) viewBox=\"0 0 100 100\" width=\"100\" height=\"100\"><title>Dot</title><circle cx=\"50\" cy=\"50\" r=\"40\" fill=\"#0a84ff\" stroke=\"#003\" stroke-width=\"4\"/></svg>",
            "<svg \(Self.ns) xmlns:xlink=\"http://www.w3.org/1999/xlink\" width=\"120\" height=\"60\" viewBox=\"0 0 120 60\"><defs><linearGradient id=\"a\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"0\"><stop offset=\"0\" stop-color=\"#f00\"/><stop offset=\"100%\" stop-color=\"rgb(0,0,255)\" stop-opacity=\"0.8\"/></linearGradient><linearGradient id=\"b\" xlink:href=\"#a\"/></defs><rect width=\"120\" height=\"60\" rx=\"8\" fill=\"url(#a)\"/></svg>",
            "<svg \(Self.ns) width=\"64\" height=\"64\" viewBox=\"0 0 64 64\"><g transform=\"translate(32 32) rotate(45)\" fill=\"none\" stroke=\"black\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M-20,-20 L20,-20 L20,20 Z\" fill-rule=\"evenodd\"/><ellipse rx=\"10\" ry=\"5\" opacity=\".5\"/><line x1=\"-5\" y1=\"0\" x2=\"5\" y2=\"0\" stroke-dasharray=\"2 1\"/></g></svg>",
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><svg \(Self.ns) width=\"32\" height=\"32\" viewBox=\"0 0 32 32\"><defs><radialGradient id=\"r\" cx=\"0.5\" cy=\"0.5\" r=\"0.5\"><stop offset=\"0\" stop-color=\"white\"/><stop offset=\"1\" stop-color=\"#123456\"/></radialGradient></defs><polygon points=\"0,0 32,0 16,32\" fill=\"url(#r)\"/><polyline points=\"0,32 16,16 32,32\" fill=\"none\" stroke=\"gray\"/></svg>",
        ]
        for (i, doc) in logos.enumerated() {
            XCTAssertNil(guardCheck(doc), "logo \(i)")
            guard case .success(.image(let data)) = LogoSanitizer.sanitize(svgUri(doc)) else { return XCTFail("logo \(i) must render") }
            XCTAssertEqual(Array(data.prefix(4)), [0x89, 0x50, 0x4E, 0x47])
        }
    }

    // MARK: Path data / transform / points / colour / href: SwiftDraw 0.29.0 behaviours (verified on the Mac mini)

    /// `M0 0Z0` makes SwiftDraw loop forever (hang + memory growth); the other bad inputs are in
    /// `LogoSanitizerTests.testPathDataGrammar*`. Guard only: these documents never reach SwiftDraw.
    func testGuardRefusesHangingAndTrappingPaths() {
        for d in ["M0 0Z0", "M0 0 L4 0 L4 4 Z 5", "M0 0Z,", "M0 0 Z , L1 1", "M0 0 ß", "M0 0Zſ1 2 3 4"] {
            XCTAssertEqual(guardCheck(svg("<path d=\"\(d)\" fill=\"red\"/>")), .activeContent, d)
        }
        XCTAssertNil(guardCheck(svg("<path d=\"M0 0 L8 0 L8 8 Z\" fill=\"red\"/>")))
    }

    func testDocumentWideSegmentBudgetAndHugePathsRefusedByTheGuard() {
        XCTAssertNotNil(guardCheck(svg("<path d=\"M0 0" + String(repeating: "Z", count: 99_000) + "\"/>")))
        let one = "<path d=\"M0 0 " + String(repeating: "L1 1 ", count: 3000) + "\"/>" // fine alone
        XCTAssertNil(guardCheck(svg(one)))
        XCTAssertEqual(guardCheck(svg(String(repeating: one, count: 2))), .tooLarge, "2 x 3000 > the 5000 document cap")
    }

    func testTransformAndPointsAreValidatedStrictly() {
        for t in ["scale(2)", "scale(2 3)", "translate(1,2) rotate(45)", "rotate(10 4 4)", "matrix(1 0 0 1 5 5)", "skewX(10) skewY(5)",
                  " translate( 1 , 2 ) "] { XCTAssertTrue(SvgActiveContentGuard.isValidTransform(t), t) }
        for t in ["", "scale(", "scale()", "scale(1 2 3)", "rotate(1 2)", "matrix(1 2 3)", "translate(1 2 3)", "skewX(1 2)", "evil(1)",
                  "scale(1) junk", "scale(1e30)", "scale(1)/**/", "scale(a)"] { XCTAssertFalse(SvgActiveContentGuard.isValidTransform(t), t) }
        XCTAssertNil(guardCheck(svg("<polygon points=\"0,0 8,0 4,8\" fill=\"red\"/>")))
        for pts in ["0,0 4,4 5", "1 2 3", "1,2,x", "", "1 2 1e30 3"] {
            XCTAssertNotNil(guardCheck(svg("<polyline points=\"\(pts)\"/>")), pts) // odd count / bad number
        }
        XCTAssertNotNil(guardCheck(svg("<defs><linearGradient id=\"g\"><stop offset=\"abc\" stop-color=\"red\"/></linearGradient></defs>")))
    }

    /// SwiftDraw 0.29.0 reads #ff000080 as opaque navy and #f008 as opaque green; rgba() is correct.
    func testAlphaHexColoursRefusedRgbaAccepted() {
        for c in ["#ff000080", "#f008", "#FF0000FF"] {
            XCTAssertEqual(guardCheck(svg("<rect width=\"8\" height=\"8\" fill=\"\(c)\"/>")), .activeContent, c)
            XCTAssertEqual(guardCheck(svg("<rect width=\"8\" height=\"8\" stop-color=\"\(c)\"/>")), .activeContent, c)
        }
        for c in ["#f00", "#ff0000", "rgba(255,0,0,0.5)", "rgb(255, 0, 0)"] {
            XCTAssertNil(guardCheck(svg("<rect width=\"8\" height=\"8\" fill=\"\(c)\"/>")), c)
        }
        guard case .success(.image(let data)) = LogoSanitizer.sanitize(svgUri(svg("<rect width=\"64\" height=\"32\" fill=\"rgba(255,0,0,0.5)\"/>"))) else { return XCTFail() }
        let px = pixel(data, x: 10, y: 10)
        XCTAssertEqual(px[0], px[3], accuracy: 2, "half transparent red (premultiplied)")
        XCTAssertEqual(px[1], 0); XCTAssertEqual(px[2], 0)
        XCTAssertGreaterThan(px[3], 100); XCTAssertLessThan(px[3], 160)
    }

    /// SwiftDraw 0.29.0 reads only xlink:href: a plain href silently stops inheriting.
    func testGradientInheritanceViaXlinkHrefWorksPlainHrefRefused() {
        func doc(_ link: String) -> String {
            svg("<defs><linearGradient id=\"a\" x1=\"0\" x2=\"1\"><stop offset=\"0\" stop-color=\"#ff0000\"/><stop offset=\"1\" stop-color=\"#ff0000\"/></linearGradient><linearGradient id=\"b\" \(link)=\"#a\"/></defs><rect width=\"64\" height=\"32\" fill=\"url(#b)\"/>")
        }
        XCTAssertEqual(guardCheck(doc("href")), .activeContent)
        XCTAssertNil(guardCheck(doc("xlink:href")))
        guard case .success(.image(let data)) = LogoSanitizer.sanitize(svgUri(doc("xlink:href"))) else { return XCTFail() }
        let px = pixel(data, x: 10, y: 10)
        XCTAssertEqual(px[0], 255); XCTAssertEqual(px[3], 255, "inherited stops paint the rect")
    }

    // MARK: Flat caps (replace the earlier per-use accounting that kept leaking)

    /// clipPath/clip-path are gone: SwiftDraw rebuilds a clip path for every user (5,000 segments x 4,000 uses = 9.6 s).
    func testClipPathIsRefusedEntirely() {
        XCTAssertEqual(guardCheck(svg("<defs><clipPath id=\"c\"><rect width=\"4\" height=\"4\"/></clipPath></defs><rect width=\"4\" height=\"4\" clip-path=\"url(#c)\"/>")), .activeContent)
        XCTAssertEqual(guardCheck(svg("<rect width=\"4\" height=\"4\" clip-path=\"url(#c)\"/>")), .activeContent)
        XCTAssertEqual(guardCheck(svg("<defs><clipPath id=\"c\"/></defs>")), .activeContent)
        XCTAssertEqual(guardCheck(svg("<rect width=\"4\" height=\"4\" clip-path=\" url(#c)\"/>")), .activeContent, "any spelling")
    }

    /// Whitespace variants of url(...) used to bypass the id extraction that fed the budget.
    func testWhitespaceAroundUrlNeverEvadesTheLimits() {
        let grad = "<defs><linearGradient id=\"g\"><stop offset=\"0\" stop-color=\"red\"/></linearGradient></defs>"
        for fill in [" url(#g)", "url(#g) ", "\turl(#g)", "\nurl(#g)", "url(#g)\n", "  url(#g)  "] {
            // On a leaf the value is either valid or refused; on a group it is always refused.
            XCTAssertEqual(guardCheck(svg(grad + "<g fill=\"\(fill)\"><rect width=\"4\" height=\"4\"/></g>")), .activeContent, fill.debugDescription)
            XCTAssertEqual(guardCheck(svg(grad + "<g stroke=\"\(fill)\"/>")), .activeContent, fill.debugDescription)
        }
        XCTAssertEqual(guardCheck("<svg \(Self.ns) width=\"8\" height=\"8\" fill=\" url(#g)\"/>"), .activeContent, "root")
    }

    /// A paint reference on a group or the root is inherited by every descendant: refused, so no accounting is needed.
    func testGradientPaintIsOnlyAllowedOnLeafShapes() {
        let grad = "<defs><linearGradient id=\"g\"><stop offset=\"0\" stop-color=\"red\"/></linearGradient></defs>"
        XCTAssertEqual(guardCheck(svg(grad + "<g fill=\"url(#g)\">" + String(repeating: "<rect width=\"4\" height=\"4\"/>", count: 100) + "</g>")), .activeContent)
        XCTAssertEqual(guardCheck("<svg \(Self.ns) width=\"8\" height=\"8\" stroke=\"url(#g)\">\(grad)<rect width=\"4\" height=\"4\"/></svg>"), .activeContent)
        XCTAssertEqual(guardCheck(svg(grad + "<defs fill=\"url(#g)\"/>")), .activeContent)
        for leaf in ["path d=\"M0 0 L1 1\"", "rect width=\"4\" height=\"4\"", "circle r=\"2\"", "ellipse rx=\"2\" ry=\"1\"", "line x2=\"4\"",
                     "polyline points=\"0,0 4,4\"", "polygon points=\"0,0 4,0 4,4\""] {
            XCTAssertNil(guardCheck(svg(grad + "<\(leaf) fill=\"url(#g)\" stroke=\"url(#g) red\"/>")), leaf)
        }
    }

    func testGradientAndStopCountsAreCapped() {
        func gradients(_ n: Int, stopsEach: Int) -> String {
            (0..<n).map { i in "<linearGradient id=\"g\(i)\">" + String(repeating: "<stop offset=\"0\" stop-color=\"red\"/>", count: stopsEach) + "</linearGradient>" }.joined()
        }
        XCTAssertNil(guardCheck(svg("<defs>" + gradients(SvgActiveContentGuard.maxGradients, stopsEach: 2) + "</defs>")))
        XCTAssertEqual(guardCheck(svg("<defs>" + gradients(SvgActiveContentGuard.maxGradients + 1, stopsEach: 1) + "</defs>")), .tooLarge)
        XCTAssertNil(guardCheck(svg("<defs>" + gradients(1, stopsEach: SvgActiveContentGuard.maxStops) + "</defs>")))
        XCTAssertEqual(guardCheck(svg("<defs>" + gradients(1, stopsEach: SvgActiveContentGuard.maxStops + 1) + "</defs>")), .tooLarge)
        XCTAssertEqual(guardCheck(svg("<defs>" + gradients(4, stopsEach: 17) + "</defs>")), .tooLarge, "68 stops in total")
    }

    /// SwiftDraw resolves the FIRST of two elements with the same id; our accounting used to see the last.
    func testDuplicateIdsAreRefused() {
        XCTAssertEqual(guardCheck(svg("<defs><linearGradient id=\"g\"/><linearGradient id=\"g\" xlink:href=\"#h\"/></defs>")), .activeContent)
        XCTAssertEqual(guardCheck(svg("<rect id=\"a\" width=\"1\" height=\"1\"/><circle id=\"a\" r=\"1\"/>")), .activeContent)
        XCTAssertNil(guardCheck(svg("<rect id=\"a\" width=\"1\" height=\"1\"/><circle id=\"b\" r=\"1\"/>")))
    }

    /// CoreGraphics is quadratic in overlapping curves (1000 same-point cubics = 0.8 s, 2000 = 3.5 s): curves have their own cap.
    func testCurveSegmentsAreCappedPerDocument() {
        let cap = SvgPathData.maxDocumentCurves
        func curves(_ n: Int, cmd: String = "C1 1 2 2 3 0 ") -> String { "<path d=\"M0 0 " + String(repeating: cmd, count: n) + "\"/>" }
        XCTAssertNil(guardCheck(svg(curves(cap))))
        XCTAssertEqual(guardCheck(svg(curves(cap + 1))), .tooLarge)
        XCTAssertEqual(guardCheck(svg(curves(cap + 1, cmd: "Q1 1 3 0 "))), .tooLarge)
        XCTAssertEqual(guardCheck(svg(curves(cap + 1, cmd: "A5 5 0 0 1 3 3 "))), .tooLarge)
        XCTAssertEqual(guardCheck(svg(curves(cap) + curves(2))), .tooLarge, "curves add up across paths")
        // Implicit repeats count too, lines do not.
        XCTAssertEqual(guardCheck(svg("<path d=\"M0 0 C" + String(repeating: "1 1 2 2 3 0 ", count: cap + 1) + "\"/>")), .tooLarge)
        XCTAssertNil(guardCheck(svg("<path d=\"M0 0 " + String(repeating: "L1 1 ", count: 4000) + "\"/>")))
        XCTAssertEqual(SvgPathData.analyze("M0 0 C1 1 2 2 3 3 4 4 5 5 6 6 L1 1 Q1 1 2 2 A1 1 0 0 1 2 2 Z", maxNumber: 1e6)?.curves, 4)
    }

    /// The largest document the caps admit (600 overlapping cubics, 1500 zig-zag lines, 2000 gradient circles, dashed strokes)
    /// must go through guard + SwiftDraw + PNG in well under a second on a release build (measured 0.6 s debug-free on the Mac mini);
    /// the bound here is generous so only a real regression (multi-second work) fails.
    func testLargestAdmittedDocumentRendersQuickly() {
        let cubics = "<path d=\"M0 0 " + String(repeating: "C1 1 2 2 3 0 ", count: SvgPathData.maxDocumentCurves) + "\" fill=\"red\" stroke=\"blue\" stroke-dasharray=\"0.2 0.2\"/>"
        let zig = "<path d=\"M0 0 " + (0..<1500).map { $0 % 2 == 0 ? "L60 \($0 % 60) " : "L0 \(($0 * 7) % 60) " }.joined() + "\" fill=\"red\" stroke=\"blue\"/>"
        let stops = (0..<SvgActiveContentGuard.maxStops).map { "<stop offset=\"\(Double($0) / 63)\" stop-color=\"#\(String(format: "%02x", $0 * 3 % 256))40ff\"/>" }.joined()
        let grad = "<defs><linearGradient id=\"g\">\(stops)</linearGradient></defs>"
        let circles = (0..<2000).map { "<circle cx=\"\($0 % 60)\" cy=\"\($0 / 60)\" r=\"2\" fill=\"url(#g)\" stroke=\"url(#g)\"/>" }.joined()
        let doc = svg(grad + cubics + zig + circles)
        XCTAssertLessThan(doc.utf8.count, LogoSanitizer.maxDecodedBytes)
        let t0 = Date()
        guard case .success(.image) = LogoSanitizer.sanitize(svgUri(doc)) else { return XCTFail("the largest admitted document must render") }
        let elapsed = Date().timeIntervalSince(t0)
        print("LARGEST-ADMITTED-DOC elapsed=\(elapsed)s bytes=\(doc.utf8.count)")
        XCTAssertLessThan(elapsed, 5.0)
    }

    /// Path segments, polygon/polyline points and shapes share ONE document-wide geometry cap.
    func testGeometryCapCountsPointsPathsAndShapesTogether() {
        let cap = SvgPathData.maxDocumentSegments
        let points = (0..<(cap + 10)).map { "\($0 % 50),\($0 % 40)" }.joined(separator: " ")
        XCTAssertEqual(guardCheck(svg("<polyline points=\"\(points)\"/>")), .tooLarge, "points beyond the cap")
        XCTAssertEqual(guardCheck(svg("<polygon points=\"\(points)\"/>")), .tooLarge)
        let half = (0..<(cap / 2 + 1)).map { "\($0 % 50),\($0 % 40)" }.joined(separator: " ")
        XCTAssertEqual(guardCheck(svg("<polygon points=\"\(half)\"/><polygon points=\"\(half)\"/>")), .tooLarge, "two polygons add up")
        let path = "M0 0 " + String(repeating: "L1 1 ", count: cap / 2)
        XCTAssertEqual(guardCheck(svg("<path d=\"\(path)\"/><polygon points=\"\(half)\"/><path d=\"\(path)\"/>")), .tooLarge, "paths and points add up")
        XCTAssertEqual(guardCheck(svg(String(repeating: "<rect width=\"1\" height=\"1\"/>", count: cap + 1))), .tooLarge)
        XCTAssertNil(guardCheck(svg("<path d=\"\(path)\"/><polygon points=\"0,0 4,0 4,4\"/>")))
    }

    /// Adjacent variable-length digit runs backtrack quadratically on long invalid input; rejection must stay linear.
    func testLongInvalidNumericAttributesAreRejectedInLinearTime() {
        let digits = String(repeating: "1", count: 300_000)
        let cases: [(String, String)] = [("width", digits + "x"), ("stroke-width", digits + "x"), ("opacity", digits + "x"),
                                          ("x", digits + "." + digits + "x"), ("offset", digits + "%x"), ("fill", "rgb(" + digits + "x"),
                                          ("stroke-miterlimit", digits + "e"), ("viewBox", digits + " 0 1 1x")]
        // Run on a worker with a watchdog: a backtracking regression fails cleanly instead of hanging the suite.
        let done = DispatchSemaphore(value: 0)
        let results = LogoRemoteSvgTests.Locked<[Bool]>([])
        let t0 = Date()
        Thread {
            for (attr, value) in cases {
                // Validate OUTSIDE the lock; the lock only guards storing the result, so a hang cannot block the reader.
                let refused = SvgActiveContentGuard.attributeProblem(element: "rect", [attr: value], isRoot: false) != nil
                results.modify { $0.append(refused) }
            }
            done.signal()
        }.start()
        let finished = done.wait(timeout: .now() + 5) == .success
        XCTAssertTrue(finished, "eight 300 KB invalid values must be rejected in linear time (backtracking regression?)")
        if finished { XCTAssertEqual(results.value, Array(repeating: true, count: cases.count)) }
        XCTAssertLessThan(Date().timeIntervalSince(t0), 2.0)
    }

    func testSvgSameDocumentFragmentsAndInternalUrlAllowed() {
        let s = svg("<defs><linearGradient id=\"g\"><stop offset=\"0\" stop-color=\"#f00\"/><stop offset=\"1\" stop-color=\"#00f\"/></linearGradient></defs><rect width=\"64\" height=\"32\" fill=\"url(#g)\"/>")
        guard case .success(.image) = LogoSanitizer.sanitize(svgUri(s)) else { return XCTFail() }
    }

    func testMalformedOrNonSvgXmlRefused() {
        XCTAssertEqual(svgRejection("<svg xmlns=\"http://www.w3.org/2000/svg\"><rect></svg>"), .invalidSvg)
        XCTAssertEqual(svgRejection("<html><body/></html>"), .invalidSvg)
        XCTAssertEqual(svgRejection("not xml at all"), .invalidSvg)
        XCTAssertEqual(svgRejection(svg("<g>&undefined;</g>")), .invalidSvg)
        XCTAssertEqual(svgRejection(" "), .invalidSvg)
    }

    func testSvgSizeCapAppliesToPayload() {
        let big = svg("<!--" + String(repeating: "a", count: LogoSanitizer.maxDecodedBytes) + "--><rect/>")
        XCTAssertEqual(svgRejection(big), .tooLarge)
    }

    // (1) SVG without a declared type is routed by a content sniff, still through the guard.
    func testSvgWithoutDeclaredTypeIsRoutedToTheSvgPath() {
        let plain = Data(svg("<rect width=\"64\" height=\"32\" fill=\"#f00\"/>").utf8)
        let decorated = Data([0xEF, 0xBB, 0xBF] + Array("<?xml version=\"1.0\"?>\n<!-- made by x -->\n".utf8) + Array(plain))
        for d in [plain, decorated] {
            guard case .success(.image) = LogoSanitizer.sanitize(imageData: d) else { return XCTFail("untyped svg must render") }
        }
        // The sniff only routes: an evil SVG still dies in the guard, and non-SVG junk is still undecodable.
        let evil = Data(svg("<script>alert(1)</script>").utf8)
        if case .failure(.activeContent) = LogoSanitizer.sanitize(imageData: evil) {} else { XCTFail("evil untyped svg") }
        if case .failure(.undecodable) = LogoSanitizer.sanitize(imageData: Data("<html><svg/></html>".utf8)) {} else { XCTFail("html is not svg") }
        if case .failure(.undecodable) = LogoSanitizer.sanitize(imageData: Data("<svgfoo/>".utf8)) {} else { XCTFail("<svgfoo> is not svg") }
        XCTAssertTrue(LogoSanitizer.looksLikeSvg(Data("<svg>".utf8)))
        XCTAssertFalse(LogoSanitizer.looksLikeSvg(Data("PNG".utf8)))
    }

    func testSvgImageDataPathUsesSameGuard() {
        let evil = Data(svg("<script>alert(1)</script>").utf8)
        if case .failure(.activeContent) = LogoSanitizer.sanitize(imageData: evil, declaredMediaType: "image/svg+xml") {} else {
            XCTFail("fetched SVG must go through the guard")
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
        let bad = "javascript:alert(1)"
        let bad2 = "http://example.org/a.png"
        let r1 = await cache.resolve(bad)
        let r2 = await cache.resolve(bad)
        let r3 = await cache.resolve(bad2)
        XCTAssertNil(r1)
        XCTAssertNil(r2)
        XCTAssertNil(r3)
        let count = await cache.sanitizeCount
        XCTAssertEqual(count, 2, "each distinct URI sanitized once")
    }

    func testCacheIsBounded() async {
        let cache = LogoCache(capacity: 2)
        for i in 0..<5 { _ = await cache.resolve("javascript:\(i)") }
        _ = await cache.resolve("javascript:0") // evicted, sanitized again
        let count = await cache.sanitizeCount
        XCTAssertEqual(count, 6)
    }
}

#if canImport(ImageIO)
/// https SVG logos are fetched, guarded and rendered (stubbed network).
final class LogoRemoteSvgTests: XCTestCase {
    /// Lock-protected box: the stub's state is touched from URLSession callback queues and the test thread.
    final class Locked<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: T
        init(_ value: T) { stored = value }
        var value: T {
            get { lock.lock(); defer { lock.unlock() }; return stored }
            set { lock.lock(); defer { lock.unlock() }; stored = newValue }
        }
        @discardableResult func modify<R>(_ body: (inout T) -> R) -> R { lock.lock(); defer { lock.unlock() }; return body(&stored) }
    }

    final class StubProtocol: URLProtocol, @unchecked Sendable {
        private static let _body = Locked(Data())
        private static let _type = Locked("image/svg+xml")
        private static let _status = Locked(200)
        private static let _declaredLength = Locked<Int?>(nil)
        private static let _delay = Locked<TimeInterval>(0)
        private static let _redirects = Locked<[String: String]>([:])
        private static let _requested = Locked<[String]>([])
        private static let _trickleChunks = Locked(0)
        private static let _trickleInterval = Locked<TimeInterval>(0.05)
        private static let _chunksSent = Locked(0)
        private static let _stopLoadingCalls = Locked(0)
        private static let _failWith = Locked<URLError.Code?>(nil)
        /// Bumped by reset(): a delayed callback from an earlier test sees a different generation and does nothing.
        private static let _generation = Locked(0)

        static var body: Data { get { _body.value } set { _body.value = newValue } }
        static var type: String { get { _type.value } set { _type.value = newValue } }
        static var status: Int { get { _status.value } set { _status.value = newValue } }
        static var declaredLength: Int? { get { _declaredLength.value } set { _declaredLength.value = newValue } }
        static var delay: TimeInterval { get { _delay.value } set { _delay.value = newValue } }
        static var redirects: [String: String] { get { _redirects.value } set { _redirects.value = newValue } }
        static var requested: [String] { _requested.value }
        /// >0: send the body as this many 1-byte chunks, `trickleInterval` apart.
        static var trickleChunks: Int { get { _trickleChunks.value } set { _trickleChunks.value = newValue } }
        static var trickleInterval: TimeInterval { get { _trickleInterval.value } set { _trickleInterval.value = newValue } }
        static var chunksSent: Int { _chunksSent.value }
        static var stopLoadingCalls: Int { _stopLoadingCalls.value }
        static var failWith: URLError.Code? { get { _failWith.value } set { _failWith.value = newValue } }

        static func reset() {
            _generation.modify { $0 += 1 }
            body = Data(); type = "image/svg+xml"; status = 200; declaredLength = nil
            delay = 0; redirects = [:]; _requested.value = []
            trickleChunks = 0; trickleInterval = 0.05; _chunksSent.value = 0; _stopLoadingCalls.value = 0; failWith = nil
        }

        private let generation = StubProtocol._generation.value
        private let stopped = Locked(false)
        private var live: Bool { !stopped.value && generation == Self._generation.value }

        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
        override func startLoading() {
            let url = request.url!
            Self._requested.modify { $0.append(url.absoluteString) }
            if let code = Self.failWith {
                client?.urlProtocol(self, didFailWithError: URLError(code))
                return
            }
            if let target = Self.redirects[url.absoluteString], let t = URL(string: target) {
                let r = HTTPURLResponse(url: url, statusCode: 302, httpVersion: nil, headerFields: ["Location": target])!
                client?.urlProtocol(self, wasRedirectedTo: URLRequest(url: t), redirectResponse: r)
                // If the delegate refused the redirect nobody calls stopLoading;
                // like a real HTTP stack, then deliver the 3xx as the final answer.
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { [self] in
                    guard live else { return }
                    client?.urlProtocol(self, didReceive: r, cacheStoragePolicy: .notAllowed)
                    client?.urlProtocolDidFinishLoading(self)
                }
                return
            }
            // Snapshot the fixture now: a delayed delivery must not read a later test's state.
            let body = Self.body, type = Self.type, status = Self.status, declared = Self.declaredLength
            let chunks = Self.trickleChunks, interval = Self.trickleInterval, delay = Self.delay
            let work = { [self] in
                guard live else { return }
                var headers = ["Content-Type": type]
                if let n = declared { headers["Content-Length"] = String(n) }
                let r = HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: headers)!
                client?.urlProtocol(self, didReceive: r, cacheStoragePolicy: .notAllowed)
                if chunks > 0 { trickle(remaining: chunks, interval: interval); return }
                client?.urlProtocol(self, didLoad: body)
                client?.urlProtocolDidFinishLoading(self)
            }
            if delay > 0 {
                DispatchQueue.global().asyncAfter(deadline: .now() + delay, execute: work)
            } else { work() }
        }

        override func stopLoading() {
            stopped.value = true
            if generation == Self._generation.value { Self._stopLoadingCalls.modify { $0 += 1 } }
        }

        private func trickle(remaining: Int, interval: TimeInterval) {
            guard live else { return }
            guard remaining > 0 else { client?.urlProtocolDidFinishLoading(self); return }
            client?.urlProtocol(self, didLoad: Data([0x41]))
            Self._chunksSent.modify { $0 += 1 }
            DispatchQueue.global().asyncAfter(deadline: .now() + interval) { [self] in
                trickle(remaining: remaining - 1, interval: interval)
            }
        }
    }

    override func setUp() { StubProtocol.reset() }
    override func tearDown() { StubProtocol.reset() } // also invalidates any still-pending delayed callbacks

    /// Condition-based wait (no fixed sleeps): polls until `condition` holds or `timeout` passes.
    private func waitUntil(timeout: TimeInterval = 5, _ condition: () -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while !condition() {
            if Date() > deadline { return false }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return true
    }

    private var session: URLSession {
        let c = URLSessionConfiguration.ephemeral
        c.protocolClasses = [StubProtocol.self]
        return URLSession(configuration: c)
    }

    func testRemoteSvgGoesThroughGuardAndRender() async {
        StubProtocol.status = 200; StubProtocol.type = "image/svg+xml"
        StubProtocol.body = Data("<svg xmlns='http://www.w3.org/2000/svg' width='8' height='8'><rect width='8' height='8'/></svg>".utf8)
        let url = URL(string: "https://example.org/logo.svg")!
        guard case .success(.image) = await LogoSanitizer.fetchAndSanitize(url, session: session) else { return XCTFail() }
        let cache = LogoCache(session: session)
        let viaCache = await cache.resolve("https://example.org/logo.svg")
        guard case .image? = viaCache else { return XCTFail("cache must resolve remote svg to an image") }
    }

    func testRemoteMaliciousSvgRefused() async {
        StubProtocol.status = 200; StubProtocol.type = "image/svg+xml"
        StubProtocol.body = Data("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>".utf8)
        let url = URL(string: "https://example.org/logo.svg")!
        if case .failure(.activeContent) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail() }
        let cache = LogoCache(session: session)
        let viaCache = await cache.resolve("https://example.org/logo.svg")
        XCTAssertNil(viaCache)
    }

    func testRemoteHttpErrorOrHtmlRefused() async {
        let url = URL(string: "https://example.org/logo.svg")!
        StubProtocol.status = 404; StubProtocol.type = "image/svg+xml"; StubProtocol.body = Data("<svg/>".utf8)
        if case .failure = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("404") }
        StubProtocol.status = 200; StubProtocol.type = "text/html"
        if case .failure(.unsupportedMediaType) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("html") }
    }

    private let okSvg = Data("<svg xmlns='http://www.w3.org/2000/svg' width='8' height='8'><rect width='8' height='8'/></svg>".utf8)

    // (2) https logos are decided by the response, not the file name
    func testExtensionlessHttpsSvgAndRasterLogosAreSanitizedByContentType() async {
        let cache = LogoCache(session: session)
        StubProtocol.type = "image/svg+xml"; StubProtocol.body = okSvg
        let svgLogo = await cache.resolve("https://example.org/logo")
        guard case .image? = svgLogo else { return XCTFail("extensionless svg must render") }

        let ctx = CGContext(data: nil, width: 8, height: 8, bitsPerComponent: 8, bytesPerRow: 0, space: CGColorSpace(name: CGColorSpace.sRGB)!,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        let out = NSMutableData()
        let dest = CGImageDestinationCreateWithData(out, "public.png" as CFString, 1, nil)!
        CGImageDestinationAddImage(dest, ctx.makeImage()!, nil); CGImageDestinationFinalize(dest)
        StubProtocol.type = "image/png"; StubProtocol.body = out as Data
        let pngLogo = await cache.resolve("https://example.org/logo.png")
        guard case .image? = pngLogo else { return XCTFail("https raster logos are fetched and re-encoded too") }

        StubProtocol.type = "text/html"; StubProtocol.body = Data("<html/>".utf8)
        let html = await cache.resolve("https://example.org/not-an-image")
        XCTAssertNil(html)
        StubProtocol.type = "image/svg+xml"; StubProtocol.body = Data("<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>".utf8)
        let evil = await cache.resolve("https://example.org/evil")
        XCTAssertNil(evil)
    }

    // (1) a fetched SVG without Content-Type
    func testFetchedSvgWithoutContentTypeIsStillSanitized() async {
        StubProtocol.type = ""; StubProtocol.body = okSvg
        guard case .success(.image) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/logo")!, session: session) else { return XCTFail() }
        StubProtocol.body = Data("<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>".utf8)
        if case .failure(.activeContent) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/logo")!, session: session) {} else { XCTFail() }
    }

    // (2) transport errors keep their meaning
    func testTimeoutAndTransportErrorsAreNotReportedAsUndecodable() async {
        let url = URL(string: "https://example.org/logo.svg")!
        StubProtocol.failWith = .timedOut
        if case .failure(.timedOut) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("timedOut") }
        StubProtocol.failWith = .notConnectedToInternet
        if case .failure(.networkFailure) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("offline") }
        StubProtocol.failWith = nil; StubProtocol.status = 503
        if case .failure(.networkFailure) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("503") }
        XCTAssertTrue(LogoRejection.timedOut.isTransient); XCTAssertTrue(LogoRejection.networkFailure.isTransient)
        for definitive in [LogoRejection.undecodable, .activeContent, .tooLarge, .unsupportedMediaType, .invalidSvg, .platformUnsupported] {
            XCTAssertFalse(definitive.isTransient, "\(definitive)")
        }
    }

    // (3) only permanent outcomes are cached
    func testTransientFailuresAreNotCachedButDefinitiveOnesAre() async {
        let cache = LogoCache(session: session)
        let uri = "https://example.org/logo.svg"
        StubProtocol.failWith = .notConnectedToInternet
        let offline = await cache.resolve(uri)
        XCTAssertNil(offline)
        StubProtocol.failWith = .timedOut
        let slow = await cache.resolve(uri)
        XCTAssertNil(slow)
        StubProtocol.failWith = nil; StubProtocol.status = 502
        let bad = await cache.resolve(uri)
        XCTAssertNil(bad)
        StubProtocol.status = 200; StubProtocol.body = okSvg
        let ok = await cache.resolve(uri) // retried after three transient failures
        guard case .image? = ok else { return XCTFail("must retry after transient failures") }
        XCTAssertEqual(StubProtocol.requested.count, 4)
        _ = await cache.resolve(uri)
        XCTAssertEqual(StubProtocol.requested.count, 4, "success is cached")

        // A definitive rejection is cached: no second request.
        StubProtocol.reset()
        StubProtocol.body = Data("<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>".utf8)
        let evilUri = "https://example.org/evil.svg"
        let first = await cache.resolve(evilUri)
        let second = await cache.resolve(evilUri)
        XCTAssertNil(first); XCTAssertNil(second)
        XCTAssertEqual(StubProtocol.requested.count, 1, "definitive rejection is cached")
    }

    // (6) same authority validation as sanitize(_:), before any request
    func testFetchRejectsUserinfoWithoutRequest() async {
        StubProtocol.body = okSvg
        let url = URL(string: "https://user:pw@example.org/logo.svg")!
        if case .failure(.invalidRemoteUrl) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail() }
        if case .failure(.invalidRemoteUrl) = await LogoSanitizer.fetchAndSanitize(URL(string: "http://example.org/l.svg")!, session: session) {} else { XCTFail() }
        XCTAssertEqual(StubProtocol.requested, [], "no request may leave")
        let cache = LogoCache(session: session)
        let viaCache = await cache.resolve("https://user:pw@example.org/logo.svg")
        XCTAssertNil(viaCache)
        XCTAssertEqual(StubProtocol.requested, [])
    }

    // (2) redirects obey the same policy
    func testRedirectToHttpOrUserinfoNotFollowed() async {
        StubProtocol.body = okSvg
        StubProtocol.redirects = ["https://example.org/a.svg": "http://example.org/b.svg"]
        if case .failure = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.svg")!, session: session) {} else { XCTFail("http redirect followed") }
        XCTAssertEqual(StubProtocol.requested, ["https://example.org/a.svg"], "redirect target must never be requested")

        StubProtocol.reset(); StubProtocol.body = okSvg
        StubProtocol.redirects = ["https://example.org/a.svg": "https://u:p@example.org/b.svg"]
        if case .failure = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.svg")!, session: session) {} else { XCTFail("userinfo redirect followed") }
        XCTAssertEqual(StubProtocol.requested, ["https://example.org/a.svg"])
    }

    func testRedirectToHttpsStillFollowed() async {
        StubProtocol.body = okSvg
        StubProtocol.redirects = ["https://example.org/a.svg": "https://cdn.example.org/b.svg"]
        guard case .success(.image) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.svg")!, session: session) else { return XCTFail() }
        XCTAssertEqual(StubProtocol.requested, ["https://example.org/a.svg", "https://cdn.example.org/b.svg"])
    }

    // (3) cap is enforced on Content-Length and while streaming
    func testDeclaredContentLengthOverCapRefusedBeforeReading() async {
        StubProtocol.body = okSvg // small and valid: only the header gives it away
        StubProtocol.declaredLength = LogoSanitizer.maxDecodedBytes + 1
        if case .failure(.tooLarge) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.svg")!, session: session) {} else { XCTFail() }
    }

    /// Demand-driven: counts how many bytes the consumer actually pulled.
    struct CountingBytes: AsyncSequence {
        typealias Element = UInt8
        final class Counter: @unchecked Sendable { var pulled = 0 }
        let total: Int
        let counter: Counter
        struct Iterator: AsyncIteratorProtocol {
            let total: Int
            let counter: Counter
            mutating func next() async -> UInt8? {
                guard counter.pulled < total else { return nil }
                counter.pulled += 1
                return 0x41
            }
        }
        func makeAsyncIterator() -> Iterator { Iterator(total: total, counter: counter) }
    }

    func testCollectStopsReadingAtTheCap() async throws {
        let limit = LogoSanitizer.maxDecodedBytes
        let counter = CountingBytes.Counter()
        let got = try await LogoSanitizer.collect(CountingBytes(total: limit * 20, counter: counter), limit: limit)
        XCTAssertNil(got)
        XCTAssertLessThanOrEqual(counter.pulled, limit + 1, "must pull at most one byte past the cap")
        let small = try await LogoSanitizer.collect(CountingBytes(total: 3, counter: .init()), limit: 4)
        XCTAssertEqual(small, Data([0x41, 0x41, 0x41]))
    }

    // (2) early exits cancel the download itself
    func testOversizedContentLengthCancelsTheDownload() async {
        StubProtocol.body = okSvg
        StubProtocol.declaredLength = 10_000_000
        StubProtocol.trickleChunks = 200 // 10 s of body if nobody cancels
        if case .failure(.tooLarge) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.svg")!, session: session) {} else { XCTFail() }
        let stopped = await waitUntil { StubProtocol.stopLoadingCalls > 0 }
        XCTAssertTrue(stopped, "URLSessionTask must be cancelled")
        XCTAssertLessThan(StubProtocol.chunksSent, 100, "body must stop flowing")
    }

    func testNon2xxCancelsTheDownload() async {
        StubProtocol.status = 500
        StubProtocol.trickleChunks = 200
        if case .failure = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.svg")!, session: session) {} else { XCTFail() }
        let stopped = await waitUntil { StubProtocol.stopLoadingCalls > 0 }
        XCTAssertTrue(stopped)
        XCTAssertLessThan(StubProtocol.chunksSent, 100)
    }

    // (3) wall-clock budget covers a trickle that keeps the inactivity timer alive
    func testSlowTrickleHitsWallClockTimeout() async {
        StubProtocol.trickleChunks = 400 // 20 s at 50 ms; each byte resets URLSession's idle timer
        let t0 = Date()
        let r = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.svg")!, session: session, timeout: 0.6)
        let elapsed = Date().timeIntervalSince(t0)
        if case .failure(.timedOut) = r {} else { XCTFail("expected timedOut, got \(r)") }
        XCTAssertLessThan(elapsed, 3, "deadline must fire while awaiting the next byte")
        let stopped = await waitUntil { StubProtocol.stopLoadingCalls > 0 }
        XCTAssertTrue(stopped, "timeout must cancel the download")
    }

    // (4) one in-flight fetch per URI
    func testConcurrentResolvesShareOneDownload() async {
        StubProtocol.body = okSvg
        StubProtocol.delay = 0.4
        let cache = LogoCache(session: session)
        let uri = "https://example.org/shared.svg"
        let results = await withTaskGroup(of: DisplayLogo?.self) { g in
            for _ in 0..<6 { g.addTask { await cache.resolve(uri) } }
            var out: [DisplayLogo?] = []
            for await r in g { out.append(r) }
            return out
        }
        XCTAssertEqual(results.count, 6)
        for r in results { guard case .image? = r else { return XCTFail("every caller gets the image") } }
        XCTAssertEqual(StubProtocol.requested.count, 1, "one download for six callers")
    }

    func testCancelledWaiterDoesNotPoisonSharedFlight() async {
        StubProtocol.body = okSvg
        StubProtocol.delay = 0.5
        let cache = LogoCache(session: session)
        let uri = "https://example.org/shared.svg"
        let a = Task { await cache.resolve(uri) }
        let b = Task { await cache.resolve(uri) }
        let started = await waitUntil { StubProtocol.requested.count == 1 }
        XCTAssertTrue(started)
        a.cancel()
        let bv = await b.value
        guard case .image? = bv else { return XCTFail("the surviving waiter must still get the image") }
        _ = await a.value
        XCTAssertEqual(StubProtocol.requested.count, 1)
        let again = await cache.resolve(uri)
        guard case .image? = again else { return XCTFail() }
        XCTAssertEqual(StubProtocol.requested.count, 1, "result was cached")
    }

    // (7) a cancelled resolve is not cached as a rejection
    func testCancelledResolveIsNotCached() async {
        StubProtocol.body = okSvg
        StubProtocol.delay = 3 // far longer than the test: a normal finish cannot masquerade as a cancel
        let cache = LogoCache(session: session)
        let uri = "https://example.org/slow.svg"
        let task = Task { await cache.resolve(uri) }
        let started = await waitUntil { StubProtocol.requested.count == 1 }
        XCTAssertTrue(started, "the fetch must be under way before it is cancelled")
        task.cancel()
        let cancelled = await task.value
        XCTAssertNil(cancelled)
        let stopped = await waitUntil(timeout: 2.5) { StubProtocol.stopLoadingCalls > 0 }
        XCTAssertTrue(stopped, "last waiter leaving must cancel the download")
        StubProtocol.delay = 0
        let fresh = await cache.resolve(uri)
        guard case .image? = fresh else { return XCTFail("retry after cancel must fetch again, not hit a cached nil") }
    }
}
#endif
