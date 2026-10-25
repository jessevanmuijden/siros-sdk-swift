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
        let url = URL(string: "https://example.org/a.png")!
        for bad in [TimeInterval.nan, .infinity, -1, 0] {
            if case .failure(.invalidTimeout) = await LogoSanitizer.fetchAndSanitize(url, timeout: bad) {} else { XCTFail("\(bad)") }
        }
    }

    /// SVG is refused in every spelling, on every platform, with its own rejection.
    func testSvgIsRefusedAsSvgNotSupportedEverywhere() {
        let evil = Data("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>".utf8)
        let benign = Data("<svg xmlns='http://www.w3.org/2000/svg' width='4' height='4'/>".utf8)
        for bytes in [evil, benign] {
            XCTAssertEqual(rejection("data:image/svg+xml;base64," + bytes.base64EncodedString()), .svgNotSupported)
            XCTAssertEqual(rejection("data:image/svg+xml;charset=utf-8;base64," + bytes.base64EncodedString()), .svgNotSupported)
            XCTAssertEqual(rejection("DATA:IMAGE/SVG+XML;BASE64," + bytes.base64EncodedString()), .svgNotSupported)
        }
        XCTAssertEqual(rejection("data:image/svg+xml;utf8,<svg onload='alert(1)'/>"), .svgNotSupported)
        XCTAssertEqual(rejection("data:image/svg+xml,%3Csvg%3E"), .svgNotSupported)
        // Fetched bytes: declared type, and untyped bytes that look like SVG (BOM, XML declaration, comments).
        if case .failure(.svgNotSupported) = LogoSanitizer.sanitize(imageData: benign, declaredMediaType: "image/svg+xml") {} else { XCTFail("declared") }
        if case .failure(.svgNotSupported) = LogoSanitizer.sanitize(imageData: benign) {} else { XCTFail("sniffed") }
        let decorated = Data([0xEF, 0xBB, 0xBF] + Array("<?xml version=\"1.0\"?>\n<!-- x -->\n".utf8) + Array(benign))
        if case .failure(.svgNotSupported) = LogoSanitizer.sanitize(imageData: decorated) {} else { XCTFail("sniffed with prolog") }
        // The sniff is only for the clearer message: look-alikes are not SVG.
        XCTAssertTrue(LogoSanitizer.looksLikeSvg(Data("<svg>".utf8)))
        XCTAssertFalse(LogoSanitizer.looksLikeSvg(Data("<svgfoo/>".utf8)))
        XCTAssertFalse(LogoSanitizer.looksLikeSvg(Data("<html><svg/></html>".utf8)))
        XCTAssertFalse(LogoSanitizer.looksLikeSvg(Data("PNG".utf8)))
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
/// https logos are fetched, sanitized and cached (stubbed network).
final class LogoRemoteTests: XCTestCase {
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
        private static let _type = Locked("image/png")
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
            body = Data(); type = "image/png"; status = 200; declaredLength = nil
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

    func testRemoteImageIsFetchedAndReencoded() async {
        StubProtocol.status = 200; StubProtocol.type = "image/png"; StubProtocol.body = okImage
        let url = URL(string: "https://example.org/logo.png")!
        guard case .success(.image(let data)) = await LogoSanitizer.fetchAndSanitize(url, session: session) else { return XCTFail() }
        XCTAssertEqual(Array(data.prefix(4)), [0x89, 0x50, 0x4E, 0x47])
        let cache = LogoCache(session: session)
        let viaCache = await cache.resolve("https://example.org/logo.png")
        guard case .image? = viaCache else { return XCTFail("cache must resolve a remote logo to an image, never a bare URL") }
    }

    /// SVG is refused for a remote logo too: by Content-Type, and by sniff when untyped.
    func testRemoteSvgIsRefusedByContentTypeAndBySniff() async {
        let svg = Data("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>".utf8)
        let url = URL(string: "https://example.org/logo")!
        StubProtocol.type = "image/svg+xml"; StubProtocol.body = svg
        if case .failure(.svgNotSupported) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("typed") }
        StubProtocol.type = ""; StubProtocol.body = svg
        if case .failure(.svgNotSupported) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("untyped") }
        let cache = LogoCache(session: session)
        let viaCache = await cache.resolve("https://example.org/logo")
        XCTAssertNil(viaCache)
    }

    func testRemoteHttpErrorOrHtmlRefused() async {
        let url = URL(string: "https://example.org/logo.png")!
        StubProtocol.status = 404; StubProtocol.type = "image/png"; StubProtocol.body = Data("not found".utf8)
        if case .failure = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("404") }
        StubProtocol.status = 200; StubProtocol.type = "text/html"
        if case .failure(.unsupportedMediaType) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("html") }
    }

    /// A small valid PNG (noise, so it is not trivially compressible).
    private let okImage: Data = {
        let ctx = CGContext(data: nil, width: 8, height: 8, bitsPerComponent: 8, bytesPerRow: 0, space: CGColorSpace(name: CGColorSpace.sRGB)!,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        let px = ctx.data!.bindMemory(to: UInt8.self, capacity: 8 * ctx.bytesPerRow)
        for i in 0..<(8 * ctx.bytesPerRow) { px[i] = UInt8(truncatingIfNeeded: i &* 37 &+ 11) }
        let out = NSMutableData()
        let dest = CGImageDestinationCreateWithData(out, "public.png" as CFString, 1, nil)!
        CGImageDestinationAddImage(dest, ctx.makeImage()!, nil)
        CGImageDestinationFinalize(dest)
        return out as Data
    }()

    // (2) https logos are decided by the response, not the file name
    // (2) https logos are decided by the response, not the file name
    func testHttpsLogosAreSanitizedByContentTypeNotFileName() async {
        let cache = LogoCache(session: session)
        StubProtocol.type = "image/png"; StubProtocol.body = okImage
        let noExtension = await cache.resolve("https://example.org/logo")
        guard case .image? = noExtension else { return XCTFail("extensionless raster logo must render") }
        StubProtocol.type = "text/html"; StubProtocol.body = Data("<html/>".utf8)
        let html = await cache.resolve("https://example.org/not-an-image")
        XCTAssertNil(html)
        StubProtocol.type = "image/png"; StubProtocol.body = Data("not a png".utf8)
        let garbage = await cache.resolve("https://example.org/garbage.png")
        XCTAssertNil(garbage)
    }

    // (1) a fetched raster without Content-Type is still sanitized by content
    func testFetchedImageWithoutContentTypeIsStillSanitized() async {
        StubProtocol.type = ""; StubProtocol.body = okImage
        guard case .success(.image) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/logo")!, session: session) else { return XCTFail() }
        StubProtocol.body = Data("garbage".utf8)
        if case .failure(.undecodable) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/logo")!, session: session) {} else { XCTFail() }
    }

    // (2) transport errors keep their meaning
    func testTimeoutAndTransportErrorsAreNotReportedAsUndecodable() async {
        let url = URL(string: "https://example.org/logo.png")!
        StubProtocol.failWith = .timedOut
        if case .failure(.timedOut) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("timedOut") }
        StubProtocol.failWith = .notConnectedToInternet
        if case .failure(.networkFailure) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("offline") }
        StubProtocol.failWith = nil; StubProtocol.status = 503
        if case .failure(.networkFailure) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail("503") }
        XCTAssertTrue(LogoRejection.timedOut.isTransient); XCTAssertTrue(LogoRejection.networkFailure.isTransient)
        for definitive in [LogoRejection.undecodable, .svgNotSupported, .tooLarge, .unsupportedMediaType, .platformUnsupported] {
            XCTAssertFalse(definitive.isTransient, "\(definitive)")
        }
    }

    // (3) only permanent outcomes are cached
    func testTransientFailuresAreNotCachedButDefinitiveOnesAre() async {
        let cache = LogoCache(session: session)
        let uri = "https://example.org/logo.png"
        StubProtocol.failWith = .notConnectedToInternet
        let offline = await cache.resolve(uri)
        XCTAssertNil(offline)
        StubProtocol.failWith = .timedOut
        let slow = await cache.resolve(uri)
        XCTAssertNil(slow)
        StubProtocol.failWith = nil; StubProtocol.status = 502
        let bad = await cache.resolve(uri)
        XCTAssertNil(bad)
        StubProtocol.status = 200; StubProtocol.body = okImage
        let ok = await cache.resolve(uri) // retried after three transient failures
        guard case .image? = ok else { return XCTFail("must retry after transient failures") }
        XCTAssertEqual(StubProtocol.requested.count, 4)
        _ = await cache.resolve(uri)
        XCTAssertEqual(StubProtocol.requested.count, 4, "success is cached")

        // A definitive rejection is cached: no second request.
        StubProtocol.reset()
        StubProtocol.body = Data("not an image".utf8)
        let evilUri = "https://example.org/evil.png"
        let first = await cache.resolve(evilUri)
        let second = await cache.resolve(evilUri)
        XCTAssertNil(first); XCTAssertNil(second)
        XCTAssertEqual(StubProtocol.requested.count, 1, "definitive rejection is cached")
    }

    // (6) same authority validation as sanitize(_:), before any request
    func testFetchRejectsUserinfoWithoutRequest() async {
        StubProtocol.body = okImage
        let url = URL(string: "https://user:pw@example.org/logo.png")!
        if case .failure(.invalidRemoteUrl) = await LogoSanitizer.fetchAndSanitize(url, session: session) {} else { XCTFail() }
        if case .failure(.invalidRemoteUrl) = await LogoSanitizer.fetchAndSanitize(URL(string: "http://example.org/l.png")!, session: session) {} else { XCTFail() }
        XCTAssertEqual(StubProtocol.requested, [], "no request may leave")
        let cache = LogoCache(session: session)
        let viaCache = await cache.resolve("https://user:pw@example.org/logo.png")
        XCTAssertNil(viaCache)
        XCTAssertEqual(StubProtocol.requested, [])
    }

    // (2) redirects obey the same policy
    func testRedirectToHttpOrUserinfoNotFollowed() async {
        StubProtocol.body = okImage
        StubProtocol.redirects = ["https://example.org/a.png": "http://example.org/b.png"]
        if case .failure = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.png")!, session: session) {} else { XCTFail("http redirect followed") }
        XCTAssertEqual(StubProtocol.requested, ["https://example.org/a.png"], "redirect target must never be requested")

        StubProtocol.reset(); StubProtocol.body = okImage
        StubProtocol.redirects = ["https://example.org/a.png": "https://u:p@example.org/b.png"]
        if case .failure = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.png")!, session: session) {} else { XCTFail("userinfo redirect followed") }
        XCTAssertEqual(StubProtocol.requested, ["https://example.org/a.png"])
    }

    func testRedirectToHttpsStillFollowed() async {
        StubProtocol.body = okImage
        StubProtocol.redirects = ["https://example.org/a.png": "https://cdn.example.org/b.png"]
        guard case .success(.image) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.png")!, session: session) else { return XCTFail() }
        XCTAssertEqual(StubProtocol.requested, ["https://example.org/a.png", "https://cdn.example.org/b.png"])
    }

    // (3) cap is enforced on Content-Length and while streaming
    func testDeclaredContentLengthOverCapRefusedBeforeReading() async {
        StubProtocol.body = okImage // small and valid: only the header gives it away
        StubProtocol.declaredLength = LogoSanitizer.maxDecodedBytes + 1
        if case .failure(.tooLarge) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.png")!, session: session) {} else { XCTFail() }
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
    // Content-Type is application/octet-stream in the two early-exit tests: with image/png, image/jpeg or text/plain
    // URLSession only delivers the cancellation after the (fake, 10 s) body has finished, while the early exit
    // itself happens before the type is looked at.
    func testOversizedContentLengthCancelsTheDownload() async {
        StubProtocol.type = "application/octet-stream"
        StubProtocol.body = okImage
        StubProtocol.declaredLength = 10_000_000
        StubProtocol.trickleChunks = 200 // 10 s of body if nobody cancels
        if case .failure(.tooLarge) = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.png")!, session: session) {} else { XCTFail() }
        let stopped = await waitUntil { StubProtocol.stopLoadingCalls > 0 }
        XCTAssertTrue(stopped, "URLSessionTask must be cancelled")
        XCTAssertLessThan(StubProtocol.chunksSent, 100, "body must stop flowing")
    }

    func testNon2xxCancelsTheDownload() async {
        StubProtocol.type = "application/octet-stream"
        StubProtocol.status = 500
        StubProtocol.trickleChunks = 200
        if case .failure = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.png")!, session: session) {} else { XCTFail() }
        let stopped = await waitUntil { StubProtocol.stopLoadingCalls > 0 }
        XCTAssertTrue(stopped)
        XCTAssertLessThan(StubProtocol.chunksSent, 100)
    }

    // (3) wall-clock budget covers a trickle that keeps the inactivity timer alive
    func testSlowTrickleHitsWallClockTimeout() async {
        StubProtocol.trickleChunks = 400 // 20 s at 50 ms; each byte resets URLSession's idle timer
        let t0 = Date()
        let r = await LogoSanitizer.fetchAndSanitize(URL(string: "https://example.org/a.png")!, session: session, timeout: 0.6)
        let elapsed = Date().timeIntervalSince(t0)
        if case .failure(.timedOut) = r {} else { XCTFail("expected timedOut, got \(r)") }
        XCTAssertLessThan(elapsed, 3, "deadline must fire while awaiting the next byte")
        let stopped = await waitUntil { StubProtocol.stopLoadingCalls > 0 }
        XCTAssertTrue(stopped, "timeout must cancel the download")
    }

    // (4) one in-flight fetch per URI
    func testConcurrentResolvesShareOneDownload() async {
        StubProtocol.body = okImage
        StubProtocol.delay = 0.4
        let cache = LogoCache(session: session)
        let uri = "https://example.org/shared.png"
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
        StubProtocol.body = okImage
        StubProtocol.delay = 0.5
        let cache = LogoCache(session: session)
        let uri = "https://example.org/shared.png"
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
        StubProtocol.body = okImage
        StubProtocol.delay = 3 // far longer than the test: a normal finish cannot masquerade as a cancel
        let cache = LogoCache(session: session)
        let uri = "https://example.org/slow.png"
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
