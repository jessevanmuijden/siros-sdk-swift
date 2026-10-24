// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(ImageIO)
import ImageIO
import CoreGraphics
#endif

/// A logo that is safe to render: either clean re-encoded image bytes, or an
/// `https` URL for the host's own image loader to fetch.
public enum DisplayLogo: Sendable, Equatable {
    /// PNG bytes produced by this SDK from decoded pixels. Nothing from the
    /// issuer's original bytes (metadata chunks, ICC/EXIF/XMP, trailing data,
    /// embedded payloads) survives.
    case image(Data)
    /// An `https` URL (no credentials in the authority). Fetching and
    /// decoding it is the host's job; hosts that want the same guarantees
    /// should pass the fetched bytes through `LogoSanitizer.sanitize(imageData:)`.
    case remote(URL)
}

/// Why a logo URI was refused. Every refusal is final: the caller shows the
/// issuer-initial fallback.
public enum LogoRejection: Error, Sendable, Equatable {
    case empty
    /// Not `https:` and not `data:` (`http:`, `file:`, `javascript:`, ...).
    case unsupportedScheme
    /// `https:` URL with no host, or with embedded credentials.
    case invalidRemoteUrl
    /// `data:` URI that is not `data:<type>;base64,<payload>`.
    case malformedDataUri
    /// Media type outside `LogoSanitizer.allowedMediaTypes`.
    case unsupportedMediaType
    /// SVG containing script, foreignObject, <use>/<image>/animation, event
    /// handlers, external references, DOCTYPE/entities or similar.
    case activeContent
    /// SVG that is not well-formed, not an `<svg>` document, or that the
    /// renderer refused.
    case invalidSvg
    case invalidBase64
    case tooLarge
    /// The bytes do not decode as the declared image type (including
    /// truncated images, and content whose real type differs from the label).
    case undecodable
    case dimensionsTooLarge
    /// A remote logo fetch did not finish within `fetchTimeout`.
    case timedOut
    /// `fetchAndSanitize` was given a timeout that is not finite or not positive.
    case invalidTimeout
    /// No ImageIO on this platform (Linux): data: logos fail closed.
    case platformUnsupported
}

/// Turns an issuer/credential display logo URI into something safe to draw.
///
/// Policy (kept identical to siros-sdk-kotlin's logo sanitizer):
/// - `https:` URLs pass through as `.remote`; `http:` and everything else is
///   refused.
/// - `data:` URIs must be `data:<media type>;base64,<payload>` (RFC 2397)
///   with media type one of `image/png`, `image/jpeg`, `image/webp`,
///   `image/gif`. The decoded payload is capped at `maxDecodedBytes`
///   (256 KiB) and the image at `maxDimension` (2048) pixels per side.
/// - The bytes are decoded with ImageIO, checked to really be the declared
///   type, and **re-encoded as a fresh PNG** from the decoded pixels, so
///   metadata and trailing/polyglot payloads are dropped. Animated GIFs
///   keep their first frame.
/// - **SVG** (`image/svg+xml`, base64 like the rest; percent-encoded SVG is
///   refused, as in Kotlin) is never passed on as XML. An XMLParser-based
///   guard first refuses (never repairs) script, foreignObject, use, a,
///   image, animation, iframe/object/embed, `on*` attributes, non-fragment
///   href/src, external `url()` / `@import`, DOCTYPE and entities, and
///   anything not well-formed. What remains is rasterized by SwiftDraw (no
///   script engine, no network or file access) to at most `svgRenderEdge`
///   pixels and then re-encoded like any raster. Without ImageIO (Linux)
///   SVG is refused as `platformUnsupported`.
/// - Fail closed: any doubt is a `LogoRejection`.
public enum LogoSanitizer {
    public static let allowedMediaTypes: Set<String> = ["image/png", "image/jpeg", "image/webp", "image/gif", "image/svg+xml"]
    /// Cap on the decoded (not base64) payload.
    public static let maxDecodedBytes = 256 * 1024
    /// Cap on width and on height, in pixels.
    public static let maxDimension = 2048
    /// Longest edge an SVG is rasterized to, in pixels (same as Kotlin).
    public static let svgRenderEdge = 512

    public static func sanitize(_ uri: String) -> Result<DisplayLogo, LogoRejection> {
        let trimmed = uri.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .failure(.empty) }
        let lower = trimmed.lowercased()
        if lower.hasPrefix("https:") { return sanitizeRemote(trimmed) }
        if lower.hasPrefix("data:") { return sanitizeDataUri(trimmed) }
        return .failure(.unsupportedScheme)
    }

    /// Sanitizes already-fetched image bytes (e.g. a remote logo the host
    /// downloaded) with the same decode/re-encode and caps as a data: logo.
    /// `declaredMediaType` is optional; when given it must be allowlisted and
    /// match the sniffed type.
    public static func sanitize(imageData: Data, declaredMediaType: String? = nil) -> Result<DisplayLogo, LogoRejection> {
        var declared: String?
        if let declaredMediaType {
            let t = declaredMediaType.lowercased()
            guard allowedMediaTypes.contains(t) else { return .failure(.unsupportedMediaType) }
            declared = t
        }
        guard imageData.count <= maxDecodedBytes else { return .failure(.tooLarge) }
        if declared == "image/svg+xml" { return sanitizeSvg(imageData) }
        return reencode(imageData, declaredMediaType: declared)
    }

    /// Downloads an `https` logo and sanitizes the bytes (SVG and raster alike)
    /// with the same guard, render and caps as a `data:` logo. Fails closed: the
    /// URL gets the same authority validation as `sanitize(_:)` (https, host,
    /// no userinfo) before any request; every redirect target is validated
    /// the same way; a non-2xx answer, wrong content type, or more than
    /// `maxDecodedBytes` (checked on Content-Length and while streaming, so
    /// the body is never buffered past the cap) is a rejection.
    public static func fetchAndSanitize(_ url: URL, session: URLSession = .shared,
                                         timeout: TimeInterval = fetchTimeout) async -> Result<DisplayLogo, LogoRejection> {
        guard let url = validatedRemoteUrl(url.absoluteString) else { return .failure(.invalidRemoteUrl) }
        guard let timeout = effectiveTimeout(timeout) else { return .failure(.invalidTimeout) }
        #if canImport(ImageIO)
        // One wall-clock budget for request AND body: a trickle that keeps
        // URLSession's inactivity timer alive still loses the race.
        return await withTaskGroup(of: Result<DisplayLogo, LogoRejection>.self) { group in
            let policy = RedirectPolicy()
            group.addTask { await fetchBody(url, session: session, policy: policy, timeout: timeout) }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                policy.cancel() // stop the download itself, not just our wait
                return .failure(Task.isCancelled ? .undecodable : .timedOut)
            }
            let first = await group.next() ?? .failure(.undecodable)
            group.cancelAll()
            policy.cancel()
            return first
        }
        #else
        return .failure(.platformUnsupported)
        #endif
    }

    #if canImport(ImageIO)
    private static func fetchBody(_ url: URL, session: URLSession, policy: RedirectPolicy,
                                  timeout: TimeInterval) async -> Result<DisplayLogo, LogoRejection> {
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        request.setValue("image/svg+xml,image/png,image/jpeg,image/webp,image/gif", forHTTPHeaderField: "Accept")
        // Every early return below leaves the download running unless the
        // URLSessionTask is cancelled explicitly (dropping the byte stream
        // does not do it).
        defer { policy.cancel() }
        do {
            let (stream, response) = try await session.bytes(for: request, delegate: policy)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return .failure(.undecodable)
            }
            if http.expectedContentLength > Int64(maxDecodedBytes) { return .failure(.tooLarge) }
            guard let data = try await collect(stream, limit: maxDecodedBytes) else { return .failure(.tooLarge) }
            let type = (http.value(forHTTPHeaderField: "Content-Type") ?? "")
                .split(separator: ";").first.map { $0.trimmingCharacters(in: .whitespaces).lowercased() } ?? ""
            return sanitize(imageData: data, declaredMediaType: type.isEmpty ? nil : type)
        } catch {
            return .failure(.undecodable)
        }
    }
    #endif

    /// Longest budget `fetchAndSanitize` will honour; larger values are clamped to it.
    public static let maxFetchTimeout: TimeInterval = 120

    /// The budget to use, or nil when it is unusable (NaN, infinite, zero or
    /// negative). Anything above `maxFetchTimeout` is clamped, so the
    /// nanosecond conversion can never overflow.
    static func effectiveTimeout(_ t: TimeInterval) -> TimeInterval? {
        guard t.isFinite, t > 0 else { return nil }
        return min(t, maxFetchTimeout)
    }

    /// Wall-clock budget for one remote logo fetch (request and body).
    public static let fetchTimeout: TimeInterval = 15

    /// Reads at most `limit` bytes; nil as soon as one more would arrive (the
    /// rest of the body is not read).
    static func collect<S: AsyncSequence>(_ bytes: S, limit: Int) async throws -> Data?
    where S.Element == UInt8 {
        var out = Data()
        for try await b in bytes {
            if out.count >= limit { return nil }
            out.append(b)
        }
        return out
    }

    /// Redirects are followed only to URLs that pass the same policy as the original.
    final class RedirectPolicy: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
        private let lock = NSLock()
        private var task: URLSessionTask?
        private var cancelled = false

        func urlSession(_ session: URLSession, didCreateTask task: URLSessionTask) {
            lock.lock(); defer { lock.unlock() }
            self.task = task
            if cancelled { task.cancel() }
        }

        /// Cancels the underlying download (now, or as soon as it exists).
        func cancel() {
            lock.lock(); defer { lock.unlock() }
            cancelled = true
            task?.cancel()
        }

        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            completionHandler(request.url.flatMap { LogoSanitizer.validatedRemoteUrl($0.absoluteString) } == nil ? nil : request)
        }
    }

    /// https, a host, no userinfo; nil otherwise.
    static func validatedRemoteUrl(_ s: String) -> URL? {
        guard let comps = URLComponents(string: s),
              comps.scheme?.lowercased() == "https",
              let host = comps.host, !host.isEmpty,
              comps.user == nil, comps.password == nil
        else { return nil }
        return comps.url
    }

    private static func sanitizeRemote(_ s: String) -> Result<DisplayLogo, LogoRejection> {
        guard let url = validatedRemoteUrl(s) else { return .failure(.invalidRemoteUrl) }
        return .success(.remote(url))
    }

    private static func sanitizeDataUri(_ s: String) -> Result<DisplayLogo, LogoRejection> {
        // RFC 2397: "data:" [ mediatype ] [ ";base64" ] "," data
        let afterScheme = s.dropFirst("data:".count)
        guard let comma = afterScheme.firstIndex(of: ",") else { return .failure(.malformedDataUri) }
        let header = afterScheme[afterScheme.startIndex..<comma].lowercased()
        let payload = afterScheme[afterScheme.index(after: comma)...]

        // Only "<type>[;charset=utf-8|us-ascii];base64" is accepted: no other
        // parameters, no percent-encoded (non-base64) form.
        var parts = header.split(separator: ";", omittingEmptySubsequences: false).map(String.init)
        if parts.count == 3, ["charset=utf-8", "charset=us-ascii"].contains(parts[1]) { parts.remove(at: 1) }
        guard parts.count == 2, parts[1] == "base64" else {
            return .failure(.malformedDataUri)
        }
        let mediaType = parts[0]
        guard allowedMediaTypes.contains(mediaType) else { return .failure(.unsupportedMediaType) }

        // Bound the work before decoding: base64 is 4 chars per 3 bytes.
        guard payload.utf8.count <= (maxDecodedBytes / 3 + 1) * 4 else { return .failure(.tooLarge) }
        // Foundation's strict decoder (no .ignoreUnknownCharacters) rejects
        // whitespace and anything outside the base64 alphabet.
        guard let bytes = Data(base64Encoded: String(payload)), !bytes.isEmpty else {
            return .failure(.invalidBase64)
        }
        guard bytes.count <= maxDecodedBytes else { return .failure(.tooLarge) }
        if mediaType == "image/svg+xml" { return sanitizeSvg(bytes) }
        return reencode(bytes, declaredMediaType: mediaType)
    }

    /// SVG: refusal guard first, then rasterize, then the PNG goes through the
    /// same decode/cap/re-encode path as any raster logo.
    private static func sanitizeSvg(_ bytes: Data) -> Result<DisplayLogo, LogoRejection> {
        #if canImport(ImageIO)
        if let refusal = SvgActiveContentGuard.check(bytes) { return .failure(refusal) }
        guard let png = SvgLogoRasterizer.rasterize(bytes) else { return .failure(.invalidSvg) }
        return reencode(png, declaredMediaType: "image/png")
        #else
        return .failure(.platformUnsupported)
        #endif
    }

    private static func reencode(_ bytes: Data, declaredMediaType: String?) -> Result<DisplayLogo, LogoRejection> {
        #if canImport(ImageIO)
        let sourceOptions: CFDictionary = [kCGImageSourceShouldCache: false] as CFDictionary
        guard let source = CGImageSourceCreateWithData(bytes as CFData, sourceOptions),
              let uti = CGImageSourceGetType(source) as String?,
              let sniffed = mediaType(forUTI: uti)
        else { return .failure(.undecodable) }
        // The content must be what the URI says it is, and allowlisted.
        guard allowedMediaTypes.contains(sniffed) else { return .failure(.unsupportedMediaType) }
        if let declaredMediaType, declaredMediaType != sniffed { return .failure(.undecodable) }
        guard CGImageSourceGetCount(source) >= 1 else { return .failure(.undecodable) }
        // ImageIO happily returns a half-filled image for a truncated file
        // (its status stays "complete"), so completeness is checked here.
        guard hasEndMarker(bytes, mediaType: sniffed) else { return .failure(.undecodable) }

        // Dimensions come from the header, before any pixel buffer exists.
        guard let props = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any],
              let srcW = (props[kCGImagePropertyPixelWidth] as? NSNumber)?.intValue,
              let srcH = (props[kCGImagePropertyPixelHeight] as? NSNumber)?.intValue,
              srcW > 0, srcH > 0
        else { return .failure(.undecodable) }
        guard srcW <= maxDimension, srcH <= maxDimension else { return .failure(.dimensionsTooLarge) }

        // The thumbnail API is ImageIO's way to get pixels with the EXIF
        // orientation applied (the metadata is dropped below). The max size is
        // the cap, which the header check above already enforced.
        let thumbOptions: CFDictionary = [
            kCGImageSourceCreateThumbnailFromImageAlways: true,
            kCGImageSourceCreateThumbnailWithTransform: true,
            kCGImageSourceThumbnailMaxPixelSize: maxDimension,
            kCGImageSourceShouldCache: false,
        ] as CFDictionary
        guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, thumbOptions) else {
            return .failure(.undecodable)
        }
        let w = image.width, h = image.height
        guard w > 0, h > 0, w <= maxDimension, h <= maxDimension else { return .failure(.undecodable) }

        // Redraw into a known sRGB RGBA bitmap: only pixels cross over.
        guard let space = CGColorSpace(name: CGColorSpace.sRGB),
              let ctx = CGContext(
                  data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                  bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
              )
        else { return .failure(.undecodable) }
        ctx.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
        guard let clean = ctx.makeImage() else { return .failure(.undecodable) }

        let out = NSMutableData()
        guard let dest = CGImageDestinationCreateWithData(out, "public.png" as CFString, 1, nil) else {
            return .failure(.undecodable)
        }
        CGImageDestinationAddImage(dest, clean, nil) // nil properties: no metadata
        guard CGImageDestinationFinalize(dest) else { return .failure(.undecodable) }
        return .success(.image(out as Data))
        #else
        return .failure(.platformUnsupported)
        #endif
    }

    /// Truncation check. This is an integrity check for the user's benefit (a
    /// half-drawn logo), not a security boundary: the output is rebuilt from
    /// pixels either way. It walks the container structure (PNG chunks, JPEG
    /// segments) so a marker embedded in metadata (e.g. an EXIF thumbnail's
    /// EOI) cannot stand in for the real end. A complete image followed by
    /// trailing bytes still passes (and is then cleaned). GIF has no cheap
    /// structural end and is not checked.
    static func hasEndMarker(_ d: Data, mediaType: String) -> Bool {
        let b = [UInt8](d)
        switch mediaType {
        case "image/png": return pngHasIend(b)
        case "image/jpeg": return jpegHasEoi(b)
        case "image/webp":
            // RIFF header: bytes 4..<8 are the little-endian size of what follows.
            guard b.count >= 12 else { return false }
            let size = Int(b[4]) | Int(b[5]) << 8 | Int(b[6]) << 16 | Int(b[7]) << 24
            return size + 8 <= b.count
        default:
            return true
        }
    }

    private static func pngHasIend(_ b: [UInt8]) -> Bool {
        var i = 8 // after the signature
        while i + 12 <= b.count {
            let len = Int(b[i]) << 24 | Int(b[i + 1]) << 16 | Int(b[i + 2]) << 8 | Int(b[i + 3])
            guard len <= b.count - i - 12 else { return false } // chunk runs past the end
            if b[i + 4] == 0x49, b[i + 5] == 0x45, b[i + 6] == 0x4E, b[i + 7] == 0x44 { return len == 0 }
            i += 12 + len
        }
        return false
    }

    private static func jpegHasEoi(_ b: [UInt8]) -> Bool {
        guard b.count >= 4, b[0] == 0xFF, b[1] == 0xD8 else { return false }
        var i = 2
        while i + 1 < b.count {
            guard b[i] == 0xFF else { return false }
            let m = b[i + 1]
            if m == 0xFF { i += 1; continue } // fill byte
            if m == 0xD9 { return true }
            if m == 0x01 || (0xD0...0xD8).contains(m) { i += 2; continue } // standalone
            guard i + 3 < b.count else { return false }
            let len = Int(b[i + 2]) << 8 | Int(b[i + 3])
            guard len >= 2, i + 2 + len <= b.count else { return false } // segment runs past the end
            i += 2 + len
            if m == 0xDA { // entropy-coded data: skip to the next real marker
                while i + 1 < b.count {
                    if b[i] == 0xFF, b[i + 1] == 0xFF { i += 1; continue } // fill byte stays in the scan
                    if b[i] == 0xFF, b[i + 1] != 0x00, !(0xD0...0xD7).contains(b[i + 1]) { break }
                    i += 1
                }
            }
        }
        return false
    }

    #if canImport(ImageIO)
    private static func mediaType(forUTI uti: String) -> String? {
        switch uti {
        case "public.png": return "image/png"
        case "public.jpeg": return "image/jpeg"
        case "com.compuserve.gif": return "image/gif"
        case "org.webmproject.webp": return "image/webp"
        default: return nil
        }
    }
    #endif
}

/// Resolves logo URIs to sanitized results off the caller's thread and
/// remembers them by URI (rejections too, so a bad logo is not re-decoded on
/// every render). Bounded: when full it forgets everything and starts over.
public actor LogoCache {
    public static let shared = LogoCache()
    private var entries: [String: DisplayLogo?] = [:]
    private let capacity: Int
    /// Number of times the sanitizer actually ran (for tests).
    public private(set) var sanitizeCount = 0

    private let session: URLSession

    /// One download + rasterization per URI, shared by every concurrent caller.
    private struct Flight {
        let id: Int
        let task: Task<DisplayLogo?, Never>
        var waiters: Int
    }
    private var flights: [String: Flight] = [:]
    private var nextFlightId = 0

    public init(capacity: Int = 64, session: URLSession = .shared) {
        self.capacity = max(1, capacity)
        self.session = session
    }

    /// The sanitized logo, or nil when the URI was rejected (show the issuer initial).
    public func resolve(_ uri: String) async -> DisplayLogo? {
        if let hit = entries[uri] { return hit }
        if flights[uri] != nil { return await join(uri) }
        sanitizeCount += 1
        var result: DisplayLogo?
        if case .success(let logo) = LogoSanitizer.sanitize(uri) { result = logo }
        // https SVG cannot be drawn by AsyncImage: fetch it and run the same
        // guard + rasterize path as a data: SVG, once, however many callers ask.
        if case .remote(let url)? = result, url.path.lowercased().hasSuffix(".svg") {
            nextFlightId += 1
            let id = nextFlightId
            let session = self.session
            let task = Task { () -> DisplayLogo? in
                let fetched = await LogoSanitizer.fetchAndSanitize(url, session: session)
                if Task.isCancelled { await self.finish(uri, id: id, result: nil, cache: false); return nil }
                var logo: DisplayLogo?
                if case .success(let l) = fetched { logo = l }
                await self.finish(uri, id: id, result: logo, cache: true)
                return logo
            }
            flights[uri] = Flight(id: id, task: task, waiters: 0)
            return await join(uri)
        }
        store(uri, result)
        return result
    }

    /// Waits for the shared flight. A cancelled waiter leaves; when the last
    /// one leaves the download is cancelled and nothing is cached.
    private func join(_ uri: String) async -> DisplayLogo? {
        guard var flight = flights[uri] else { return entries[uri] ?? nil }
        flight.waiters += 1
        flights[uri] = flight
        let id = flight.id
        let value = await withTaskCancellationHandler {
            await flight.task.value
        } onCancel: {
            Task { await self.leave(uri, id: id) }
        }
        return Task.isCancelled ? nil : value
    }

    private func leave(_ uri: String, id: Int) {
        guard var flight = flights[uri], flight.id == id else { return }
        flight.waiters -= 1
        if flight.waiters <= 0 {
            flight.task.cancel()
            flights[uri] = nil
        } else {
            flights[uri] = flight
        }
    }

    private func finish(_ uri: String, id: Int, result: DisplayLogo?, cache: Bool) {
        guard flights[uri]?.id == id else { return } // everyone left already
        flights[uri] = nil
        if cache { store(uri, result) }
    }

    private func store(_ uri: String, _ result: DisplayLogo?) {
        if entries.count >= capacity { entries.removeAll() }
        entries[uri] = .some(result)
    }
}
