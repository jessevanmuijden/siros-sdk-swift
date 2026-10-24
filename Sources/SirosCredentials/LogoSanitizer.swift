// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
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
    /// `image/svg+xml`: refused on purpose, see `LogoSanitizer`.
    case svgNotSupported
    case invalidBase64
    case tooLarge
    /// The bytes do not decode as the declared image type (including
    /// truncated images, and content whose real type differs from the label).
    case undecodable
    case dimensionsTooLarge
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
/// - **SVG is rejected.** SVG is XML that can carry script, external
///   references and `<foreignObject>`; Apple platforms have no renderer in
///   the SDK's reach that parses it without that risk, and rendering via
///   WKWebView or hand-sanitising the XML are both out. Issuers that need a
///   vector logo should supply a raster `data:` URI or an `https:` URL.
/// - Fail closed: any doubt is a `LogoRejection`.
public enum LogoSanitizer {
    public static let allowedMediaTypes: Set<String> = ["image/png", "image/jpeg", "image/webp", "image/gif"]
    /// Cap on the decoded (not base64) payload.
    public static let maxDecodedBytes = 256 * 1024
    /// Cap on width and on height, in pixels.
    public static let maxDimension = 2048

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
            if t == "image/svg+xml" { return .failure(.svgNotSupported) }
            guard allowedMediaTypes.contains(t) else { return .failure(.unsupportedMediaType) }
            declared = t
        }
        guard imageData.count <= maxDecodedBytes else { return .failure(.tooLarge) }
        return reencode(imageData, declaredMediaType: declared)
    }

    private static func sanitizeRemote(_ s: String) -> Result<DisplayLogo, LogoRejection> {
        guard let comps = URLComponents(string: s),
              comps.scheme?.lowercased() == "https",
              let host = comps.host, !host.isEmpty,
              comps.user == nil, comps.password == nil,
              let url = comps.url
        else { return .failure(.invalidRemoteUrl) }
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
            if parts.first == "image/svg+xml" { return .failure(.svgNotSupported) }
            return .failure(.malformedDataUri)
        }
        let mediaType = parts[0]
        if mediaType == "image/svg+xml" { return .failure(.svgNotSupported) }
        guard allowedMediaTypes.contains(mediaType) else { return .failure(.unsupportedMediaType) }

        // Bound the work before decoding: base64 is 4 chars per 3 bytes.
        guard payload.utf8.count <= (maxDecodedBytes / 3 + 1) * 4 else { return .failure(.tooLarge) }
        // Foundation's strict decoder (no .ignoreUnknownCharacters) rejects
        // whitespace and anything outside the base64 alphabet.
        guard let bytes = Data(base64Encoded: String(payload)), !bytes.isEmpty else {
            return .failure(.invalidBase64)
        }
        guard bytes.count <= maxDecodedBytes else { return .failure(.tooLarge) }
        return reencode(bytes, declaredMediaType: mediaType)
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
