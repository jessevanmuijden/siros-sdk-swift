# Issuer and credential logos

Issuer and credential display logos come from issuer-controlled metadata, so
they are untrusted input. `LogoSanitizer` (module `SirosCredentials`) turns a
logo URI into either clean PNG bytes, an `https` URL, or a typed
`LogoRejection`. It fails closed: anything not understood is refused and the
UI shows the issuer initial instead. `LogoCache` runs this off the main actor,
caches the result by URI and shares one fetch between concurrent callers.

## Accepted sources

- `https:` URLs (host required, no `user:password@`). `http:`, `file:`,
  `javascript:` and every other scheme are refused.
- `data:` URIs of the exact form `data:<type>[;charset=utf-8|us-ascii];base64,<payload>`
  with `<type>` one of `image/png`, `image/jpeg`, `image/webp`, `image/gif`.
  Percent-encoded (non-base64) data URIs are refused.
- Rasters are decoded with ImageIO, checked to be the declared type, and
  re-encoded as a fresh PNG, so metadata and trailing bytes cannot survive.
  Animated GIFs keep their first frame.
- `LogoCache` fetches every `https` logo once (`LogoSanitizer.fetchAndSanitize`)
  and sanitizes the bytes: the response `Content-Type` (`image/png`, `image/jpeg`,
  `image/webp`, `image/gif`) decides the type, not the file name; a response with
  no `Content-Type` is sniffed, and anything else is refused. The result is always
  clean PNG bytes, never a URL for an unchecked image loader.
  (`LogoSanitizer.sanitize(_:)` on its own still returns `.remote(url)` for hosts
  that do their own loading.)

## SVG is not supported

`image/svg+xml` is refused with `svgNotSupported`: as a `data:` URI (any form),
as a response with that `Content-Type`, and when untyped bytes look like an
`<svg` document. SVG is XML that can carry script, external references and
constructs that crash or hang the available renderers, and this SDK ships no
safe renderer. Support is tracked in a separate pull request (SVG issuer logos
via SwiftDraw with an allowlist guard).

## Limits

| Limit | Value |
|---|---|
| Decoded `data:` payload / fetched body | 256 KiB (checked on the encoded length and `Content-Length` before decoding, and while streaming) |
| Raster edge | 2048 px |
| Remote fetch | 15 s wall-clock for request and body by default, 120 s maximum (larger values are clamped, NaN/infinite/non-positive are refused) |
| Redirects | followed only to `https` URLs without credentials; any other target is not followed |

## Fail-closed and platform behaviour

Any parse, decode, size, timeout or validation problem is a `LogoRejection`;
nothing is passed through. Timeouts, network errors, non-2xx answers and
cancellation (`timedOut`, `networkFailure`) are transient and never cached, so the
next resolve retries; accepted logos and definitive rejections are cached. Without
ImageIO (Linux) every `data:` logo is refused with `platformUnsupported`; `https`
URLs still pass through `sanitize(_:)`.

## Guidance for issuers

- Prefer a PNG, or an `https` URL that serves the right `Content-Type`.
- Use a raster logo; SVG is refused.
- Keep the file under 256 KiB and 2048 px per side.

## Android

`siros-sdk-kotlin` applies the same media-type allowlist, size caps and PNG
re-encode, and additionally renders SVG through its own guard (as of the reviewed
branch `feat/sanitized-data-uri-logos`), so Android may show SVG logos that iOS
refuses.
