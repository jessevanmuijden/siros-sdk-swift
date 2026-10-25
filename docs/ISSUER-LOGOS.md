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
  with `<type>` one of `image/png`, `image/jpeg`, `image/webp`, `image/gif`,
  `image/svg+xml`. Percent-encoded (non-base64) data URIs are refused.
- Rasters are decoded with ImageIO, checked to be the declared type, and
  re-encoded as a fresh PNG, so metadata and trailing bytes cannot survive.
  Animated GIFs keep their first frame.
- `LogoCache` fetches every `https` logo once (`LogoSanitizer.fetchAndSanitize`)
  and sanitizes the bytes: the response `Content-Type` (`image/png`, `image/jpeg`,
  `image/webp`, `image/gif` or `image/svg+xml`) decides raster versus SVG, not the
  file name, and anything else is refused. The result is always clean PNG bytes,
  never a URL for an unchecked image loader. (`LogoSanitizer.sanitize(_:)` on its
  own still returns `.remote(url)` for hosts that do their own loading.)

## SVG: deny by default

SVG is never passed on as XML. A guard accepts a document only if every
element, attribute and value is on an allowlist, then SwiftDraw (pinned to an
exact version) rasterizes it to at most 512 px and the PNG is re-encoded like
any raster. The allowlist exists because the renderer has crashed or hung on
inputs a denylist did not anticipate (self-referencing patterns, nested `svg`,
huge sizes, `@font-face` fonts, a path with a number after `Z`), and mis-renders
alpha hex colours and plain `href`.

Accepted elements: `svg` (root only), `g`, `defs`, `title`, `desc`, `path`,
`rect`, `circle`, `ellipse`, `line`, `polyline`, `polygon`, `linearGradient`,
`radialGradient`, `stop`, `clipPath`.

Accepted attributes, each with a strict value grammar: `id`; geometry (`x`, `y`,
`width`, `height`, `cx`, `cy`, `r`, `rx`, `ry`, `x1`..`y2`, `fx`, `fy`, `fr`,
`offset`, `points`, `d`); `viewBox`, `preserveAspectRatio`; `transform` and
`gradientTransform` (a strict list of `matrix`, `translate`, `scale`, `rotate`,
`skewX`, `skewY` with the right number of arguments); path data `d` (strict SVG
syntax: valid commands with exactly the right argument counts, nothing after
`Z`/`z` except whitespace, ASCII only); `points` (an even number of coordinates); paint and stroke (`fill`, `stroke`, `stop-color`,
`stroke-width`, `stroke-linecap`, `stroke-linejoin`, `stroke-miterlimit`,
`stroke-dasharray`, `stroke-dashoffset`, `fill-rule`, `clip-rule`); opacity
attributes; `clip-path`; `display`; gradient `gradientUnits`, `spreadMethod`,
`clipPathUnits`; and `href`/`xlink:href` on gradients. The only references
accepted are same-document `url(#id)` and `#id`; gradient inheritance must be
written `xlink:href` (a plain `href` is refused); colours are `#rgb`, `#rrggbb`,
`rgb()`, `rgba()`, named colours, `none` and `currentColor` (4- and 8-digit
alpha hex such as `#ff000080` is refused, use `rgba()` or `*-opacity`): no whitespace inside `url(`,
no quotes, no comments, no `data:` or external URLs. The only `xmlns` values
accepted are the SVG and xlink namespaces on the root.

Refused, never repaired:

- `style` attributes and `<style>` elements, `class`
- text and fonts (`text`, `tspan`, `font-*`, `@font-face`)
- DOCTYPE and entity declarations
- `use`, `symbol`, `pattern`, `mask`, `filter`, `marker`, `switch`, `image`,
  `a`, `view`, animation, `script`, `foreignObject`
- editor metadata and any namespaced element or attribute (`sodipodi:*`,
  `inkscape:*`, `xml:space`, `metadata`, ...)
- 4- and 8-digit hex colours, a plain `href`, malformed path data or transforms,
  odd `points` counts
- a nested `<svg>` (only the root is allowed)
- text content anywhere except inside `title` and `desc`
- malformed XML, a root that is not `svg`, or any value outside its grammar

## Limits

| Limit | Value |
|---|---|
| Decoded `data:` payload / fetched body / SVG source | 256 KiB (checked on the encoded length and `Content-Length` before decoding, and while streaming) |
| Raster edge | 2048 px |
| SVG rendered size | at most 512 px on the longest edge; width, height, viewBox and every number at most 1,000,000 |
| SVG elements / nesting depth | 5000 / 64 |
| Remote fetch | 15 s wall-clock for request and body by default, 120 s maximum (larger values are clamped, NaN/infinite/non-positive are refused) |
| Redirects | followed only to `https` URLs without credentials; any other target is not followed |

## Fail-closed and platform behaviour

Any parse, decode, size, timeout or validation problem is a `LogoRejection`;
nothing is passed through. A cancelled fetch is not cached, so the next
resolve retries. Without ImageIO (Linux) every `data:` logo, SVG included, is
refused with `platformUnsupported`; `https` URLs still pass through.

## Guidance for issuers

- Prefer a PNG, or an `https` URL that serves the right `Content-Type`. For SVG, keep to simple shapes and
  gradients.
- Convert text to outlines; fonts are not supported.
- Use presentation attributes (`fill="#0a84ff"`) instead of `style` or CSS, `rgba()`/`fill-opacity` instead of alpha hex, and `xlink:href` for gradient inheritance.
- Strip editor metadata (Inkscape/Illustrator namespaces, DOCTYPE,
  `enable-background`, `xml:space`) and avoid `use`, filters, masks and
  patterns.
- Keep the file under 256 KiB.

## Android

`siros-sdk-kotlin` applies the same media-type allowlist, size caps and PNG
re-encode. Its SVG guard is a denylist of elements and attributes in front of
AndroidSVG rather than an allowlist (as of the reviewed branch
`feat/sanitized-data-uri-logos`), so Android may accept SVGs that iOS refuses.
