// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import SwiftUI
import SirosCredentials
import SVGView

/// Whether every instance in a batch has already been used in a
/// presentation (`sigCount > 0`) - the single canonical definition of
/// "exhausted" so callers that resolve a tap without going through
/// `CredentialCardView.onClick` (`CredentialStack`, which reads every touch
/// through its own single gesture recognizer instead - see that file's doc
/// comment) can apply the identical rule before opening detail, rather than
/// re-deriving a copy that could silently drift from this one. Nil (no
/// batch/usage data on hand) is never treated as exhausted.
func credentialBatchExhausted(_ instances: [CredentialInstance]?) -> Bool {
    guard let instances else { return false }
    return !instances.contains { $0.sigCount == 0 }
}

/// Credit-card style credential display.
///
/// Uses background_color/text_color from credential metadata when available,
/// otherwise falls back to system colors.
/// Aspect ratio 1.6:1 matches the web frontend's card proportions.
///
/// If the issuer's VCTM published `rendering.svg_templates`, this renders the
/// real branded SVG (claims substituted into its `{{svg_id}}` placeholders)
/// instead of the flat color+logo layout - shows a spinner while fetching
/// rather than flashing the flat layout first, and falls back to it if the
/// fetch/substitution fails for any reason.
struct CredentialCardView: View {
    let credential: StoredCredential
    /// Every copy in this credential's batch (see `StoredCredential.batchId`),
    /// including itself - mirrors wallet-frontend's `vcEntity.instances`: the
    /// ribbon shows how many copies haven't been used in a presentation yet.
    /// Nil (the default) hides the ribbon entirely and never treats the card
    /// as exhausted - for callers, like the detail screen's compact header,
    /// that don't have batch/usage data on hand rather than showing a
    /// misleading "0".
    var instances: [CredentialInstance]? = nil
    /// Called when the card is tapped, UNLESS it's exhausted (every batch
    /// instance already used - see `instances`) - mirrors the Kotlin sample
    /// app's `CredentialCard` owning its own click-vs-exhausted gating
    /// internally rather than leaving it to the caller.
    ///
    /// Nil (the default) attaches NO tap gesture at all, rather than one
    /// whose action is merely a no-op - `CredentialStack` relies on this:
    /// it reads every touch on a stacked card through its own single
    /// gesture recognizer (see `CredentialStack.swift`'s doc comment), and
    /// an inert-but-still-present `.onTapGesture` here would be exactly the
    /// two-independent-recognizers setup that silently ate every tap the
    /// first time this was tried (confirmed live in the simulator, not from
    /// reading the code) - a no-op *action* wasn't enough to prevent that;
    /// the modifier itself has to be absent.
    var onClick: (() -> Void)? = nil
    /// Called when the user taps "Renew" on a fully-exhausted credential.
    /// Only ever shown/invoked when `instances` is non-nil and every
    /// instance's `sigCount > 0`; ignored (no button rendered) if nil.
    var onRenewClick: (() -> Void)? = nil
    /// Why this credential cannot currently be used, from the SDK's run of
    /// DIIP's Validity and Revocation Algorithm (see
    /// `SirosWallet.refreshCredentialStatuses`). Nil - the default - means it
    /// can be used, or that no evaluation has run yet.
    ///
    /// The card renders it and computes none of it: establishing revocation
    /// means fetching the issuer's Token Status List, which belongs in the
    /// SDK, not in a SwiftUI body.
    var credentialStatus: CredentialStatus? = nil

    @Environment(\.colorScheme) private var colorScheme
    @State private var svgState: SvgLoadState = .notApplicable

    /// Nil when the caller doesn't have batch/usage data on hand (see
    /// `instances`'s doc comment) - only gates the greyed-out/Renew state
    /// when we actually know the count, never on the strength of an absence.
    private var unusedCount: Int? { instances?.filter { $0.sigCount == 0 }.count }
    private var isExhausted: Bool { credentialBatchExhausted(instances) }

    var body: some View {
        // A credential whose metadata has not been built yet is still a
        // credential, and it already carries what a card needs: its
        // configuration id, its issuer and its own type. Reading that directly
        // means the card does not depend on whether anything has populated
        // `metadata`.
        let meta = credential.metadata ?? CredentialUtils.buildFallbackMetadata(credential)
        // A type that declares no colour gets a tint derived from its type
        // identifier: stable across devices and launches, different between
        // types (it used to be one accent colour for all of them).
        let bgRGB = meta.backgroundColor.flatMap { CardRGB(hex: $0) }
            ?? typeTintColor(typeId: cardTypeId(metadata: meta, credential: credential), dark: colorScheme == .dark)
        let bgColor = bgRGB.map { Color(red: $0.red, green: $0.green, blue: $0.blue) } ?? .accentColor
        // Text colour: the issuer's if declared AND readable on the resolved
        // background (a declared white on a generated light tint is 1.66:1),
        // else whichever of black and white reads better.
        let fgRGB = resolvedCardTextColor(declared: meta.textColor.flatMap { CardRGB(hex: $0) }, on: bgRGB)
        let fgColor = fgRGB.map { Color(red: $0.red, green: $0.green, blue: $0.blue) } ?? .white

        let card = Group {
            switch svgState {
            case .loaded(let svgText):
                SVGView(string: svgText)
                    .aspectRatio(1.6, contentMode: .fit)
                    .frame(maxWidth: .infinity)
                    .clipShape(RoundedRectangle(cornerRadius: 16))
            case .loading:
                RoundedRectangle(cornerRadius: 16)
                    .fill(bgColor)
                    .aspectRatio(1.6, contentMode: .fit)
                    .frame(maxWidth: .infinity)
                    .overlay { ProgressView().tint(fgColor) }
            case .notApplicable, .failed:
                flatCard(meta: meta, bgColor: bgColor, fgColor: fgColor)
            }
        }
        .overlay(alignment: .topTrailing) {
            if let status = unusableStatus {
                Text(status.ribbonLabel.uppercased())
                    .font(.caption2.bold())
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(
                        RoundedRectangle(cornerRadius: 4)
                            .fill(status.ribbonColor)
                    )
                    .padding(8)
            } else if let unusedCount {
                // Remaining-copies ribbon - mirrors wallet-frontend's
                // UsagesRibbon: count of batch copies not yet used in a
                // presentation (sigCount == 0), so it counts down as copies
                // get consumed rather than showing the fixed batch size.
                // Only shown when EXPIRED isn't (they'd otherwise collide in
                // the same corner) - matches this card's single top-trailing
                // badge slot.
                Text("\(unusedCount)")
                    .font(.caption2.bold())
                    .foregroundColor(unusedCount > 0 ? SirosTheme.onSurfaceVariant : .white)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(
                        Capsule()
                            .fill(unusedCount > 0 ? SirosTheme.surfaceVariant : SirosTheme.error)
                    )
                    .padding(8)
            }
        }
        .overlay {
            // Every batch instance already used - grey the whole card out
            // (it can no longer be presented, see
            // CredentialUtils.eligibleInstances) and offer Renew instead of
            // leaving it looking like a normal, selectable credential.
            if isExhausted {
                ZStack {
                    Color.black.opacity(0.55)
                    if let onRenewClick {
                        Button(action: onRenewClick) {
                            Text(L10n.string("credentials.renew"))
                                .font(.body.bold())
                                .foregroundColor(.white)
                        }
                    }
                }
                .clipShape(RoundedRectangle(cornerRadius: 16))
            }
        }
        .task(id: SvgLoadKey(credentialId: credential.id, isDark: colorScheme == .dark)) {
            await loadSvg(preferDark: colorScheme == .dark)
        }

        if let onClick {
            card
                .contentShape(Rectangle())
                .onTapGesture {
                    guard !isExhausted else { return }
                    onClick()
                }
        } else {
            card
        }
    }

    @ViewBuilder
    private func flatCard(meta: CredentialMetadata?, bgColor: Color, fgColor: Color) -> some View {
        let issuerName = issuerLabel(name: meta?.issuer?.name, url: meta?.issuer?.url)
        let labels = cardLabels(name: meta?.name, format: credential.format, typeId: cardTypeId(metadata: meta, credential: credential))
        VStack(alignment: .leading, spacing: 0) {
            // Top: issuer badge (logo or initial), when the credential says who
            // issued it. When it does not, the row is left out rather than
            // filled in: a circle holding "?" beside the words "Unknown
            // Issuer" tells the holder nothing twice, an empty corner once.
            if issuerName != nil || meta?.logo?.uri != nil {
                HStack(spacing: 8) {
                    issuerBadge(meta: meta, issuerName: issuerName, fgColor: fgColor)
                    if let issuerName {
                        Text(issuerName)
                            .font(.caption)
                            .foregroundStyle(fgColor.opacity(0.8))
                            .lineLimit(1)
                    }
                    Spacer()
                }
            }

            Spacer()

            // Bottom: credential name, then the type beneath it. The wire
            // format is not shown as a slot of its own: it is what a credential
            // is encoded as, not what it is.
            Text(labels.title)
                .font(.title3.bold())
                .foregroundStyle(fgColor)
                .lineLimit(2)

            if let typeBadge = labels.typeBadge {
                Text(typeBadge)
                    .font(.caption2)
                    .foregroundStyle(fgColor.opacity(cardBadgeOpacity))
                    .lineLimit(1)
            }

            if let description = meta?.description {
                Text(description)
                    .font(.caption)
                    .foregroundStyle(fgColor.opacity(0.7))
                    .lineLimit(1)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity)
        .aspectRatio(1.6, contentMode: .fit)
        .background(
            RoundedRectangle(cornerRadius: 16)
                .fill(bgColor)
        )
        .shadow(color: bgColor.opacity(0.3), radius: 8, y: 4)
    }

    /// The status to show, or nil when the credential is usable.
    ///
    /// Falls back to the credential's own `exp` when the SDK has not evaluated
    /// this credential yet, so a card rendered before the first refresh still
    /// says "expired" rather than nothing.
    private var unusableStatus: CredentialStatus? {
        if let credentialStatus {
            return credentialStatus.isUsable ? nil : credentialStatus
        }
        // expiresAt is a JWT `exp` claim - always epoch seconds, not millis.
        guard let expiresAt = credential.expiresAt, expiresAt > 0,
              Date(timeIntervalSince1970: Double(expiresAt)) < Date()
        else { return nil }
        return .expired
    }

    private func issuerBadge(meta: CredentialMetadata?, issuerName: String?, fgColor: Color) -> some View {
        IssuerLogoBadge(logoUri: meta?.logo?.uri, issuerName: issuerName, fgColor: fgColor)
    }

    private func loadSvg(preferDark: Bool) async {
        guard let templates = credential.metadata?.svgTemplates, !templates.isEmpty else {
            svgState = .notApplicable
            return
        }
        let preferredScheme = preferDark ? "dark" : "light"
        let template = templates.first(where: { $0.colorScheme == preferredScheme }) ?? templates[0]

        // Key on the CHOSEN template's own colorScheme, not preferredScheme -
        // when no template matches the preferred scheme and this falls back
        // to templates[0], preferredScheme wouldn't reflect what was
        // actually resolved/rendered, splitting what should be one cache
        // entry across two different keys.
        let cacheKey = svgRenderCacheKey(credentialId: credential.id, templateUri: template.uri, colorScheme: template.colorScheme ?? "default")
        if let cached = svgRenderCache.object(forKey: cacheKey) {
            svgState = .loaded(cached as String)
            return
        }

        // Only transition to .loading once a cache miss confirms real
        // network work is actually needed - setting it unconditionally
        // above caused an unnecessary state flicker on cache hits.
        svgState = .loading

        guard let url = URL(string: template.uri) else {
            svgState = .failed
            return
        }
        do {
            let (data, response) = try await URLSession.shared.data(from: url)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                  let svgText = String(data: data, encoding: .utf8) else {
                svgState = .failed
                return
            }
            let claims = CredentialUtils.extractClaims(credential)
            let substituted = SvgTemplateRenderer.substitute(svgText, claims: claims)
            let rendered = ensureSvgImageHeight(ensureSvgViewBox(substituted))
            svgRenderCache.setObject(rendered as NSString, forKey: cacheKey)
            svgState = .loaded(rendered)
        } catch {
            svgState = .failed
        }
    }
}

/// Process-lifetime (not disk-persisted) cache of substituted SVG template
/// text, keyed by everything that affects the rendered output - avoids
/// re-fetching and re-substituting a card's template SVG every time its
/// `.task(id:)` re-fires (e.g. scrolling it off/on screen recreates the
/// view). `NSCache` is not a strict LRU (`countLimit` is a best-effort
/// cap, and eviction order isn't guaranteed), but like Android's
/// `LruCache` it's bounded and additionally evicted under memory
/// pressure, so a leaked entry can't accumulate unboundedly - matches the
/// Kotlin sample app's similarly-bounded (64-entry `LruCache`)
/// `svgRenderCache` in `CredentialCard.kt`.
private let svgRenderCache: NSCache<NSString, NSString> = {
    let cache = NSCache<NSString, NSString>()
    cache.countLimit = 64
    return cache
}()

private func svgRenderCacheKey(credentialId: Int64, templateUri: String, colorScheme: String) -> NSString {
    "\(credentialId)|\(templateUri)|\(colorScheme)" as NSString
}

/// Loading state for a credential card's VCTM SVG template rendering.
private enum SvgLoadState: Equatable {
    /// This credential's metadata has no svg_templates - render the flat card immediately.
    case notApplicable
    /// Fetch/substitution in progress - show a spinner, not the flat card.
    case loading
    case loaded(String)
    /// Fetch or render failed - fall back to the flat card.
    case failed
}

private struct SvgLoadKey: Equatable {
    let credentialId: Int64
    let isDark: Bool
}

// MARK: - Defensive SVG normalization

/// Matches an opening `<svg ...` tag, deliberately stopping short of its
/// closing `>` (mirrors the Kotlin sample app's `SVG_ROOT_TAG_OPEN`) so
/// `ensureSvgViewBox` can splice new attributes in front of that `>` without
/// needing to special-case a self-closing root tag (an `<svg>` root is
/// never self-closing in practice, but this avoids the question).
private let svgRootTagOpenRegex = try! NSRegularExpression(pattern: "<svg\\b[^>]*")
private let svgHasViewBoxAttrRegex = try! NSRegularExpression(pattern: "\\bviewBox=[\"']")
private let svgHasPreserveAspectRatioAttrRegex = try! NSRegularExpression(pattern: "\\bpreserveAspectRatio=[\"']")
private let svgDimensionAttrRegex = try! NSRegularExpression(pattern: "\\b(width|height)=([\"'])(\\d+(?:\\.\\d+)?)\\2")

/// Injects a `viewBox` on the SVG root when it's missing entirely, derived
/// from the root's own plain-number `width`/`height` attributes - a no-op
/// when a `viewBox` already exists, or when `width`/`height` aren't both
/// plain numbers. Port of the Kotlin sample app's `ensureSvgViewBox`
/// (`CredentialCard.kt`) - see its doc comment for why this and
/// `ensureSvgImageHeight` are both needed: a real issuer's SVG credential
/// template (wwwallet.org's demo PID) declares numeric `width`/`height` with
/// no `viewBox`, which otherwise leaves percentage-sized children ambiguous
/// across renderers.
func ensureSvgViewBox(_ svg: String) -> String {
    let full = NSRange(svg.startIndex..., in: svg)
    guard let rootMatch = svgRootTagOpenRegex.firstMatch(in: svg, range: full),
          let rootRange = Range(rootMatch.range, in: svg) else { return svg }
    let rootTag = String(svg[rootRange])
    let rootNSRange = NSRange(rootRange, in: svg)
    if svgHasViewBoxAttrRegex.firstMatch(in: svg, range: rootNSRange) != nil { return svg }

    var dimensions: [String: String] = [:]
    for match in svgDimensionAttrRegex.matches(in: svg, range: rootNSRange) {
        guard let nameRange = Range(match.range(at: 1), in: svg),
              let valueRange = Range(match.range(at: 3), in: svg) else { continue }
        dimensions[String(svg[nameRange])] = String(svg[valueRange])
    }
    guard let width = dimensions["width"], let height = dimensions["height"] else { return svg }

    let preserveAspectRatio = svgHasPreserveAspectRatioAttrRegex.firstMatch(in: svg, range: rootNSRange) != nil
        ? "" : " preserveAspectRatio=\"none\""

    var result = svg
    result.replaceSubrange(rootRange, with: "\(rootTag) viewBox=\"0 0 \(width) \(height)\"\(preserveAspectRatio)")
    return result
}

/// Matches an `<image ...>` opening tag (self-closing or not).
private let svgImageTagRegex = try! NSRegularExpression(pattern: "<image\\b[^>]*>")
/// Matches a percentage `width="NN%"`/`width='NN%'` attribute within an already-isolated tag string.
private let svgImageWidthPercentAttrRegex = try! NSRegularExpression(pattern: "width=([\"'])(\\d+%)\\1")
/// True if the tag string already declares a `height` attribute (any value).
private let svgHasHeightAttrRegex = try! NSRegularExpression(pattern: "\\bheight=[\"']")

/// Injects a missing `height` on an `<image>` element that declares a
/// percentage `width` but no `height` at all, mirroring the exact width
/// value. Port of the Kotlin sample app's `ensureSvgImageHeight`
/// (`CredentialCard.kt`) - confirmed necessary via live testing there: a
/// real issuer's SVG credential template
/// (demo-issuer.wwwallet.org's EHIC card) has its full-bleed background
/// `<image>` declare `width="100%"` with no `height` attribute whatsoever.
/// Per SVG 1.1, an `<image>` with no height defaults to height 0 - the
/// element renders invisibly rather than erroring, so the card silently
/// shows nothing but its own flat background color. An `<image>` that
/// already declares a `height` (any value) is never touched.
func ensureSvgImageHeight(_ svg: String) -> String {
    let mutable = NSMutableString(string: svg)
    let matches = svgImageTagRegex.matches(in: svg, range: NSRange(location: 0, length: mutable.length))
    for match in matches.reversed() {
        let tag = mutable.substring(with: match.range)
        let tagRange = NSRange(location: 0, length: (tag as NSString).length)
        guard let widthMatch = svgImageWidthPercentAttrRegex.firstMatch(in: tag, range: tagRange),
              svgHasHeightAttrRegex.firstMatch(in: tag, range: tagRange) == nil else {
            continue
        }
        let percentage = (tag as NSString).substring(with: widthMatch.range(at: 2))
        let selfClosing = tag.hasSuffix("/>")
        let bodyRaw = selfClosing ? String(tag.dropLast(2)) : String(tag.dropLast(1))
        let body = bodyRaw.replacingOccurrences(of: "\\s+$", with: "", options: .regularExpression)
        let closer = selfClosing ? " />" : ">"
        mutable.replaceCharacters(in: match.range, with: "\(body) height=\"\(percentage)\"\(closer)")
    }
    return mutable as String
}

// MARK: - Color hex extension

extension Color {
    init?(hex: String) {
        var hexString = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        if hexString.hasPrefix("#") {
            hexString.removeFirst()
        }
        guard hexString.count == 6,
              let value = UInt64(hexString, radix: 16) else {
            return nil
        }
        let r = Double((value >> 16) & 0xFF) / 255.0
        let g = Double((value >> 8) & 0xFF) / 255.0
        let b = Double(value & 0xFF) / 255.0
        self.init(red: r, green: g, blue: b)
    }
}

/// Issuer badge: the sanitized logo when there is one, otherwise the issuer
/// initial. Sanitizing runs in `LogoCache` (off the main actor, cached by
/// URI), never in `body`; until it finishes, and whenever the logo is
/// rejected or fails to load, the initial is shown.
private struct IssuerLogoBadge: View {
    let logoUri: String?
    let issuerName: String?
    let fgColor: Color
    @State private var logo: DisplayLogo?

    var body: some View {
        Group {
            switch logo {
            case .image(let data):
                if let image = Self.platformImage(from: data) {
                    image.resizable().scaledToFill()
                        .frame(width: 32, height: 32)
                        .clipShape(Circle())
                } else {
                    initialBadge
                }
            case .remote(let url):
                AsyncImage(url: url) { phase in
                    switch phase {
                    case .success(let image):
                        image.resizable().scaledToFill()
                    case .empty, .failure:
                        initialBadge
                    @unknown default:
                        initialBadge
                    }
                }
                .frame(width: 32, height: 32)
                .clipShape(Circle())
            case nil:
                initialBadge
            }
        }
        .task(id: logoUri) {
            guard let logoUri else { logo = nil; return }
            logo = nil
            let resolved = await LogoCache.shared.resolve(logoUri)
            // Actor calls do not abort on cancellation: a superseded task
            // must not overwrite what the newer one set.
            guard !Task.isCancelled else { return }
            logo = resolved
        }
    }

    @ViewBuilder
    private var initialBadge: some View {
        if let initial = issuerName?.prefix(1).uppercased() {
            Circle()
                .fill(fgColor.opacity(0.15))
                .frame(width: 32, height: 32)
                .overlay(
                    Text(initial)
                        .font(.caption.bold())
                        .foregroundStyle(fgColor)
                )
        }
    }

    private static func platformImage(from data: Data) -> Image? {
        #if canImport(UIKit)
        return UIImage(data: data).map { Image(uiImage: $0) }
        #elseif canImport(AppKit)
        return NSImage(data: data).map { Image(nsImage: $0) }
        #else
        return nil
        #endif
    }
}
