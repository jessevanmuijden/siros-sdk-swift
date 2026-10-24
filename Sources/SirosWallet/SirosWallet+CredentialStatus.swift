// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import SirosCredentials

/// DIIP's Validity and Revocation Algorithm, run over the credentials this
/// wallet holds: the `validFrom` / `validUntil` window, then the issuer's
/// Token Status List.
///
/// A host app renders the outcome and computes none of it - establishing
/// revocation means fetching and verifying a Status List Token, which is not
/// something a UI layer should be doing.
extension SirosWallet {

    /// The DIIP release this wallet follows when it speaks
    /// ``InteropProfile/diip`` - see ``DiipProfile``.
    public var diipProfile: DiipProfile { config.diipProfile }

    /// The interoperability profile this wallet speaks with `issuer` when
    /// nothing else decides - see ``InteropProfile``.
    ///
    /// A per-Issuer override wins over the wallet-wide default. The match is
    /// by prefix so that a `credential_issuer` with a path under a configured
    /// base counts, and the longest configured prefix wins so a specific entry
    /// is not shadowed by a broader one. This is an escape hatch for an Issuer
    /// whose metadata is wrong, not the normal path: see
    /// ``holderBinding(for:)``.
    public func interopProfile(for issuer: String?) -> InteropProfile {
        issuerOverride(for: issuer) ?? config.interopProfile
    }

    /// The configured override for `issuer`, if a specific one was set.
    ///
    /// Compared as URLs, not as strings. A string prefix test matches
    /// `https://issuer.example.evil` against an override for
    /// `https://issuer.example` - a different domain handed another issuer's
    /// configuration - and `https://issuer.example@evil.com/x` too, where the
    /// part that looks like the configured issuer is only userinfo and the
    /// real host is someone else's. Both are the same bug wearing different
    /// clothes: whoever controls the matched string controls which profile is
    /// used.
    ///
    /// So: scheme, host and port must be equal, the path must be the
    /// configured one or a segment under it, and a URL carrying userinfo never
    /// matches - a legitimate `credential_issuer` has none, and accepting one
    /// only reopens the trick above.
    func issuerOverride(for issuer: String?) -> InteropProfile? {
        guard let issuer, let candidate = URL(string: issuer) else { return nil }
        return config.issuerInteropProfiles
            .filter { entry in Self.sameIssuer(candidate, entry.key) }
            .max { $0.key.count < $1.key.count }?
            .value
    }

    /// The port a URL actually addresses: the explicit one, else the
    /// scheme's default.
    static func effectivePort(of url: URL) -> Int? {
        if let port = url.port { return port }
        switch url.scheme?.lowercased() {
        case "https": return 443
        case "http": return 80
        default: return nil
        }
    }

    static func sameIssuer(_ candidate: URL, _ configured: String) -> Bool {
        guard let base = URL(string: configured),
              candidate.user == nil, candidate.password == nil,
              base.user == nil, base.password == nil,
              candidate.scheme?.lowercased() == base.scheme?.lowercased(),
              candidate.host?.lowercased() == base.host?.lowercased(),
              // Effective ports, not the literal ones: `URL.port` is nil when
              // the port is implicit, so comparing directly makes
              // `https://issuer.example` and `https://issuer.example:443`
              // look like different issuers and silently drops the override.
              Self.effectivePort(of: candidate) == Self.effectivePort(of: base)
        else { return false }

        func trimmed(_ path: String) -> String {
            path.hasSuffix("/") ? String(path.dropLast()) : path
        }
        let basePath = trimmed(base.path)
        let candidatePath = trimmed(candidate.path)
        if basePath.isEmpty { return true }
        return candidatePath == basePath || candidatePath.hasPrefix(basePath + "/")
    }

    /// How the Holder's key should be named in an OID4VCI proof to `issuer` -
    /// the one thing HAIP and DIIP genuinely disagree about, and something
    /// OID4VCI makes a per-issuance choice.
    ///
    /// **Negotiated, not configured.** The Issuer's own
    /// `cryptographic_binding_methods_supported` for the configuration being
    /// issued says which identifier it can verify, so a wallet holding
    /// credentials from a HAIP ecosystem and a DIIP ecosystem shapes each
    /// proof to its Issuer without anyone choosing a profile. A user cannot
    /// reasonably be asked which of two interoperability profiles an issuer
    /// they just scanned belongs to, and does not have to be.
    ///
    /// The configured profile is only the fallback, for an Issuer that
    /// advertises nothing usable - and the per-Issuer override the escape
    /// hatch above that, for one that advertises the wrong thing.
    ///
    /// Handed to `KeystoreManager.generateProof` so the keystore never has to
    /// know about issuers.
    public func holderBinding(for issuer: String?) -> HolderBinding {
        // An explicit per-Issuer override comes first. It exists precisely for
        // an Issuer whose metadata advertises the wrong thing, so letting the
        // metadata win would leave it with nothing to override.
        if let override = issuerOverride(for: issuer) {
            return override.holderBinding
        }

        // The offer's identifier and the one the proof is being signed for are
        // compared the way an override is, not as raw strings: the same issuer
        // routinely writes itself with and without a trailing slash, or with
        // an explicit :443. Treating those as different issuers would discard
        // what the Issuer advertised and fall back to the configured profile -
        // silently sending a DIIP-only Issuer the HAIP proof shape.
        //
        // Snapshotted under `lock` (review finding): `activeOffer` is mutated
        // under `lock` elsewhere (`startIssuance`'s "another issuance already
        // in progress" guard, a renewal, a reset) and a concurrent one of
        // those could otherwise race this read with a torn or stale value.
        lock.lock(); let snapshotOffer = activeOffer; lock.unlock()
        let advertised = snapshotOffer
            .flatMap { offer -> [String]? in
                guard Self.sameAdvertisedIssuer(offer.credentialIssuerIdentifier, issuer) else { return nil }
                return offer.cryptographicBindingMethodsSupported
            }
        if let negotiated = HolderBinding.negotiate(advertised) {
            return negotiated
        }
        return config.interopProfile.holderBinding
    }

    /// Whether the active offer's issuer is the one a proof is being signed
    /// for. A nil `issuer` means the caller did not say, in which case the
    /// active offer is the only issuance in flight and does apply.
    static func sameAdvertisedIssuer(_ offerIssuer: String?, _ issuer: String?) -> Bool {
        guard let issuer else { return true }
        guard let offerIssuer else { return false }
        // No raw-string equality shortcut (review finding): two copies of the
        // SAME confusing string (e.g. a URL carrying userinfo, or something
        // that is not a URL at all) would match each other here while
        // `sameIssuer` below - the policy this function exists to apply
        // consistently - rejects exactly that shape. Always go through it.
        guard let url = URL(string: issuer) else { return false }
        return sameIssuer(url, offerIssuer)
    }

    /// Evaluate one credential's status.
    ///
    /// The result is cached; ``refreshCredentialStatuses()`` re-runs it. A
    /// status list that cannot be reached leaves the credential
    /// ``CredentialStatus/valid`` rather than hiding it, which is what keeps
    /// the wallet usable offline.
    public func credentialStatus(of credential: StoredCredential) async -> CredentialStatus {
        // Captured BEFORE anything below that can suspend, including the
        // parse step's own error path (review finding: that path used to
        // write to the cache unconditionally, guarded by none of this) - a
        // logout/new-login or this credential's own deletion can complete
        // WHILE either path is still running, and the generation checks
        // `set` itself performs, atomically, under its own lock (see
        // `CredentialStatusCache.set`'s doc comment) is what keeps a write
        // below from landing after `endSessionLocally()`'s
        // credentialStatusCache.clear() or deleteCredential(_:)'s
        // .remove(_:) already ran - silently resurrecting a previous
        // account's (or a deleted credential's) status for whichever
        // account/credential next reuses the id.
        //
        // Both captured, not just the session generation (review finding,
        // sharper than the one this guard already closed): id reuse can
        // happen WITHOUT any session boundary at all - credential A is
        // deleted and its id immediately reused by credential B, both within
        // the SAME session - and a stale write for A must be refused even
        // though the session generation never changed. `idGeneration` is
        // what tells A's write apart from B's for the exact same id; see
        // `CredentialStatusCache.idGenerations`'s doc comment.
        // Captured together, under one lock acquisition, not as two
        // separate calls (review finding): see
        // `CredentialStatusCache.currentGenerations(for:)`'s doc comment for
        // why two separate reads - even back to back - are not atomic with
        // each other.
        let (cacheGeneration, idGeneration) = credentialStatusCache.currentGenerations(for: credential.id)

        // Shared by every return path below, so the parse-failure case is
        // guarded exactly the same way as the normal evaluation (review
        // finding) rather than by a separate, easy-to-miss copy of the check.
        //
        // The existence check and the generation checks are COMPLEMENTARY,
        // not redundant with each other (review finding, self-caught - an
        // earlier round dropped this check, reasoning the generation check
        // alone made it redundant; it does not): `idGeneration` alone cannot
        // tell "this credential was deleted and never reused" apart from "a
        // normal evaluation that started before any delete at all" - both
        // read as a generation match at write time, since nothing changed
        // the id's generation AFTER capture if it was ALREADY gone before
        // capture even happened. A fresh existence check closes exactly that
        // gap; `idGeneration` closes the gap a bare existence check cannot
        // (id reused by someone else - existence alone would see the NEW
        // occupant and wrongly accept the OLD one's stale write). Together
        // they are stronger than either alone; the sliver of a window
        // between this check returning and `set` running is the same
        // residual every other race in this file discloses rather than
        // claims to fully close.
        func cacheIfStillCurrent(_ status: CredentialStatus) async {
            guard await credentialStore.getById(credential.id) != nil else { return }
            credentialStatusCache.set(credential.id, status, generation: cacheGeneration, idGeneration: idGeneration)
        }

        // A credential whose validity data will not parse is not a valid one.
        // Collapsing the parse failure into "no claims" and then into `.valid`
        // let malformed - or deliberately malformed - MSO content skip both
        // the validity window and the revocation check entirely.
        let parsed: [String: Any]?
        do {
            parsed = try CredentialUtils.parseValidityClaims(credential)
        } catch {
            await cacheIfStillCurrent(.unknown)
            return .unknown
        }
        // Cached too (review finding), not merely returned: without this, a
        // STALE cache entry from whatever credential previously held this
        // id (an id SQLite reuses - see the tombstone mechanism above) would
        // survive indefinitely, since nothing else ever overwrites it for an
        // id whose current credential has no validity/status claims at all -
        // retain(_:) preserves any id still currently held, stale entry
        // included. A reused id's own claim-less credential must read as
        // `.valid` from here on, not whatever its previous occupant was.
        guard let claims = parsed else {
            await cacheIfStillCurrent(.valid)
            return .valid
        }

        // An mdoc's normalised claims carry no `iss`, so the credential's own
        // stored issuer identifier is what binds its Status List Token to an
        // issuer. Without it that check is skipped for every mdoc.
        let status = await credentialStatusEvaluator.evaluate(
            claims: claims,
            credentialIssuer: credential.credentialIssuerIdentifier
        )

        await cacheIfStillCurrent(status)
        return status
    }

    /// The last known status of a credential, without network access or
    /// re-evaluation - for synchronous call sites such as a SwiftUI body.
    /// ``CredentialStatus/valid`` until ``refreshCredentialStatuses()`` has
    /// run.
    public func cachedCredentialStatus(of credentialId: Int64) -> CredentialStatus {
        credentialStatusCache.get(credentialId)
    }

    /// Re-evaluate every held credential, and return the statuses by
    /// credential id.
    @discardableResult
    public func refreshCredentialStatuses() async -> [Int64: CredentialStatus] {
        var statuses: [Int64: CredentialStatus] = [:]
        for credential in await credentialStore.getAll() {
            statuses[credential.id] = await credentialStatus(of: credential)
        }
        // Re-fetched here, rather than reusing the loop's own now-possibly-
        // stale snapshot (review finding): `credentialStatus(of:)` always
        // returns a computed result for an id, whether or not its own
        // generation/tombstone-guarded write actually landed - so `statuses`
        // above can still carry an entry for a credential deleted WHILE this
        // loop was running. `retain(_:)` un-tombstones every id it is given;
        // handing it a deleted id would reopen that id's tombstone for
        // exactly the id a concurrent deleteCredential(_:) just closed it
        // for, letting a late write resurrect it. Re-fetching narrows the
        // race to the (much smaller) gap between this call and `retain`
        // itself, rather than spanning this whole loop's duration.
        let stillHeld = Set(await credentialStore.getAll().map { $0.id })
        credentialStatusCache.retain(stillHeld.intersection(statuses.keys))
        return statuses
    }

    /// Resolve a DID to its document, for the methods ``diipProfile``
    /// requires - an Issuer's signing key, or a Verifier's identity.
    public func resolveDid(_ did: String) async -> DidResolution {
        await didResolver.resolve(did)
    }

    /// The signing key an issuer publishes, for verifying a Status List Token
    /// it signed.
    ///
    /// Resolved through ``DidResolver``, so `did:web` and anything else that
    /// needs resolving goes to go-trust rather than being fetched here. A
    /// status list whose key cannot be resolved goes unverified, which the
    /// reader reports as an unavailable status, never as a valid one.
    static func resolveIssuerSigningKey(
        issuer: String,
        kid: String?,
        resolver: DidResolver,
        profile: DiipProfile
    ) async -> [String: String]? {
        // Any syntactically valid DID goes to the resolver, which delegates
        // whatever is not did:jwk to go-trust. Testing DidMethod.of here would
        // make an issuer identified by a method this SDK does not name -
        // did:ebsi, say - fall through to the HTTPS branch, where it resolves
        // to nothing: its status list would then never verify, and revocation
        // for it would silently never apply.
        if DidMethod.methodName(of: issuer) != nil {
            return await resolver.resolve(issuer).document?
                .findPublicKey(kid: kid, relationship: .assertionMethod)
        }
        return await resolveHttpsIssuerSigningKey(issuer: issuer, kid: kid, profile: profile)
    }

    /// The signing key an HTTPS-identified Issuer publishes, from its SD-JWT
    /// VC issuer metadata (`jwks`, or `jwks_uri`).
    ///
    /// Most Issuers are identified by an HTTPS URL rather than a DID, so
    /// without this the Token Status List could never be verified for them and
    /// every revocation check would degrade to "unavailable" - which this SDK
    /// deliberately treats as usable, so revocation would silently never
    /// apply.
    ///
    /// This is not a trust decision and does not pretend to be one. The path
    /// is derived from the Issuer's own identifier, so there is no choice of
    /// authority to make - unlike DID method resolution, which is go-trust's
    /// (see ``DidResolver``). Whether this Issuer is trusted at all is
    /// answered by the issuer trust list, the same as for the credential
    /// itself; all this does is obtain the key that Issuer publishes under its
    /// own name.
    ///
    /// The well-known suffix moves with the profile: SD-JWT VC renamed it
    /// between drafts, so it comes from
    /// ``DiipProfile/sdJwtVcIssuerMetadataPath`` rather than being hardcoded.
    /// Both spellings are tried, since an issuer pinned to the other draft is
    /// common.
    static func resolveHttpsIssuerSigningKey(
        issuer: String,
        kid: String?,
        profile: DiipProfile
    ) async -> [String: String]? {
        // Case-insensitively: URI schemes are case-insensitive, so rejecting
        // `HTTPS://issuer.example` here would leave that issuer's status list
        // unverifiable and its revocation silently never applied.
        guard issuer.lowercased().hasPrefix("https://") else { return nil }
        // Trim every trailing slash, not just one: the well-known path
        // carries its own leading slash.
        var base = issuer
        while base.hasSuffix("/") { base.removeLast() }

        var paths = [profile.sdJwtVcIssuerMetadataPath]
        for fallback in ["/.well-known/jwt-vc-issuer", "/.well-known/vc-issuer"]
        where !paths.contains(fallback) {
            paths.append(fallback)
        }

        for path in paths {
            guard case .success(let body) = await fetchPublicUrl(base + path, headers: [:]),
                  let keys = await issuerJwks(metadata: body)
            else { continue }
            if let key = selectIssuerKey(keys, kid: kid) { return key }
        }
        return nil
    }

    /// The JWK set an SD-JWT VC issuer metadata document points at, inline or
    /// by reference.
    static func issuerJwks(metadata body: Data) async -> [[String: Any]]? {
        guard let metadata = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else {
            return nil
        }
        if let jwks = metadata["jwks"] as? [String: Any], let keys = jwks["keys"] as? [[String: Any]] {
            return keys
        }
        guard let uri = metadata["jwks_uri"] as? String,
              case .success(let referenced) = await fetchPublicUrl(uri, headers: [:]),
              let jwks = try? JSONSerialization.jsonObject(with: referenced) as? [String: Any],
              let keys = jwks["keys"] as? [[String: Any]]
        else { return nil }
        return keys
    }

    /// Pick the key a Status List Token's `kid` names, or the only usable one
    /// when it named none. A set with several keys and no `kid` is ambiguous,
    /// and guessing there would mean accepting a signature from whichever key
    /// happened to be first.
    static func selectIssuerKey(_ keys: [[String: Any]], kid: String?) -> [String: String]? {
        // A key carrying private material is not something an issuer publishes
        // for verification; refusing it keeps a misconfigured JWKS from being
        // treated as a verification key.
        let usable = keys.filter { $0["d"] == nil && $0["k"] == nil }
        let match: [String: Any]?
        if let kid {
            // Two keys sharing one `kid` is exactly as ambiguous as several
            // keys with none (review finding): which one a verifier means is
            // then whichever the server's array happened to list first, not
            // something this wallet decided.
            let matches = usable.filter { ($0["kid"] as? String) == kid }
            match = matches.count == 1 ? matches[0] : nil
        } else {
            match = usable.count == 1 ? usable[0] : nil
        }
        return match?.compactMapValues { $0 as? String }
    }

    /// Fetch a URL that belongs to a third party - an issuer's Status List
    /// Token, named by a URI inside the credential itself.
    ///
    /// Only documents whose location the credential already states, never DID
    /// resolution: which document is authoritative for an identifier is
    /// go-trust's decision (see ``DidResolver``). The Status List Token's own
    /// signing key is still resolved through that path, so fetching the list
    /// is not a trust decision.
    ///
    /// These carry NO wallet credentials: attaching this wallet's bearer token
    /// or tenant id to a request at an arbitrary domain would leak them.
    ///
    /// Reports which of ``TokenStatusList/FetchOutcome`` resulted, not a
    /// plain `Data?` (review finding): a request this wallet's OWN policy
    /// refused to even attempt, and one that reached the server and got back
    /// a non-2xx response, both used to collapse into the same `nil` a
    /// genuinely unreachable endpoint produces - which
    /// `TokenStatusListClient.resolve` then treated as offline-friendly and
    /// reported `.valid`, turning a blocked or failing status URI into a
    /// silent pass rather than an unknown.
    static func fetchPublicUrl(_ urlString: String, headers: [String: String]) async -> TokenStatusList.FetchOutcome {
        guard let url = URL(string: urlString), isPublicFetchAllowed(url), let host = url.host,
              await hostResolvesToOnlyPublicAddresses(host)
        else {
            // Never attempted at all - this wallet's own policy refused the
            // URL. Not the same as the endpoint being unreachable.
            return .rejected
        }
        var request = URLRequest(url: url)
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        // A fresh delegate instance per call (review finding), passed to
        // this one request rather than relying on the session's own default
        // delegate: `data(for:request:delegate:)` routes THIS task's
        // callbacks to it instead, so it needs no `ObjectIdentifier`-keyed
        // bookkeeping to stay correct under concurrent calls - there is only
        // ever one task per instance - and, the actual point of this
        // change, `fetchPublicUrl` can ask THIS SPECIFIC instance whether
        // IT cancelled the request after the fact.
        let delegate = HttpsOnlyRedirectDelegate()
        do {
            let (data, response) = try await thirdPartySession.data(for: request, delegate: delegate)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                // The server WAS reached; it just didn't answer with success.
                return .rejected
            }
            return .success(data)
        } catch {
            // A cap-triggered cancellation reached the server and received
            // (too much) data - not "could not reach it at all" (review
            // finding): the evaluator treats ONLY a genuine transport
            // failure as offline-friendly, so without this distinction an
            // oversized or hostile response could force a credential to
            // read as `.valid` instead of `.unknown`.
            return delegate.didExceedResponseCap ? .rejected : .unreachable
        }
    }
}

/// The session third-party fetches go out on.
///
/// Not attaching an `Authorization` header is not enough on its own to say a
/// request carries no wallet credentials: `URLSession.shared` keeps a shared
/// cookie store and credential cache, so a cookie set by one of this wallet's
/// own hosts would ride along to a third-party domain that happens to match -
/// a leak no call site can see, because nothing at the call site mentions
/// cookies. An ephemeral configuration with the cookie and credential storage
/// removed is what makes the guarantee in `fetchPublicUrl` true rather than
/// merely intended.
///
/// The delegate refuses a redirect to anything but HTTPS for the same reason.
/// `fetchPublicUrl` checks the URL this wallet asks for, but URLSession follows
/// redirects on its own, so without this a status-list or metadata URL could
/// answer with a 302 to `http://` and serve the JWKS or the status token in the
/// clear - the downgrade the HTTPS-only rule exists to prevent, arranged by
/// whoever controls the URL.
private let thirdPartySession: URLSession = {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.httpCookieStorage = nil
    configuration.httpCookieAcceptPolicy = .never
    configuration.httpShouldSetCookies = false
    configuration.urlCredentialStorage = nil
    configuration.urlCache = nil
    configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
    // No session-level delegate: `fetchPublicUrl` passes a fresh
    // `HttpsOnlyRedirectDelegate` to every call instead (see its doc
    // comment), which `data(for:request:delegate:)` uses in place of
    // whatever the session itself declares.
    return URLSession(configuration: configuration)
}()

/// Whether a third-party URL may be fetched at all.
///
/// Everything reached this way - a Status List Token, an issuer's metadata,
/// the `jwks_uri` it points at - is used to decide whether a credential is
/// still valid and which key says so. Over plaintext, anyone on the path can
/// answer those questions instead of the issuer: serve a status list that says
/// "valid", or a JWKS holding their own key. An issuer identifier is an HTTPS
/// URL to begin with, so this rejects nothing a well-formed deployment does.
///
/// Userinfo means nothing for an issuer's metadata or status list, and a URL
/// carrying it is the classic way to make a host look like one it is not
/// (`https://issuer.example@evil.example/`).
///
/// One predicate, applied to the URL this wallet asks for *and* to every
/// redirect it is offered: a rule enforced on the first request and not on the
/// hop after it is not a rule.
///
/// Also rejects an IP-literal host in a reserved/private/loopback/link-local
/// range (review finding): without this, a credential-controlled status URI
/// or issuer `jwks_uri` naming `https://127.0.0.1/...` or a private-network
/// address passed every other check here and was fetched, turning status
/// evaluation into an SSRF/local-network probing primitive. A literal
/// `localhost` is rejected the same way, since it resolves to loopback by
/// convention everywhere. A real HOSTNAME is not resolved here to check
/// where it points - this is a pre-connect, static check against the URL
/// text only, not a DNS-rebinding defense (the OS resolver settles that at
/// connect time, after this check has already passed); closing that fully
/// would need a custom resolver pinning the address actually connected to,
/// which is a larger change than this fail-closed literal-IP check.
func isPublicFetchAllowed(_ url: URL) -> Bool {
    guard url.scheme?.lowercased() == "https",
          url.user == nil, url.password == nil,
          let host = url.host, !host.isEmpty
    else { return false }
    return !isReservedOrLoopbackHost(host)
}

/// Whether every address `host` resolves to is public - the hostname half
/// of blocking SSRF/local-network probing through a credential-controlled
/// URL (review finding): `isPublicFetchAllowed` alone only rejects IP
/// *literals* in the URL text, so an ordinary DNS name a credential/issuer
/// points at a private address sailed through every check there untouched
/// and was fetched.
///
/// Deliberately NOT folded into `isPublicFetchAllowed` itself (unlike that
/// function, this performs real DNS I/O): dozens of existing tests call
/// `isPublicFetchAllowed` directly against placeholder hostnames (RFC
/// 2606's `issuer.example`) expecting a pure, instant, offline predicate -
/// folding a real lookup in here would make the whole test suite network-
/// dependent. This is called only from the real fetch path below and from
/// the redirect delegate, where a DNS round trip is already about to
/// happen regardless.
///
/// Bounded by `hostResolutionTimeout` (review finding, found empirically -
/// not merely theorized - while writing this fix's own tests): `getaddrinfo`
/// has no timeout parameter of its own, and a name that will not resolve at
/// all can make it block for a LONG time (tens of seconds, observed) in an
/// environment with no path to a DNS server, which would otherwise turn
/// every status/JWKS check against such a host into a multi-second-or-worse
/// stall - worse than simply being offline, which this whole mechanism
/// exists to tolerate gracefully. A lookup that does not finish in time is
/// treated the same as one that fails outright: not a policy decision this
/// function is positioned to make either way.
///
/// Not airtight against DNS rebinding: the address actually dialed is
/// still resolved a second time, by URLSession's own resolver, after this
/// check passes - closing that fully needs a custom resolver that pins the
/// exact address connected to, a larger change than this PR takes on (see
/// `isPublicFetchAllowed`'s own doc comment for the same caveat on the
/// literal-IP check). This closes the practical case the finding
/// describes: an ordinary, slowly-changing DNS record pointed at a private
/// address.
func hostResolvesToOnlyPublicAddresses(_ host: String) async -> Bool {
    // Deliberately NOT `withTaskGroup` running `resolveHostBlocking`
    // directly in a child task (tried first, and measured, not merely
    // suspected, to fail): that puts a genuinely BLOCKING call on Swift
    // concurrency's own cooperative thread pool, which has as few threads
    // as this process has cores - a slow `getaddrinfo` there can occupy the
    // only thread able to run the timeout task's own continuation too,
    // starving the race itself and making the "bounded" timeout wait out
    // the full unbounded lookup anyway. Two plain GCD background blocks,
    // outside that pool entirely, race properly.
    let timeout = hostResolutionTimeout
    return await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
        let gate = ResumeGate()
        DispatchQueue.global(qos: .utility).async {
            gate.resume(with: resolveHostBlocking(host), continuation)
        }
        // On its OWN queue: the lookups above block global-queue threads for as long as `getaddrinfo` takes (tens of
        // seconds on a slow resolver, measured on a CI iOS simulator: 13 s against a 0.2 s bound), and a timer that has to
        // wait for one of those threads is not a bound at all.
        hostResolutionTimeoutQueue.asyncAfter(deadline: .now() + timeout) {
            // Treated as BLOCKED, not allowed (review finding - this is
            // deliberately NOT the same answer a clean, fast resolution
            // failure gets): a lookup that is merely slow might still
            // resolve to anything by the time `URLSession` resolves it
            // again at actual connect time, private address included - a
            // hostname an attacker deliberately makes slow to resolve is
            // exactly how a timeout, specifically, could otherwise bypass
            // this check. A genuinely non-existent name fails FAST on a
            // working resolver (confirmed - RFC 2606's reserved
            // `.invalid`), so this path is for "unknown", not "ordinarily
            // absent", and fail-closed is the only defensible default for
            // "unknown" here, same as everywhere else in this evaluator.
            gate.resume(with: false, continuation)
        }
    }
}

/// Ensures a `CheckedContinuation` is resumed exactly once, whichever of
/// ``hostResolvesToOnlyPublicAddresses(_:)``'s two racing background blocks
/// - the real lookup, or the timeout - gets there first. Resuming a
/// `CheckedContinuation` twice is a programmer error `Continuation`
/// terminates the process over, so the second racer losing silently (not
/// resuming at all) is required, not merely tidy.
private final class ResumeGate: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false

    func resume(with value: Bool, _ continuation: CheckedContinuation<Bool, Never>) {
        lock.lock()
        let shouldResume = !resumed
        resumed = true
        lock.unlock()
        if shouldResume { continuation.resume(returning: value) }
    }
}

/// The same check, for the one call site that cannot `await` it - the
/// redirect delegate's callback, a plain synchronous closure `URLSession`
/// invokes directly. Bounded the same way, via a semaphore rather than
/// Swift concurrency's own timeout machinery, since this runs on whatever
/// thread `URLSession` calls the delegate back on, not inside a `Task`.
func hostResolvesToOnlyPublicAddressesBlocking(_ host: String) -> Bool {
    let semaphore = DispatchSemaphore(value: 0)
    let box = ResultBox(false)
    DispatchQueue.global(qos: .utility).async {
        box.value = resolveHostBlocking(host)
        semaphore.signal()
    }
    // Blocked on timeout (review finding, sharper than a mere policy call -
    // this was also an actual data race): on `.timedOut`, the background
    // lookup can still be RUNNING and can still write to `box.value` after
    // this point - reading it unsynchronized with that write, as the
    // previous version did regardless of the wait outcome, is a genuine
    // race on top of being the wrong policy anyway. Returning here, without
    // touching `box` at all, avoids both: `box.value` is read ONLY after a
    // `.success` wait, where `signal()` (called right after the write, in
    // program order, on the lookup's own thread) establishes the
    // happens-before edge that makes the read safe.
    guard semaphore.wait(timeout: .now() + hostResolutionTimeout) == .success else { return false }
    return box.value
}

/// Fires the resolution timeouts; nothing else runs on it, so a pile of blocked lookups cannot delay a timeout.
private let hostResolutionTimeoutQueue = DispatchQueue(label: "org.siros.host-resolution-timeout", qos: .userInitiated)

/// How long ``hostResolvesToOnlyPublicAddresses(_:)`` and its blocking
/// sibling wait for a DNS answer before giving up - see their shared doc
/// comment for why this exists at all. A `var`, not a `let`, purely so
/// tests can shorten it rather than wait out the real value.
var hostResolutionTimeout: TimeInterval = 5

/// A plain mutable box, `@unchecked Sendable` because access to it is
/// already serialized by the semaphore in
/// ``hostResolvesToOnlyPublicAddressesBlocking(_:)`` - the writer signals
/// the semaphore after its one write, and the reader only reads after
/// `wait` returns, so the two sides never touch `value` at the same time.
private final class ResultBox: @unchecked Sendable {
    var value: Bool
    init(_ value: Bool) { self.value = value }
}

/// The actual (unbounded) `getaddrinfo` lookup - never called directly;
/// both wrappers above bound it with a timeout first.
private func resolveHostBlocking(_ host: String) -> Bool {
    var hints = addrinfo()
    // `SOCK_STREAM` is already `Int32` on Darwin but Glibc's own
    // `__socket_type` enum on Linux, which `addrinfo.ai_socktype` (`Int32`
    // on both) does not accept directly there.
    #if canImport(Darwin)
    hints.ai_socktype = SOCK_STREAM
    #else
    hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
    #endif
    var result: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else {
        // Could not resolve at all - not a policy decision to make here:
        // the connect attempt fails on its own and reads as `.unreachable`,
        // the same as any other transport failure, not as "blocked".
        return true
    }
    defer { freeaddrinfo(first) }

    var node: UnsafeMutablePointer<addrinfo>? = first
    while let current = node {
        switch current.pointee.ai_family {
        case AF_INET:
            let sin = current.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            if isReservedIPv4(sin.sin_addr.s_addr.bigEndian) { return false }
        case AF_INET6:
            let sin6 = current.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
            if isReservedIPv6(sin6.sin6_addr) { return false }
        default:
            break
        }
        node = current.pointee.ai_next
    }
    return true
}

/// Whether `host` (a URL's `.host`, so an IPv6 literal arrives WITHOUT its
/// `[...]` brackets) is a loopback, private-network, link-local, or other
/// IANA-reserved address - or the conventional `localhost` name - rather
/// than a real, routable public hostname/address.
private func isReservedOrLoopbackHost(_ host: String) -> Bool {
    let lowered = host.lowercased()
    if lowered == "localhost" || lowered.hasSuffix(".localhost") { return true }

    var ipv4 = in_addr()
    if host.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
        return isReservedIPv4(ipv4.s_addr.bigEndian)
    }
    var ipv6 = in6_addr()
    if host.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
        return isReservedIPv6(ipv6)
    }
    // Not an IP literal at all - a real hostname, which this check does not
    // resolve (see the doc comment above).
    return false
}

/// IANA-reserved/special-use IPv4 ranges (RFC 5735/6890 and successors) that
/// are never a legitimate public issuer: loopback (127/8), "this network"
/// (0/8), link-local (169.254/16), the three private ranges (10/8,
/// 172.16/12, 192.168/16), carrier-grade NAT (100.64/10), the documentation
/// ranges, and multicast/reserved (224/4 and above, which also covers the
/// all-ones broadcast address).
private func isReservedIPv4(_ addressBigEndian: UInt32) -> Bool {
    /// A CIDR range, as the combined base address (not 4 separate octets -
    /// SwiftLint's `large_tuple` rule caps tuples at 2 members, so this is a
    /// struct instead) and prefix length.
    struct Range {
        let base: UInt32
        let prefixBits: Int
        init(_ o1: UInt8, _ o2: UInt8, _ o3: UInt8, _ o4: UInt8, prefixBits: Int) {
            base = (UInt32(o1) << 24) | (UInt32(o2) << 16) | (UInt32(o3) << 8) | UInt32(o4)
            self.prefixBits = prefixBits
        }
        func contains(_ address: UInt32) -> Bool {
            let mask: UInt32 = prefixBits == 0 ? 0 : (~UInt32(0)) << (32 - prefixBits)
            return (address & mask) == (base & mask)
        }
    }
    let ranges: [Range] = [
        Range(0, 0, 0, 0, prefixBits: 8), Range(10, 0, 0, 0, prefixBits: 8),
        Range(100, 64, 0, 0, prefixBits: 10), Range(127, 0, 0, 0, prefixBits: 8),
        Range(169, 254, 0, 0, prefixBits: 16), Range(172, 16, 0, 0, prefixBits: 12),
        Range(192, 0, 0, 0, prefixBits: 24), Range(192, 0, 2, 0, prefixBits: 24),
        Range(192, 88, 99, 0, prefixBits: 24), Range(192, 168, 0, 0, prefixBits: 16),
        Range(198, 18, 0, 0, prefixBits: 15), Range(198, 51, 100, 0, prefixBits: 24),
        Range(203, 0, 113, 0, prefixBits: 24), Range(224, 0, 0, 0, prefixBits: 4),
    ]
    return ranges.contains { $0.contains(addressBigEndian) }
}

/// IANA-reserved IPv6 ranges: loopback (::1), unique-local (fc00::/7,
/// RFC 4193's private-network analogue), link-local (fe80::/10), and an
/// embedded IPv4-mapped address (`::ffff:a.b.c.d`) checked against the SAME
/// IPv4 ranges above - an IPv6 stack is not a separate network, and skipping
/// this would let the IPv4 checks be bypassed by spelling the same address
/// as a v6 literal.
private func isReservedIPv6(_ address: in6_addr) -> Bool {
    let bytes = withUnsafeBytes(of: address) { Array($0) }
    if bytes == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] { return true } // ::1
    if (bytes[0] & 0xFE) == 0xFC { return true } // fc00::/7
    if bytes[0] == 0xFE, (bytes[1] & 0xC0) == 0x80 { return true } // fe80::/10
    if bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
        let embeddedIPv4 = (UInt32(bytes[12]) << 24) | (UInt32(bytes[13]) << 16)
            | (UInt32(bytes[14]) << 8) | UInt32(bytes[15])
        return isReservedIPv4(embeddedIPv4)
    }
    return false
}

/// The most a third-party response's COMPRESSED body may be, enforced while
/// it is still arriving (review finding), not only on `Inflate`'s own output
/// afterward: `URLSession`'s plain `data(for:)` buffers an entire response
/// before returning it, with no size limit of its own, so a credential-
/// controlled status-list URI (or a chunked/streamed response at one) could
/// otherwise make evaluating a single stored credential consume unbounded
/// memory. Far above anything a real Status List Token needs (a few
/// kilobytes, per the draft) but well short of a denial-of-service payload.
let maxPublicFetchResponseBytes = 10 * 1024 * 1024

/// Refuses any redirect that ``isPublicFetchAllowed(_:)`` would not have
/// allowed as a first request, AND enforces
/// ``maxPublicFetchResponseBytes`` while a response body is still arriving.
///
/// One instance backs exactly one request: `fetchPublicUrl` constructs a
/// fresh one per call and passes it to `data(for:request:delegate:)`, which
/// is why this needs no per-task (`ObjectIdentifier`-keyed) bookkeeping -
/// there is only ever one task to track, and, the actual reason for this
/// shape (review finding), `fetchPublicUrl` can ask THIS instance
/// afterward whether IT cancelled its own request, which a shared,
/// session-wide delegate instance juggling many concurrent tasks could not
/// answer for any one of them without a lot more bookkeeping.
///
/// Passing nil to the redirect completion handler stops the redirect and
/// returns the 3xx response itself, which `fetchPublicUrl` then rejects as
/// not a 2xx. `URLSession`'s async `data(for:)` still routes through a
/// `URLSessionDataDelegate`'s `didReceive data:` as chunks arrive even though
/// its own return value is the fully-buffered `Data` - cancelling the task
/// here, the moment the running total exceeds the cap, is what keeps
/// `data(for:)` from ever finishing that buffer for an oversized response;
/// the cancellation surfaces to `fetchPublicUrl` as a thrown error - which
/// `didExceedResponseCap` lets it tell apart from a genuine transport
/// failure (review finding: collapsing the two together let an oversized or
/// hostile response read as merely "unreachable", which is offline-friendly,
/// instead of the "server answered, but something is wrong" this actually
/// is).
final class HttpsOnlyRedirectDelegate: NSObject, URLSessionTaskDelegate, URLSessionDataDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var bytesReceived = 0
    private var exceededCap = false

    /// Whether THIS delegate's one task was cancelled for exceeding
    /// ``maxPublicFetchResponseBytes`` - read by `fetchPublicUrl` after
    /// `data(for:request:delegate:)` throws, to tell that apart from any
    /// other transport failure.
    var didExceedResponseCap: Bool {
        lock.lock()
        defer { lock.unlock() }
        return exceededCap
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard let url = request.url, isPublicFetchAllowed(url), let host = url.host,
              hostResolvesToOnlyPublicAddressesBlocking(host)
        else {
            completionHandler(nil)
            return
        }
        completionHandler(request)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock()
        bytesReceived += data.count
        let exceeded = bytesReceived > maxPublicFetchResponseBytes
        if exceeded { exceededCap = true }
        lock.unlock()
        if exceeded {
            dataTask.cancel()
        }
    }
}

/// A small mutable cache of evaluated statuses.
///
/// `SirosWallet` is a `final class`, not an actor, so this holds its own lock
/// rather than relying on the wallet's isolation.
final class CredentialStatusCache: @unchecked Sendable {
    private let lock = NSLock()
    private var statuses: [Int64: CredentialStatus] = [:]
    /// A per-id occupancy generation, bumped by `remove(_:)` - replaces a
    /// plain tombstone set (review finding, sharper than the one
    /// `tombstoned` itself closed): a bare "has this id been deleted"
    /// boolean cannot tell a STALE write for the id's PREVIOUS occupant
    /// apart from a fresh write for its NEW one once `retain(_:)` has seen
    /// the id come back - both would see "not tombstoned" and succeed,
    /// letting credential A's write land for credential B's id after B has
    /// legitimately taken it over. A per-id counter that keeps incrementing
    /// (never reset by `retain(_:)`) closes it: `set(_:_:generation:idGeneration:)`
    /// only accepts a write whose captured `idGeneration` still matches THIS
    /// id's CURRENT one, which changes every time the id's occupant does -
    /// A's write, captured under the OLD value, is refused even though B's
    /// own fresh write (captured under the new one) succeeds for the exact
    /// same id.
    private var idGenerations: [Int64: Int] = [:]
    /// Bumped by `clear()` (a session boundary - logout, account switch).
    /// `set(_:_:generation:idGeneration:)` refuses to write a result
    /// computed under an older generation than this one (review finding): a
    /// caller capturing "is this still the same session" via a SEPARATE
    /// flag/lock before `clear()` runs cannot be atomic with this write
    /// either, for the exact same reason `idGenerations` cannot be checked
    /// separately from `set` itself - a concurrent `clear()` can land in the
    /// gap between that check and this call just as a concurrent
    /// `remove(_:)` can. Folding the generation check into `set` itself,
    /// alongside the per-id one, closes both races with one mechanism
    /// instead of two.
    private var generation = 0

    func get(_ id: Int64) -> CredentialStatus {
        lock.lock()
        defer { lock.unlock() }
        return statuses[id] ?? .valid
    }

    /// The cache's current generation alone - only for a caller (`clear()`'s
    /// own tests) that is not about to evaluate a specific credential and so
    /// has no id to pair it with. A real evaluation must use
    /// ``currentGenerations(for:)`` instead - see its own doc comment for
    /// why two separate calls, even back to back, are not equivalent.
    func currentGeneration() -> Int {
        lock.lock()
        defer { lock.unlock() }
        return generation
    }

    /// `id`'s current occupancy generation - direct access for callers (this
    /// file's own non-vacuousness checks) that need to inspect it without
    /// going through a full evaluation. Prefer ``currentGenerations(for:)``
    /// when capturing a value to pass into `set` later. Defaults to 0 for an
    /// id `remove(_:)` has never been called for.
    func currentIdGeneration(_ id: Int64) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return idGenerations[id] ?? 0
    }

    /// Both the cache's overall generation AND `id`'s own occupancy
    /// generation, captured together under ONE lock acquisition (review
    /// finding): `currentGeneration()` and `currentIdGeneration(_:)` called
    /// SEPARATELY - even back to back, with no other work between them -
    /// are not atomic WITH each other. A `remove(id)` (deleting credential A)
    /// followed by the id being reused (credential B) landing in the gap
    /// between those two separate calls would hand credential A's
    /// evaluation B's NEW `idGeneration` paired with whichever overall
    /// `generation` happened to be read - A's eventual write would then
    /// match at write time (nothing changed since THIS capture) and
    /// overwrite B's cache entry with A's stale result. One lock acquisition
    /// for both reads closes that gap the same way folding the write's own
    /// checks into `set` itself already closed the equivalent gap there.
    func currentGenerations(for id: Int64) -> (generation: Int, idGeneration: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (generation, idGenerations[id] ?? 0)
    }

    /// Records `status` for `id`, UNLESS `generation` no longer matches (a
    /// session boundary happened) OR `idGeneration` no longer matches THIS
    /// id's current one (the id has since been deleted - and possibly
    /// reused by a different credential) - both checked, and the write
    /// applied, under this one lock, so neither a concurrent `remove(_:)`
    /// nor a concurrent `clear()` can land in between a caller's own check
    /// and this write (review finding - see `idGenerations`'s and
    /// `generation`'s doc comments).
    func set(_ id: Int64, _ status: CredentialStatus, generation callerGeneration: Int, idGeneration callerIdGeneration: Int) {
        lock.lock()
        defer { lock.unlock() }
        guard callerGeneration == generation, (idGenerations[id] ?? 0) == callerIdGeneration else { return }
        statuses[id] = status
    }

    /// Drop every status not in `ids` - a credential that has been deleted
    /// should not keep a stale status alive. Deliberately does NOT touch
    /// `idGenerations` (review finding): a reused id's new occupant is
    /// recognised by capturing a FRESH `currentIdGeneration(_:)` for its own
    /// evaluation, which already reads the post-`remove(_:)` value - nothing
    /// needs to be "forgiven" here the way un-tombstoning used to, and
    /// forgetting a removed id's generation here would let a stale write
    /// from its PREVIOUS occupant match again.
    func retain(_ ids: Set<Int64>) {
        lock.lock()
        defer { lock.unlock() }
        statuses = statuses.filter { ids.contains($0.key) }
    }

    /// Drop one id - for `deleteCredential(_:)`, so an id SQLite/the
    /// credential store later reuses for an unrelated credential (review
    /// finding: "an ID collision can expose the wrong outcome to the new
    /// account") never reads back a status that belonged to whatever used
    /// to have this id, AND so an evaluation of the just-deleted credential
    /// that is still in flight cannot resurrect one for it afterward - see
    /// `idGenerations`'s doc comment.
    func remove(_ id: Int64) {
        lock.lock()
        defer { lock.unlock() }
        statuses.removeValue(forKey: id)
        idGenerations[id, default: 0] += 1
    }

    /// All held statuses, e.g. after a logout. Clears per-id generations
    /// too: a new account's credentials can legitimately reuse any id a
    /// previous account's did, and the new account's own evaluations must
    /// not be refused by generations left over from the previous account -
    /// `generation`'s own bump below is what actually guards the session
    /// boundary; resetting `idGenerations` here is safe riding on top of it,
    /// not a substitute for it.
    func clear() {
        lock.lock()
        defer { lock.unlock() }
        generation += 1
        statuses.removeAll()
        idGenerations.removeAll()
    }
}
