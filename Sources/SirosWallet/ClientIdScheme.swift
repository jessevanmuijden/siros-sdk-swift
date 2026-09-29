// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// Represents a parsed OID4VP client_id_scheme with its normalized identifier.
///
/// The client_id on the wire uses a prefix convention (e.g., "x509_san_dns:hostname")
/// to indicate how the verifier identifies itself. This enum provides type-safe
/// access to the parsed components.
public enum ClientIdScheme: Sendable {
    /// X.509 SAN DNS — verifier identified by hostname in certificate SAN.
    case x509SanDns(hostname: String)
    /// X.509 SAN URI — verifier identified by URI in certificate SAN.
    case x509SanUri(uri: String)
    /// DID-based — verifier identified by a Decentralized Identifier.
    case did(did: String, method: String)
    /// Verifier attestation — verifier authenticated via third-party attestation JWT.
    case verifierAttestation(subject: String)
    /// HTTPS URL — verifier identified by URL (redirect_uri scheme or unsigned).
    case https(url: String)
    /// Pre-registered or unknown scheme — catch-all.
    case preRegistered(clientId: String)

    /// The normalized identifier for this scheme.
    public var identifier: String {
        switch self {
        case .x509SanDns(let hostname): return hostname
        case .x509SanUri(let uri): return uri
        case .did(let did, _): return did
        case .verifierAttestation(let subject): return subject
        case .https(let url): return url
        case .preRegistered(let clientId): return clientId
        }
    }

    /// A user-facing identifier with the scheme prefix stripped - a raw
    /// client_id like "x509_san_dns:verifier.multipaz.org" is meaningless to
    /// a user; the hostname alone is what matters. Falls back to
    /// `identifier` when no hostname can be extracted (e.g. a non-web DID, or
    /// an x509_hash-style value that's a certificate hash, not a name).
    public var displayName: String {
        switch self {
        case .x509SanDns(let hostname):
            return hostname
        case .x509SanUri(let uri):
            return URL(string: uri)?.host ?? uri
        case .https(let url):
            return URL(string: url)?.host ?? url
        case .did(let did, let method):
            // did:web:example.com[:path...] -> example.com - path segments
            // after the host are colon-separated per the did:web spec.
            if method == "web" {
                let rest = did.dropFirst("did:web:".count)
                return String(rest.split(separator: ":").first ?? Substring(rest))
            }
            return did
        case .verifierAttestation(let subject):
            return subject
        case .preRegistered(let clientId):
            return clientId
        }
    }

    /// Parse a raw client_id string into a typed `ClientIdScheme`.
    ///
    /// Mirrors the parsing logic in wallet-frontend's `parseClientIdScheme`.
    public static func parse(_ clientId: String) -> ClientIdScheme {
        if clientId.hasPrefix("x509_san_dns:") {
            return .x509SanDns(hostname: String(clientId.dropFirst("x509_san_dns:".count)))
        }
        if clientId.hasPrefix("x509_san_uri:") {
            return .x509SanUri(uri: String(clientId.dropFirst("x509_san_uri:".count)))
        }
        if clientId.hasPrefix("did:") {
            let parts = clientId.split(separator: ":", maxSplits: 2)
            let method = parts.count > 1 ? String(parts[1]) : ""
            return .did(did: clientId, method: method)
        }
        // OpenID4VP 1.0 final spec's name for the same DID-based scheme
        // (go-wallet-backend's ClientIDSchemeDecentralizedIdentifier) -
        // the wire client_id is "decentralized_identifier:" + the bare DID
        // (e.g. "decentralized_identifier:did:web:verifier.example.com").
        // Parsed down to the SAME .did case as the bare "did:..." form
        // (recursing on the stripped remainder), not .preRegistered, so
        // .identifier/.displayName strip the wire-form wrapper down to just
        // the DID rather than displaying the "decentralized_identifier:"
        // protocol prefix verbatim (review finding).
        if clientId.hasPrefix("decentralized_identifier:did:") {
            return parse(String(clientId.dropFirst("decentralized_identifier:".count)))
        }
        if clientId.hasPrefix("verifier_attestation:") {
            return .verifierAttestation(subject: String(clientId.dropFirst("verifier_attestation:".count)))
        }
        if clientId.hasPrefix("https://") || clientId.hasPrefix("http://") {
            return .https(url: clientId)
        }
        return .preRegistered(clientId: clientId)
    }
}
