// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Why a presentation response could not be encrypted. Carries no token and no key material.
public enum JarmResponseError: Error, Sendable, Equatable {
    /// The verifier key is not a public P-256 EC key usable for encryption.
    case unusableKey(String)
    case unsupportedAlgorithm(String)
    case unsupportedEncryption(String)
    /// `aud` must be the validated `verified_request.client_id`; without it nothing is built.
    case missingAudience
}

/// The `vp_token` member of a presentation response.
public enum VpTokenValue: Sendable, Equatable {
    /// A single token string (a request that did not use DCQL).
    case string(String)
    /// DCQL: credential query id to the tokens presented for it, in order.
    case dcql([(queryId: String, tokens: [String])])

    public static func == (lhs: VpTokenValue, rhs: VpTokenValue) -> Bool {
        switch (lhs, rhs) {
        case (.string(let a), .string(let b)): return a == b
        case (.dcql(let a), .dcql(let b)):
            return a.count == b.count && zip(a, b).allSatisfy { $0.queryId == $1.queryId && $0.tokens == $1.tokens }
        default: return false
        }
    }

    /// DCQL when every part names its query, otherwise the parts joined with newlines (as the
    /// engine-side builder treated a non-DCQL response).
    public static func from(parts: [(queryId: String?, token: String)]) -> VpTokenValue {
        guard !parts.isEmpty, parts.allSatisfy({ !($0.queryId ?? "").isEmpty }) else {
            return .string(parts.map(\.token).joined(separator: "\n"))
        }
        var grouped: [(queryId: String, tokens: [String])] = []
        for part in parts {
            // `queryId` is non-empty for every part here.
            let id = part.queryId ?? ""
            if let index = grouped.firstIndex(where: { $0.queryId == id }) {
                grouped[index].tokens.append(part.token)
            } else {
                grouped.append((id, [part.token]))
            }
        }
        return .dcql(grouped)
    }

    var jsonObject: Any {
        switch self {
        case .string(let token): return token
        case .dcql(let entries):
            // A repeated query id (the case is public, so a caller may pass one) merges, tokens in order.
            return entries.reduce(into: [String: [String]]()) { $0[$1.queryId, default: []] += $1.tokens }
        }
    }
}

/// The response of an OpenID4VP `direct_post.jwt` presentation, built by the wallet so the engine only
/// ever relays ciphertext: a JWE (compact) to the verifier's key whose payload is the JARM claims
/// (`iss`, `aud`, `iat`, `exp`, `vp_token`, `state`).
///
/// ECDH-ES (direct key agreement, RFC 7518 4.6) to a P-256 key with A128GCM or A256GCM. The protected
/// header carries exactly the requested `alg` and `enc`, the verifier JWK's `kid` when it has one (a
/// verifier finds its ephemeral decryption key by it), and the ephemeral `epk` (no `cty`: the plaintext is a JSON claims set, which JWE does not mark). The engine
/// refuses a JWE whose header differs, so none of these is optional.
public enum JarmResponse {

    public static let issuer = "https://self-issued.me/v2"
    public static let lifetimeSeconds = 300

    public static let supportedEncs = ["A128GCM", "A256GCM"]

    /// The JARM claims as JSON.
    public static func claims(vpToken: VpTokenValue, state: String?, audience: String, issuedAt: Date) -> Data {
        let iat = Int(issuedAt.timeIntervalSince1970)
        var claims: [String: Any] = [
            "iss": issuer, "aud": audience, "iat": iat, "exp": iat + lifetimeSeconds, "vp_token": vpToken.jsonObject,
        ]
        if let state { claims["state"] = state }
        // sortedKeys and no slash escaping: the same bytes for the same input.
        return (try? JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data()
    }

    /// Build and encrypt the response.
    /// - Parameters:
    ///   - audience: the validated `verified_request.client_id`; never anything the wallet derived.
    ///   - recipientJwk: the verifier's public key as the engine resolved it.
    public static func encrypt(
        vpToken: VpTokenValue, state: String?, audience: String?, recipientJwk: [String: String],
        alg: String, enc: String, issuedAt: Date = Date()
    ) throws -> String {
        guard let audience, !audience.isEmpty else { throw JarmResponseError.missingAudience }
        guard alg == "ECDH-ES" else { throw JarmResponseError.unsupportedAlgorithm(alg) }
        guard supportedEncs.contains(enc) else { throw JarmResponseError.unsupportedEncryption(enc) }
        let recipient = try publicKey(from: recipientJwk)
        let plaintext = claims(vpToken: vpToken, state: state, audience: audience, issuedAt: issuedAt)

        let ephemeral = P256.KeyAgreement.PrivateKey()
        let point = ephemeral.publicKey.x963Representation
        var header: [String: Any] = [
            "alg": alg, "enc": enc,
            "epk": [
                "kty": "EC", "crv": "P-256",
                "x": CredentialResponseJwe.encode(point.subdata(in: 1..<33)),
                "y": CredentialResponseJwe.encode(point.subdata(in: 33..<65)),
            ],
        ]
        if let kid = recipientJwk["kid"] { header["kid"] = kid }
        let headerData = try JSONSerialization.data(withJSONObject: header, options: [.sortedKeys, .withoutEscapingSlashes])
        let protected = CredentialResponseJwe.encode(headerData)

        let z = try ephemeral.sharedSecretFromKeyAgreement(with: recipient).withUnsafeBytes { Array($0) }
        let keyBytes = enc == "A256GCM" ? 32 : 16
        let cek = CredentialResponseJwe.concatKdf(z: z, algorithmId: enc, apu: Data(), apv: Data(), keyBits: keyBytes * 8)
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: cek), nonce: AES.GCM.Nonce(), authenticating: Data(protected.utf8))
        // Direct key agreement has no encrypted key: that segment is empty.
        let jwe = [
            protected, "", CredentialResponseJwe.encode(Data(box.nonce)),
            CredentialResponseJwe.encode(box.ciphertext), CredentialResponseJwe.encode(box.tag),
        ].joined(separator: ".")
        try selfCheck(jwe, alg: alg, enc: enc, kid: recipientJwk["kid"])
        return jwe
    }

    /// Largest response the engine accepts.
    public static let maxResponseBytes = 4 * 1024 * 1024

    /// What the engine checks before it posts, checked here first so a response it would refuse is never
    /// sent: five segments, none empty except the encrypted key of direct ECDH-ES, no more than 4 MiB, and
    /// a protected header whose `alg` and `enc` are the request's and whose `kid` is the JWK's.
    static func selfCheck(_ jwe: String, alg: String, enc: String, kid: String?) throws {
        let parts = jwe.split(separator: ".", omittingEmptySubsequences: false)
        guard jwe.utf8.count <= maxResponseBytes, parts.count == 5,
              [0, 2, 3, 4].allSatisfy({ !parts[$0].isEmpty }), parts[1].isEmpty == (alg == "ECDH-ES"),
              let header = CredentialResponseJwe.decode(String(parts[0])),
              let object = (try? JSONSerialization.jsonObject(with: header)) as? [String: Any],
              object["alg"] as? String == alg, object["enc"] as? String == enc, object["kid"] as? String == kid else {
            throw JarmResponseError.unusableKey("the response failed its own check")
        }
    }

    private static func publicKey(from jwk: [String: String]) throws -> P256.KeyAgreement.PublicKey {
        guard jwk["kty"] == "EC", jwk["crv"] == "P-256" else { throw JarmResponseError.unusableKey("not an EC P-256 key") }
        // A private key is never an encryption target; the engine refuses it too.
        guard jwk["d"] == nil else { throw JarmResponseError.unusableKey("a private key") }
        if let use = jwk["use"], use != "enc" { throw JarmResponseError.unusableKey("not for encryption") }
        guard let x = jwk["x"].flatMap({ CredentialResponseJwe.decode($0) }), let y = jwk["y"].flatMap({ CredentialResponseJwe.decode($0) }),
              x.count == 32, y.count == 32,
              let key = try? P256.KeyAgreement.PublicKey(x963Representation: Data([4]) + x + y) else {
            throw JarmResponseError.unusableKey("not a point on P-256")
        }
        return key
    }
}

/// RFC 7638 thumbprints of the public keys this SDK handles.
public enum JwkThumbprint {
    /// The thumbprint (base64url of the SHA-256 over `{"crv","kty","x","y"}` in that member order) of an EC public
    /// JWK; nil unless it is a complete EC key with string members.
    public static func ec(_ jwk: [String: String]) -> String? {
        guard jwk["kty"] == "EC", let crv = jwk["crv"], let x = jwk["x"], let y = jwk["y"] else { return nil }
        let canonical = "{\"crv\":\(quote(crv)),\"kty\":\"EC\",\"x\":\(quote(x)),\"y\":\(quote(y))}"
        return CredentialResponseJwe.encode(Data(SHA256.hash(data: Data(canonical.utf8))))
    }

    private static func quote(_ text: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return String(decoding: (try? encoder.encode(text)) ?? Data(), as: UTF8.self)
    }
}
