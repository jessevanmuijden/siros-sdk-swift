// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// `transaction_data_hashes` computation (OpenID4VP 1.0 Appendix B).
///
/// The hash input is the base64url STRING exactly as the verifier sent it:
/// "base64url decoding is not performed before hashing". Hashing decoded
/// bytes, or a re-serialisation of the decoded object, produces a value no
/// verifier will accept.
public enum TransactionDataHashing {
    /// Algorithms this SDK can compute, in preference order.
    public static let supportedAlgorithms = ["sha-256", "sha-384", "sha-512"]

    /// `base64url(HASH(ASCII bytes of raw))`, unpadded; `nil` for an
    /// algorithm this SDK does not support.
    public static func hash(raw: String, algorithm: String) -> String? {
        let input = Data(raw.utf8)
        let digest: Data
        switch algorithm {
        case "sha-256": digest = Data(SHA256.hash(data: input))
        case "sha-384": digest = Data(SHA384.hash(data: input))
        case "sha-512": digest = Data(SHA512.hash(data: input))
        default: return nil
        }
        return base64UrlEncode(digest)
    }

    static func base64UrlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Strict base64url decode: only the URL-safe alphabet, optional trailing
    /// `=` padding, nothing else (no standard-alphabet `+` `/`, no whitespace).
    static func base64UrlDecode(_ text: String) -> Data? {
        var body = Substring(text)
        var padding = 0
        while body.last == "=" { body = body.dropLast(); padding += 1 }
        guard padding <= 2, !body.isEmpty else { return nil }
        let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        guard body.allSatisfy(alphabet.contains) else { return nil }
        guard body.count % 4 != 1 else { return nil }
        if padding > 0, (body.count + padding) % 4 != 0 { return nil }
        var standard = String(body).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        standard += String(repeating: "=", count: (4 - standard.count % 4) % 4)
        return Data(base64Encoded: standard)
    }
}
