// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Why a Credential Response JWE could not be opened. Carries no plaintext and no key material.
public enum CredentialResponseJweError: Error, Sendable, Equatable {
    case malformed(String)
    case unsupportedAlgorithm(String)
    case unsupportedEncryption(String)
    /// The header names an algorithm or encryption other than the pair this wallet advertised.
    case notNegotiated(String)
    case unsupportedCurve
    case authenticationFailed
}

/// The `alg` and `enc` pair a wallet advertises for a Credential Response (OpenID4VCI
/// `credential_response_encryption`), and the ones it can open.
public struct CredentialResponseEncryptionParams: Sendable, Equatable {
    public let alg: String
    public let enc: String

    public init(alg: String, enc: String) {
        self.alg = alg
        self.enc = enc
    }

    public static let supportedAlgs = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"]
    public static let supportedEncs = ["A128GCM", "A256GCM", "A128CBC-HS256", "A256CBC-HS512"]

    public var isSupported: Bool { Self.supportedAlgs.contains(alg) && Self.supportedEncs.contains(enc) }
}

/// A Credential Response JWE (compact serialization) opened with a recipient P-256 key:
/// ECDH-ES (RFC 7518 section 4.6) with the content encryptions A128GCM, A256GCM,
/// A128CBC-HS256 and A256CBC-HS512, directly or with AES Key Wrap (`ECDH-ES+A128KW`,
/// `ECDH-ES+A256KW`, RFC 3394).
public enum CredentialResponseJwe {

    /// Decrypt `compact` with `recipient`. When `expected` is given the header's `alg` and
    /// `enc` must be exactly that pair: the wallet advertised it, so anything else is not
    /// what it asked for and is refused rather than opened.
    public static func decrypt(
        _ compact: String,
        recipient: P256.KeyAgreement.PrivateKey,
        expected: CredentialResponseEncryptionParams? = nil
    ) throws -> Data {
        let parts = compact.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 5 else { throw CredentialResponseJweError.malformed("a compact JWE has five parts") }
        guard let headerData = decode(parts[0]),
              let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any],
              let alg = header["alg"] as? String, let enc = header["enc"] as? String,
              let encryptedKey = decode(parts[1]), let iv = decode(parts[2]),
              let ciphertext = decode(parts[3]), let tag = decode(parts[4]) else {
            throw CredentialResponseJweError.malformed("header or part is not base64url JSON")
        }
        guard CredentialResponseEncryptionParams.supportedAlgs.contains(alg) else {
            throw CredentialResponseJweError.unsupportedAlgorithm(alg)
        }
        guard let content = ContentEncryption(rawValue: enc) else { throw CredentialResponseJweError.unsupportedEncryption(enc) }
        if let expected, expected.alg != alg || expected.enc != enc {
            throw CredentialResponseJweError.notNegotiated("\(alg) \(enc)")
        }
        // A header this code does not fully understand must not be half-honoured.
        guard header["zip"] == nil, header["crit"] == nil else {
            throw CredentialResponseJweError.malformed("zip and crit are not supported")
        }

        guard let epk = header["epk"] as? [String: Any], epk["kty"] as? String == "EC" else {
            throw CredentialResponseJweError.malformed("epk is missing")
        }
        guard epk["crv"] as? String == "P-256" else { throw CredentialResponseJweError.unsupportedCurve }
        guard let x = (epk["x"] as? String).flatMap(decode), let y = (epk["y"] as? String).flatMap(decode),
              x.count == 32, y.count == 32 else {
            throw CredentialResponseJweError.malformed("epk is not a P-256 point")
        }
        let ephemeral: P256.KeyAgreement.PublicKey
        do {
            ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: Data([4] + x + y))
        } catch {
            throw CredentialResponseJweError.malformed("epk is not on the curve")
        }
        let secret: SharedSecret
        do { secret = try recipient.sharedSecretFromKeyAgreement(with: ephemeral) } catch {
            throw CredentialResponseJweError.authenticationFailed
        }
        let z = secret.withUnsafeBytes { Array($0) }

        let apu = (header["apu"] as? String).flatMap(decode) ?? Data()
        let apv = (header["apv"] as? String).flatMap(decode) ?? Data()

        let cek: [UInt8]
        if alg == "ECDH-ES" {
            guard encryptedKey.isEmpty else { throw CredentialResponseJweError.malformed("ECDH-ES carries no encrypted key") }
            cek = concatKdf(z: z, algorithmId: enc, apu: apu, apv: apv, keyBits: content.keyBytes * 8)
        } else {
            // RFC 3394 adds exactly eight bytes, so the negotiated content encryption fixes the length;
            // anything else is refused before any of the 6n block decryptions run.
            guard encryptedKey.count == content.keyBytes + 8 else {
                throw CredentialResponseJweError.malformed("the encrypted key has the wrong length")
            }
            let kekBytes = alg == "ECDH-ES+A128KW" ? 16 : 32
            let kek = concatKdf(z: z, algorithmId: alg, apu: apu, apv: apv, keyBits: kekBytes * 8)
            guard let unwrapped = try? AesKeyWrap.unwrap(kek: kek, wrapped: Array(encryptedKey)),
                  unwrapped.count == content.keyBytes else {
                throw CredentialResponseJweError.authenticationFailed
            }
            cek = unwrapped
        }

        let aad = Array(parts[0].utf8)
        guard let plaintext = try content.open(cek: cek, iv: Array(iv), ciphertext: Array(ciphertext), tag: Array(tag), aad: aad) else {
            throw CredentialResponseJweError.authenticationFailed
        }
        return Data(plaintext)
    }

    // MARK: - Content encryption

    private enum ContentEncryption: String {
        case a128gcm = "A128GCM"
        case a256gcm = "A256GCM"
        case a128cbcHs256 = "A128CBC-HS256"
        case a256cbcHs512 = "A256CBC-HS512"

        var keyBytes: Int {
            switch self {
            case .a128gcm: return 16
            case .a256gcm: return 32
            case .a128cbcHs256: return 32
            case .a256cbcHs512: return 64
            }
        }

        /// The plaintext, or nil when the authentication tag does not verify.
        func open(cek: [UInt8], iv: [UInt8], ciphertext: [UInt8], tag: [UInt8], aad: [UInt8]) throws -> [UInt8]? {
            switch self {
            case .a128gcm, .a256gcm:
                guard iv.count == 12, tag.count == 16, let nonce = try? AES.GCM.Nonce(data: iv),
                      let box = try? AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag) else { return nil }
                return (try? AES.GCM.open(box, using: SymmetricKey(data: cek), authenticating: aad)).map { Array($0) }
            case .a128cbcHs256, .a256cbcHs512:
                // RFC 7518 section 5.2: MAC_KEY is the first half, ENC_KEY the second.
                let half = cek.count / 2
                let macKey = Array(cek[0..<half]), encKey = Array(cek[half...])
                let tagLength = half
                guard iv.count == 16, tag.count == tagLength, ciphertext.count % 16 == 0, !ciphertext.isEmpty else { return nil }
                var al = [UInt8](repeating: 0, count: 8)
                var bits = UInt64(aad.count) * 8
                for index in (0..<8).reversed() { al[index] = UInt8(bits & 0xff); bits >>= 8 }
                let macInput = Data(aad + iv + ciphertext + al)
                let mac: [UInt8]
                if self == .a128cbcHs256 {
                    mac = Array(HMAC<SHA256>.authenticationCode(for: macInput, using: SymmetricKey(data: macKey)))
                } else {
                    mac = Array(HMAC<SHA512>.authenticationCode(for: macInput, using: SymmetricKey(data: macKey)))
                }
                // The tag is checked before anything is decrypted, in constant time.
                guard constantTimeEqual(Array(mac.prefix(tagLength)), tag) else { return nil }
                guard let padded = try? cbcDecrypt(key: encKey, iv: iv, ciphertext: ciphertext) else { return nil }
                return pkcs7Unpad(padded)
            }
        }
    }

    private static func cbcDecrypt(key: [UInt8], iv: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        let blocks = try AesBlock.decryptBlocks(key: key, data: ciphertext)
        var previous = iv
        var out = [UInt8]()
        out.reserveCapacity(blocks.count)
        for start in stride(from: 0, to: blocks.count, by: 16) {
            for offset in 0..<16 { out.append(blocks[start + offset] ^ previous[offset]) }
            previous = Array(ciphertext[start..<(start + 16)])
        }
        return out
    }

    private static func pkcs7Unpad(_ data: [UInt8]) -> [UInt8]? {
        guard let last = data.last, last >= 1, last <= 16, Int(last) <= data.count else { return nil }
        let padding = data.suffix(Int(last))
        guard padding.allSatisfy({ $0 == last }) else { return nil }
        return Array(data.dropLast(Int(last)))
    }

    // MARK: - Key agreement

    /// NIST SP 800-56A single-step KDF with SHA-256, as RFC 7518 section 4.6.2 profiles it.
    static func concatKdf(z: [UInt8], algorithmId: String, apu: Data, apv: Data, keyBits: Int) -> [UInt8] {
        func lengthPrefixed(_ bytes: [UInt8]) -> [UInt8] {
            let count = UInt32(bytes.count)
            return [UInt8(count >> 24 & 0xff), UInt8(count >> 16 & 0xff), UInt8(count >> 8 & 0xff), UInt8(count & 0xff)] + bytes
        }
        let bits = UInt32(keyBits)
        let otherInfo = lengthPrefixed(Array(algorithmId.utf8)) + lengthPrefixed(Array(apu)) + lengthPrefixed(Array(apv))
            + [UInt8(bits >> 24 & 0xff), UInt8(bits >> 16 & 0xff), UInt8(bits >> 8 & 0xff), UInt8(bits & 0xff)]
        var derived = [UInt8]()
        var counter: UInt32 = 1
        let needed = (keyBits + 7) / 8
        while derived.count < needed {
            let counterBytes = [UInt8(counter >> 24 & 0xff), UInt8(counter >> 16 & 0xff), UInt8(counter >> 8 & 0xff), UInt8(counter & 0xff)]
            derived += Array(SHA256.hash(data: Data(counterBytes + z + otherInfo)))
            counter += 1
        }
        return Array(derived.prefix(needed))
    }

    // MARK: - Helpers

    static func decode(_ text: String) -> Data? {
        var base64 = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        guard !base64.contains("=") else { return nil }
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        return Data(base64Encoded: base64)
    }

    static func encode(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var difference: UInt8 = 0
        for index in a.indices { difference |= a[index] ^ b[index] }
        return difference == 0
    }
}

/// RFC 3394 AES Key Wrap, unwrap only (a wallet never wraps a key for an issuer here).
enum AesKeyWrap {
    static let defaultIv: [UInt8] = [0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6]

    enum Failure: Error { case badLength, integrity }

    static func unwrap(kek: [UInt8], wrapped: [UInt8]) throws -> [UInt8] {
        guard wrapped.count >= 24, wrapped.count % 8 == 0 else { throw Failure.badLength }
        let n = wrapped.count / 8 - 1
        var a = Array(wrapped[0..<8])
        var r = (0..<n).map { Array(wrapped[(8 * ($0 + 1))..<(8 * ($0 + 2))]) }
        for j in stride(from: 5, through: 0, by: -1) {
            for i in stride(from: n, through: 1, by: -1) {
                let t = UInt64(n * j + i)
                var tBytes = [UInt8](repeating: 0, count: 8)
                var tv = t
                for index in (0..<8).reversed() { tBytes[index] = UInt8(tv & 0xff); tv >>= 8 }
                let xored = zip(a, tBytes).map { $0 ^ $1 }
                let block = try AesBlock.decryptBlocks(key: kek, data: xored + r[i - 1])
                a = Array(block[0..<8])
                r[i - 1] = Array(block[8..<16])
            }
        }
        var difference: UInt8 = 0
        for index in 0..<8 { difference |= a[index] ^ defaultIv[index] }
        guard difference == 0 else { throw Failure.integrity }
        return r.flatMap { $0 }
    }
}
