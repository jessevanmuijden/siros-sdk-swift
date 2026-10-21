// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// The AES operations Credential Response decryption needs and CryptoKit / swift-crypto do not offer:
/// RFC 3394 key unwrap and AES-CBC with PKCS#7 padding.
///
/// On Apple platforms both are CommonCrypto (`CCSymmetricKeyUnwrap`; `CCCrypt` in CBC mode with
/// padding). Elsewhere (Linux CI) they are built on a plain FIPS 197 reference implementation, so
/// the vectors run on every platform. The reference is table-driven and not constant time; it is
/// not shipped on a device.
enum AesBlock {

    enum Failure: Error { case badKeyLength, badDataLength, integrity, platform }

    /// RFC 3394 unwrap of `wrapped` with `kek`; `Failure.integrity` when the integrity check fails.
    static func keyUnwrap(kek: [UInt8], wrapped: [UInt8]) throws -> [UInt8] {
        guard [16, 24, 32].contains(kek.count) else { throw Failure.badKeyLength }
        guard wrapped.count >= 24, wrapped.count % 8 == 0 else { throw Failure.badDataLength }
        #if canImport(CommonCrypto)
        var raw = [UInt8](repeating: 0, count: wrapped.count)
        var rawLength = raw.count
        let status = CCSymmetricKeyUnwrap(
            CCWrappingAlgorithm(kCCWRAPAES), CCrfc3394_iv, CCrfc3394_ivLen,
            kek, kek.count, wrapped, wrapped.count, &raw, &rawLength
        )
        guard status == Int32(kCCSuccess) else { throw Failure.integrity }
        return Array(raw.prefix(rawLength))
        #else
        return try ReferenceAes.unwrap(kek: kek, wrapped: wrapped)
        #endif
    }

    /// AES-CBC decryption with PKCS#7 padding removed; `Failure.integrity` for bad padding.
    static func cbcDecryptPkcs7(key: [UInt8], iv: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        guard [16, 24, 32].contains(key.count) else { throw Failure.badKeyLength }
        guard iv.count == 16, !ciphertext.isEmpty, ciphertext.count % 16 == 0 else { throw Failure.badDataLength }
        #if canImport(CommonCrypto)
        var plain = [UInt8](repeating: 0, count: ciphertext.count + 16)
        var written = 0
        // CBC with PKCS#7 padding (the options value is `kCCOptionPKCS7Padding`; ECB is not selected).
        let status = plain.withUnsafeMutableBytes { outPtr in
            CCCrypt(
                UInt32(kCCDecrypt), UInt32(kCCAlgorithmAES), UInt32(kCCOptionPKCS7Padding),
                key, key.count, iv, ciphertext, ciphertext.count, outPtr.baseAddress, outPtr.count, &written
            )
        }
        guard status == Int32(kCCSuccess) else { throw Failure.integrity }
        return Array(plain.prefix(written))
        #else
        return try ReferenceAes.cbcDecryptPkcs7(key: key, iv: iv, ciphertext: ciphertext)
        #endif
    }

    #if !canImport(CommonCrypto)
    /// The raw block cipher of the reference implementation: for the FIPS 197 vectors only.
    static func referenceDecryptBlocks(key: [UInt8], data: [UInt8]) throws -> [UInt8] {
        guard [16, 24, 32].contains(key.count) else { throw Failure.badKeyLength }
        guard data.count % 16 == 0 else { throw Failure.badDataLength }
        return try ReferenceAes(key: key).decrypt(data)
    }
    #endif
}

#if !canImport(CommonCrypto)
/// FIPS 197 inverse cipher, for platforms without CommonCrypto.
private struct ReferenceAes {
    static func unwrap(kek: [UInt8], wrapped: [UInt8]) throws -> [UInt8] {
        let aes = try ReferenceAes(key: kek)
        let n = wrapped.count / 8 - 1
        var a = Array(wrapped[0..<8])
        var r = (0..<n).map { Array(wrapped[(8 * ($0 + 1))..<(8 * ($0 + 2))]) }
        for j in stride(from: 5, through: 0, by: -1) {
            for i in stride(from: n, through: 1, by: -1) {
                let t = UInt64(n * j + i)
                var tBytes = [UInt8](repeating: 0, count: 8)
                var shifted = t
                for index in (0..<8).reversed() { tBytes[index] = UInt8(shifted & 0xff); shifted >>= 8 }
                let block = try aes.decrypt(zip(a, tBytes).map { $0 ^ $1 } + r[i - 1])
                a = Array(block[0..<8])
                r[i - 1] = Array(block[8..<16])
            }
        }
        var difference: UInt8 = 0
        for index in 0..<8 { difference |= a[index] ^ 0xA6 }
        guard difference == 0 else { throw AesBlock.Failure.integrity }
        return r.flatMap { $0 }
    }

    static func cbcDecryptPkcs7(key: [UInt8], iv: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
        let blocks = try ReferenceAes(key: key).decrypt(ciphertext)
        var previous = iv
        var out = [UInt8]()
        for start in stride(from: 0, to: blocks.count, by: 16) {
            for offset in 0..<16 { out.append(blocks[start + offset] ^ previous[offset]) }
            previous = Array(ciphertext[start..<(start + 16)])
        }
        guard let last = out.last, last >= 1, last <= 16, Int(last) <= out.count,
              out.suffix(Int(last)).allSatisfy({ $0 == last }) else { throw AesBlock.Failure.integrity }
        return Array(out.dropLast(Int(last)))
    }

    private static let sbox: [UInt8] = {
        // The AES S-box from its definition (multiplicative inverse in GF(2^8), then the affine map).
        var box = [UInt8](repeating: 0, count: 256)
        var p: UInt8 = 1
        var q: UInt8 = 1
        repeat {
            p = p ^ (p << 1) ^ ((p & 0x80) != 0 ? 0x1B : 0)
            q ^= q << 1; q ^= q << 2; q ^= q << 4
            if q & 0x80 != 0 { q ^= 0x09 }
            let x = q ^ rotl(q, 1) ^ rotl(q, 2) ^ rotl(q, 3) ^ rotl(q, 4)
            box[Int(p)] = x ^ 0x63
        } while p != 1
        box[0] = 0x63
        return box
    }()
    private static let inverse: [UInt8] = {
        var inv = [UInt8](repeating: 0, count: 256)
        for (index, value) in sbox.enumerated() { inv[Int(value)] = UInt8(index) }
        return inv
    }()

    private static func rotl(_ x: UInt8, _ n: UInt8) -> UInt8 { (x << n) | (x >> (8 - n)) }

    private static func mul(_ a: UInt8, _ b: UInt8) -> UInt8 {
        var a = a
        var b = b
        var product: UInt8 = 0
        while b != 0 {
            if b & 1 != 0 { product ^= a }
            a = (a << 1) ^ ((a & 0x80) != 0 ? 0x1B : 0)
            b >>= 1
        }
        return product
    }

    private let roundKeys: [[UInt8]]
    private let rounds: Int

    init(key: [UInt8]) throws {
        let nk = key.count / 4
        rounds = nk + 6
        var words = [[UInt8]]()
        for i in 0..<nk { words.append(Array(key[(4 * i)..<(4 * i + 4)])) }
        var rcon: UInt8 = 1
        for i in nk..<(4 * (rounds + 1)) {
            var temp = words[i - 1]
            if i % nk == 0 {
                temp = [temp[1], temp[2], temp[3], temp[0]].map { Self.sbox[Int($0)] }
                temp[0] ^= rcon
                rcon = Self.mul(rcon, 2)
            } else if nk > 6 && i % nk == 4 {
                temp = temp.map { Self.sbox[Int($0)] }
            }
            words.append(zip(words[i - nk], temp).map { $0 ^ $1 })
        }
        roundKeys = (0...rounds).map { round in (0..<4).flatMap { words[4 * round + $0] } }
    }

    func decrypt(_ data: [UInt8]) throws -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(data.count)
        for start in stride(from: 0, to: data.count, by: 16) {
            out += decryptBlock(Array(data[start..<(start + 16)]))
        }
        return out
    }

    private func decryptBlock(_ input: [UInt8]) -> [UInt8] {
        var s = zip(input, roundKeys[rounds]).map { $0 ^ $1 }
        for round in stride(from: rounds - 1, through: 0, by: -1) {
            s = invShiftRows(s).map { Self.inverse[Int($0)] }
            s = zip(s, roundKeys[round]).map { $0 ^ $1 }
            if round != 0 { s = invMixColumns(s) }
        }
        return s
    }

    private func invShiftRows(_ s: [UInt8]) -> [UInt8] {
        var r = s
        for row in 1..<4 { for col in 0..<4 { r[4 * ((col + row) % 4) + row] = s[4 * col + row] } }
        return r
    }

    private func invMixColumns(_ s: [UInt8]) -> [UInt8] {
        var r = s
        for col in 0..<4 {
            let a = Array(s[(4 * col)..<(4 * col + 4)])
            r[4 * col + 0] = Self.mul(a[0], 14) ^ Self.mul(a[1], 11) ^ Self.mul(a[2], 13) ^ Self.mul(a[3], 9)
            r[4 * col + 1] = Self.mul(a[0], 9) ^ Self.mul(a[1], 14) ^ Self.mul(a[2], 11) ^ Self.mul(a[3], 13)
            r[4 * col + 2] = Self.mul(a[0], 13) ^ Self.mul(a[1], 9) ^ Self.mul(a[2], 14) ^ Self.mul(a[3], 11)
            r[4 * col + 3] = Self.mul(a[0], 11) ^ Self.mul(a[1], 13) ^ Self.mul(a[2], 9) ^ Self.mul(a[3], 14)
        }
        return r
    }
}
#endif
