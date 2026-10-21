// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation
#if canImport(CommonCrypto)
import CommonCrypto
#endif

/// AES decryption of whole blocks (ECB, no padding): the one primitive RFC 3394
/// key unwrap and CBC need and CryptoKit / swift-crypto do not offer.
///
/// On Apple platforms it is CommonCrypto. Elsewhere (Linux CI) it is a plain
/// reference implementation of FIPS 197's inverse cipher, so the vectors run on
/// every platform. The reference is table-driven and not constant time; it is
/// not shipped on a device.
enum AesBlock {

    enum Failure: Error { case badKeyLength, badDataLength, platform }

    static func decryptBlocks(key: [UInt8], data: [UInt8]) throws -> [UInt8] {
        guard [16, 24, 32].contains(key.count) else { throw Failure.badKeyLength }
        guard data.count % 16 == 0 else { throw Failure.badDataLength }
        if data.isEmpty { return [] }
        #if canImport(CommonCrypto)
        var out = [UInt8](repeating: 0, count: data.count + 16)
        var written = 0
        let status = out.withUnsafeMutableBytes { outPtr in
            CCCrypt(
                CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                key, key.count, nil, data, data.count, outPtr.baseAddress, outPtr.count, &written
            )
        }
        guard status == kCCSuccess, written == data.count else { throw Failure.platform }
        return Array(out.prefix(written))
        #else
        return try ReferenceAes(key: key).decrypt(data)
        #endif
    }
}

#if !canImport(CommonCrypto)
/// FIPS 197 inverse cipher, for platforms without CommonCrypto.
private struct ReferenceAes {
    private static let sbox: [UInt8] = {
        // The AES S-box from its definition (multiplicative inverse in GF(2^8), then the affine map).
        var box = [UInt8](repeating: 0, count: 256)
        var p: UInt8 = 1, q: UInt8 = 1
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
        var a = a, b = b, product: UInt8 = 0
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
