// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// `proof_time` of a `zkp_req` presentation (nym_auth rulebook v0.4): the prover-supplied time, the circuit's
/// public input, in the EXACT 20-byte form `YYYY-MM-DDThh:mm:ssZ` (second precision, no fraction, `T` and `Z`
/// upper case, no offset, a real UTC instant). Nothing here reads a clock: the caller supplies `now`.
///
/// The check is by length and shape first (a general date parser accepts fractions and numeric offsets that
/// the form refuses); the numbers are parsed only to settle that the instant is real.
public enum ZkpReqProofTime {
    public enum Invalid: String, Error, Sendable, Equatable {
        case form = "proof_time_form"
        case notAnInstant = "proof_time_not_an_instant"
        case outOfRange = "proof_time_out_of_range"
        case inFuture = "proof_time_in_future"
        case tooOld = "proof_time_too_old"

        public var code: String { rawValue }
    }

    /// The length of the form, in bytes.
    public static let length = 20
    /// The last second the form can express: 9999-12-31T23:59:59Z.
    public static let maxSeconds: Int64 = 253_402_300_799
    /// Recommended tolerances: recommendations, not protocol constants; the verifier's to configure.
    public static let recommendedSkewSeconds: Int64 = 60
    public static let recommendedMaxAgeSeconds: Int64 = 600

    /// The 20-byte rendering of epoch seconds (UTC), 0 through ``maxSeconds``.
    public static func render(seconds: Int64) throws -> String {
        guard (0...maxSeconds).contains(seconds) else { throw Invalid.outOfRange }
        let days = seconds / 86_400, remainder = seconds % 86_400
        let (y, m, d) = civil(fromDays: days)
        func two(_ n: Int64) -> String { n < 10 ? "0\(n)" : "\(n)" }
        let year = String(y)
        return String(repeating: "0", count: 4 - year.count) + year + "-\(two(m))-\(two(d))T\(two(remainder / 3600)):\(two(remainder % 3600 / 60)):\(two(remainder % 60))Z"
    }

    /// Epoch seconds of a `proof_time`, or the reason it is not one.
    public static func parse(_ text: String) throws -> Int64 {
        let bytes = Array(text.utf8)
        guard bytes.count == length else { throw Invalid.form }
        let shape = Array("dddd-dd-ddTdd:dd:ddZ".utf8)
        for (byte, expected) in zip(bytes, shape) {
            let ok = expected == UInt8(ascii: "d") ? (byte >= 0x30 && byte <= 0x39) : byte == expected
            guard ok else { throw Invalid.form }
        }
        func number(_ from: Int, _ to: Int) -> Int64 { bytes[from..<to].reduce(0) { $0 * 10 + Int64($1 - 0x30) } }
        let (y, mo, d, h, mi, s) = (number(0, 4), number(5, 7), number(8, 10), number(11, 13), number(14, 16), number(17, 19))
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0)
        let monthDays: Int64
        switch mo {
        case 1, 3, 5, 7, 8, 10, 12: monthDays = 31
        case 4, 6, 9, 11: monthDays = 30
        case 2: monthDays = leap ? 29 : 28
        default: throw Invalid.notAnInstant
        }
        guard (1...monthDays).contains(d), h <= 23, mi <= 59, s <= 59 else { throw Invalid.notAnInstant }
        return days(fromCivil: y, mo, d) * 86_400 + h * 3600 + mi * 60 + s
    }

    /// The verifier's tolerance: `now - maxAge <= proof_time <= now + skew`, both inclusive.
    public static func checkTolerance(
        _ proofTime: String, now: Int64, skew: Int64 = recommendedSkewSeconds, maxAge: Int64 = recommendedMaxAgeSeconds
    ) throws {
        let t = try parse(proofTime)
        if t > now &+ skew { throw Invalid.inFuture }
        if t < now &- maxAge { throw Invalid.tooOld }
    }

    /// Proleptic Gregorian (year, month, day) to days since 1970-01-01.
    static func days(fromCivil year: Int64, _ month: Int64, _ day: Int64) -> Int64 {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let mp = (month + 9) % 12
        let doy = (153 * mp + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146_097 + doe - 719_468
    }

    private static func civil(fromDays days: Int64) -> (Int64, Int64, Int64) {
        let z = days + 719_468
        let era = (z >= 0 ? z : z - 146_096) / 146_097
        let doe = z - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let d = doy - (153 * mp + 2) / 5 + 1
        let m = mp < 10 ? mp + 3 : mp - 9
        return (yoe + era * 400 + (m <= 2 ? 1 : 0), m, d)
    }
}
