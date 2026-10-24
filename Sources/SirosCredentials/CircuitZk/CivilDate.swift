// Copyright 2026 SIROS Foundation. BSD 2-Clause License.

import Foundation

/// A strictly formatted `YYYY-MM-DD` calendar date. Calendar-free on purpose:
/// the age maths must not depend on the device time zone or locale.
struct CivilDate: Equatable {
    let year: Int, month: Int, day: Int

    init?(_ text: String) {
        let bytes = Array(text.utf8)
        guard bytes.count == 10, bytes[4] == 0x2D, bytes[7] == 0x2D else { return nil }
        func digits(_ range: Range<Int>) -> Int? {
            var value = 0
            for index in range {
                guard (0x30...0x39).contains(bytes[index]) else { return nil }
                value = value * 10 + Int(bytes[index] - 0x30)
            }
            return value
        }
        guard let year = digits(0..<4), let month = digits(5..<7), let day = digits(8..<10),
              year >= 1, (1...12).contains(month) else { return nil }
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
        let lengths = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        guard day >= 1, day <= lengths[month - 1] else { return nil }
        self.year = year
        self.month = month
        self.day = day
    }

    /// Days since 1970-01-01 (proleptic Gregorian; Howard Hinnant's days_from_civil).
    var daysSinceEpoch: Int {
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        return era * 146097 + doe - 719468
    }

    /// Completed years from this date to `today`, never below 0.
    func years(until today: CivilDate) -> Int {
        let beforeBirthday = (today.month, today.day) < (month, day)
        return max(0, today.year - year - (beforeBirthday ? 1 : 0))
    }
}
